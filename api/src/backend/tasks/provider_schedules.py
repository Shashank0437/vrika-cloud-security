"""Provider scan schedule helpers backed by django-celery-beat.

Stores cadence metadata in PeriodicTask.kwargs under ``schedule`` so the
``/api/v1/schedules`` CRUD API can round-trip daily / weekly / monthly /
interval configurations used by the ADVANCED UI.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from api.db_utils import rls_transaction
from api.models import Provider, Scan, StateChoices
from django_celery_beat.models import CrontabSchedule, IntervalSchedule, PeriodicTask
from tasks.jobs.attack_paths import db_utils as attack_paths_db_utils
from tasks.utils import SCHEDULED_SCAN_NAME

logger = logging.getLogger(__name__)

FREQUENCY_DAILY = "DAILY"
FREQUENCY_INTERVAL = "INTERVAL"
FREQUENCY_WEEKLY = "WEEKLY"
FREQUENCY_MONTHLY = "MONTHLY"
VALID_FREQUENCIES = frozenset(
    {
        FREQUENCY_DAILY,
        FREQUENCY_INTERVAL,
        FREQUENCY_WEEKLY,
        FREQUENCY_MONTHLY,
    }
)
SCAN_INTERVAL_HOURS_MIN = 24
SCHEDULE_KWARGS_KEY = "schedule"
TASK_NAME_PREFIX = "scan-perform-scheduled-"


def scheduled_task_name(provider_id: str) -> str:
    return f"{TASK_NAME_PREFIX}{provider_id}"


def get_scheduled_periodic_task(provider_id: str) -> PeriodicTask | None:
    return PeriodicTask.objects.filter(name=scheduled_task_name(provider_id)).first()


def _empty_attributes() -> dict[str, Any]:
    return {
        "scan_enabled": False,
        "scan_frequency": FREQUENCY_DAILY,
        "scan_hour": None,
        "scan_timezone": "UTC",
        "scan_interval_hours": None,
        "scan_day_of_week": None,
        "scan_day_of_month": None,
        "compliances": [],
        "next_scan_at": None,
        "last_scan_at": None,
    }


def _parse_periodic_kwargs(periodic_task: PeriodicTask) -> dict[str, Any]:
    try:
        kwargs = json.loads(periodic_task.kwargs or "{}")
    except (TypeError, json.JSONDecodeError):
        return {}
    return kwargs if isinstance(kwargs, dict) else {}


def _infer_legacy_attributes(periodic_task: PeriodicTask) -> dict[str, Any]:
    """Map pre-metadata daily interval tasks to ADVANCED schedule attributes."""
    attrs = _empty_attributes()
    attrs["scan_enabled"] = bool(periodic_task.enabled)
    attrs["scan_frequency"] = FREQUENCY_DAILY
    attrs["scan_timezone"] = "UTC"

    if (
        periodic_task.interval
        and periodic_task.interval.period == IntervalSchedule.HOURS
    ):
        every = periodic_task.interval.every
        if every == 24:
            attrs["scan_frequency"] = FREQUENCY_DAILY
        elif every >= SCAN_INTERVAL_HOURS_MIN:
            attrs["scan_frequency"] = FREQUENCY_INTERVAL
            attrs["scan_interval_hours"] = every

    hour = 0
    if periodic_task.start_time:
        hour = periodic_task.start_time.astimezone(UTC).hour
    elif periodic_task.crontab:
        try:
            hour = int(str(periodic_task.crontab.hour).split(",")[0])
        except (TypeError, ValueError):
            hour = 0
        tz_name = str(periodic_task.crontab.timezone or "UTC")
        attrs["scan_timezone"] = tz_name
        if periodic_task.crontab.day_of_week not in ("*", None, ""):
            attrs["scan_frequency"] = FREQUENCY_WEEKLY
            try:
                attrs["scan_day_of_week"] = int(
                    str(periodic_task.crontab.day_of_week).split(",")[0]
                )
            except (TypeError, ValueError):
                attrs["scan_day_of_week"] = 0
        elif periodic_task.crontab.day_of_month not in ("*", None, ""):
            attrs["scan_frequency"] = FREQUENCY_MONTHLY
            try:
                attrs["scan_day_of_month"] = int(
                    str(periodic_task.crontab.day_of_month).split(",")[0]
                )
            except (TypeError, ValueError):
                attrs["scan_day_of_month"] = 1

    attrs["scan_hour"] = hour
    return attrs


def compute_next_scan_at(periodic_task: PeriodicTask | None) -> datetime | None:
    if periodic_task is None or not periodic_task.enabled:
        return None

    # Prefer wall-clock math from stored schedule metadata (timezone-correct).
    kwargs = _parse_periodic_kwargs(periodic_task)
    stored = kwargs.get(SCHEDULE_KWARGS_KEY)
    if isinstance(stored, dict) and stored.get("scan_hour") is not None:
        attrs = {
            "scan_enabled": bool(periodic_task.enabled),
            "scan_frequency": stored.get("scan_frequency") or FREQUENCY_DAILY,
            "scan_hour": stored.get("scan_hour"),
            "scan_timezone": stored.get("scan_timezone") or "UTC",
            "scan_interval_hours": stored.get("scan_interval_hours"),
            "scan_day_of_week": stored.get("scan_day_of_week"),
            "scan_day_of_month": stored.get("scan_day_of_month"),
        }
        from_attrs = next_run_from_schedule_attrs(attrs)
        if from_attrs is not None:
            return from_attrs

    try:
        schedule = periodic_task.schedule
    except Exception:
        logger.exception(
            "Unable to resolve schedule for periodic task %s", periodic_task.id
        )
        return None

    now = datetime.now(UTC)
    last = periodic_task.last_run_at or now
    try:
        remaining = schedule.remaining_estimate(last)
    except Exception:
        logger.exception(
            "Unable to estimate next run for periodic task %s", periodic_task.id
        )
        return None
    if remaining is None:
        return None
    next_at = last + remaining
    if next_at <= now:
        try:
            remaining = schedule.remaining_estimate(now)
            next_at = now + remaining
        except Exception:
            return next_at
    return next_at


def next_run_from_schedule_attrs(
    attrs: dict[str, Any], now: datetime | None = None
) -> datetime | None:
    """Next fire time from ADVANCED schedule attributes, in UTC."""
    if not attrs.get("scan_enabled") or attrs.get("scan_hour") is None:
        return None

    frequency = attrs.get("scan_frequency") or FREQUENCY_DAILY
    if frequency == FREQUENCY_INTERVAL:
        # Interval schedules are driven by Celery IntervalSchedule, not wall-clock hour.
        return None

    try:
        tz = ZoneInfo(attrs.get("scan_timezone") or "UTC")
    except ZoneInfoNotFoundError:
        tz = ZoneInfo("UTC")

    now_utc = now or datetime.now(UTC)
    local_now = now_utc.astimezone(tz)
    hour = int(attrs["scan_hour"])
    candidate = local_now.replace(hour=hour, minute=0, second=0, microsecond=0)

    if frequency == FREQUENCY_WEEKLY:
        # Cron: 0=Sunday .. 6=Saturday. datetime.weekday(): 0=Monday .. 6=Sunday.
        cron_dow = int(attrs.get("scan_day_of_week") or 0)
        python_dow = (cron_dow + 6) % 7
        days_ahead = (python_dow - local_now.weekday()) % 7
        candidate = candidate + timedelta(days=days_ahead)
        if candidate <= local_now:
            candidate += timedelta(days=7)
    elif frequency == FREQUENCY_MONTHLY:
        day = int(attrs.get("scan_day_of_month") or 1)
        candidate = candidate.replace(day=day)
        if candidate <= local_now:
            month = candidate.month + 1
            year = candidate.year
            if month > 12:
                month = 1
                year += 1
            candidate = candidate.replace(year=year, month=month, day=day)
    else:
        # DAILY
        if candidate <= local_now:
            candidate += timedelta(days=1)

    return candidate.astimezone(UTC)


def advance_schedule_datetime(periodic_task: PeriodicTask, when: datetime) -> datetime:
    """Advance ``when`` until it is strictly in the future for this schedule."""
    now = datetime.now(UTC)
    next_dt = when
    if periodic_task.interval:
        interval = periodic_task.interval
        while next_dt <= now:
            next_dt += timedelta(**{interval.period: interval.every})
        return next_dt

    schedule = periodic_task.schedule
    for _ in range(128):
        if next_dt > now:
            return next_dt
        remaining = schedule.remaining_estimate(next_dt)
        bump = (
            remaining
            if remaining and remaining.total_seconds() > 0
            else timedelta(minutes=1)
        )
        next_dt = next_dt + bump
    return next_dt


def last_completed_scan_at(tenant_id: str, provider_id: str) -> datetime | None:
    with rls_transaction(tenant_id):
        return (
            Scan.objects.filter(
                tenant_id=tenant_id,
                provider_id=provider_id,
                state=StateChoices.COMPLETED,
                completed_at__isnull=False,
            )
            .order_by("-completed_at")
            .values_list("completed_at", flat=True)
            .first()
        )


def read_schedule_attributes(
    provider: Provider, periodic_task: PeriodicTask | None = None
) -> dict[str, Any]:
    provider_id = str(provider.id)
    tenant_id = str(provider.tenant_id)
    periodic_task = periodic_task or get_scheduled_periodic_task(provider_id)

    if periodic_task is None:
        attrs = _empty_attributes()
        attrs["last_scan_at"] = last_completed_scan_at(tenant_id, provider_id)
        return attrs

    kwargs = _parse_periodic_kwargs(periodic_task)
    stored = kwargs.get(SCHEDULE_KWARGS_KEY)
    if isinstance(stored, dict) and stored.get("scan_hour") is not None:
        attrs = _empty_attributes()
        attrs["scan_enabled"] = bool(periodic_task.enabled)
        attrs["scan_frequency"] = stored.get("scan_frequency") or FREQUENCY_DAILY
        attrs["scan_hour"] = stored.get("scan_hour")
        attrs["scan_timezone"] = stored.get("scan_timezone") or "UTC"
        attrs["scan_interval_hours"] = stored.get("scan_interval_hours")
        attrs["scan_day_of_week"] = stored.get("scan_day_of_week")
        attrs["scan_day_of_month"] = stored.get("scan_day_of_month")
    else:
        attrs = _infer_legacy_attributes(periodic_task)

    scanner_args = kwargs.get("scanner_args") or {}
    compliances = (
        scanner_args.get("compliances") if isinstance(scanner_args, dict) else None
    )
    attrs["compliances"] = (
        list(compliances) if isinstance(compliances, list) and compliances else []
    )

    attrs["next_scan_at"] = compute_next_scan_at(periodic_task)
    attrs["last_scan_at"] = last_completed_scan_at(tenant_id, provider_id)
    return attrs


def _validate_timezone(name: str) -> str:
    try:
        ZoneInfo(name)
    except ZoneInfoNotFoundError as exc:
        raise ValueError(f"Unknown timezone: {name}") from exc
    return name


def validate_schedule_payload(data: dict[str, Any]) -> dict[str, Any]:
    frequency = data.get("scan_frequency")
    if frequency not in VALID_FREQUENCIES:
        raise ValueError("Invalid scan_frequency.")

    enabled = bool(data.get("scan_enabled", True))
    hour = data.get("scan_hour")
    if hour is None:
        raise ValueError("scan_hour is required.")
    hour = int(hour)
    if hour < 0 or hour > 23:
        raise ValueError("scan_hour must be between 0 and 23.")

    timezone_name = _validate_timezone(data.get("scan_timezone") or "UTC")

    interval_hours = data.get("scan_interval_hours")
    day_of_week = data.get("scan_day_of_week")
    day_of_month = data.get("scan_day_of_month")

    if frequency == FREQUENCY_INTERVAL:
        if interval_hours is None:
            raise ValueError("scan_interval_hours is required for INTERVAL.")
        interval_hours = int(interval_hours)
        if interval_hours < SCAN_INTERVAL_HOURS_MIN:
            raise ValueError(
                f"scan_interval_hours must be at least {SCAN_INTERVAL_HOURS_MIN}."
            )
        day_of_week = None
        day_of_month = None
    elif frequency == FREQUENCY_WEEKLY:
        if day_of_week is None:
            raise ValueError("scan_day_of_week is required for WEEKLY.")
        day_of_week = int(day_of_week)
        if day_of_week < 0 or day_of_week > 6:
            raise ValueError("scan_day_of_week must be between 0 and 6.")
        interval_hours = None
        day_of_month = None
    elif frequency == FREQUENCY_MONTHLY:
        if day_of_month is None:
            raise ValueError("scan_day_of_month is required for MONTHLY.")
        day_of_month = int(day_of_month)
        if day_of_month < 1 or day_of_month > 28:
            raise ValueError("scan_day_of_month must be between 1 and 28.")
        interval_hours = None
        day_of_week = None
    else:
        interval_hours = None
        day_of_week = None
        day_of_month = None

    return {
        "scan_enabled": enabled,
        "scan_frequency": frequency,
        "scan_hour": hour,
        "scan_timezone": timezone_name,
        "scan_interval_hours": interval_hours,
        "scan_day_of_week": day_of_week,
        "scan_day_of_month": day_of_month,
    }


def _build_beat_schedule(attrs: dict[str, Any]):
    frequency = attrs["scan_frequency"]
    hour = attrs["scan_hour"]
    timezone_name = attrs["scan_timezone"]

    if frequency == FREQUENCY_INTERVAL:
        schedule, _ = IntervalSchedule.objects.get_or_create(
            every=attrs["scan_interval_hours"],
            period=IntervalSchedule.HOURS,
        )
        return {"interval": schedule, "crontab": None}

    crontab_kwargs: dict[str, Any] = {
        "minute": "0",
        "hour": str(hour),
        "month_of_year": "*",
        "timezone": ZoneInfo(timezone_name),
    }
    if frequency == FREQUENCY_WEEKLY:
        crontab_kwargs["day_of_week"] = str(attrs["scan_day_of_week"])
        crontab_kwargs["day_of_month"] = "*"
    elif frequency == FREQUENCY_MONTHLY:
        crontab_kwargs["day_of_week"] = "*"
        crontab_kwargs["day_of_month"] = str(attrs["scan_day_of_month"])
    else:
        crontab_kwargs["day_of_week"] = "*"
        crontab_kwargs["day_of_month"] = "*"

    crontab, _ = CrontabSchedule.objects.get_or_create(**crontab_kwargs)
    return {"interval": None, "crontab": crontab}


def _merge_periodic_kwargs(
    existing: dict[str, Any],
    *,
    tenant_id: str,
    provider_id: str,
    schedule_attrs: dict[str, Any],
    scanner_args: dict | None,
) -> dict[str, Any]:
    merged = {
        "tenant_id": tenant_id,
        "provider_id": provider_id,
        SCHEDULE_KWARGS_KEY: schedule_attrs,
    }
    existing_scanner = existing.get("scanner_args")
    if scanner_args is not None:
        if scanner_args.get("compliances"):
            merged["scanner_args"] = {"compliances": scanner_args["compliances"]}
    elif isinstance(existing_scanner, dict) and existing_scanner.get("compliances"):
        merged["scanner_args"] = {
            "compliances": existing_scanner["compliances"],
        }
    return merged


def upsert_provider_schedule(
    provider: Provider,
    payload: dict[str, Any],
    scanner_args: dict | None = None,
) -> dict[str, Any]:
    """Create or update the Celery beat schedule for a provider."""
    attrs = validate_schedule_payload(payload)
    tenant_id = str(provider.tenant_id)
    provider_id = str(provider.id)
    task_name = scheduled_task_name(provider_id)
    beat = _build_beat_schedule(attrs)

    periodic_task = get_scheduled_periodic_task(provider_id)
    existing_kwargs = _parse_periodic_kwargs(periodic_task) if periodic_task else {}
    periodic_kwargs = _merge_periodic_kwargs(
        existing_kwargs,
        tenant_id=tenant_id,
        provider_id=provider_id,
        schedule_attrs=attrs,
        scanner_args=scanner_args,
    )

    if periodic_task is None:
        periodic_task = PeriodicTask(
            name=task_name,
            task="scan-perform-scheduled",
            one_off=False,
        )

    periodic_task.interval = beat["interval"]
    periodic_task.crontab = beat["crontab"]
    periodic_task.enabled = attrs["scan_enabled"]
    periodic_task.kwargs = json.dumps(periodic_kwargs)
    periodic_task.start_time = datetime.now(UTC)
    periodic_task.save()

    next_scan_at = (
        compute_next_scan_at(periodic_task) if attrs["scan_enabled"] else None
    )

    with rls_transaction(tenant_id):
        scheduled_scan = (
            Scan.objects.filter(
                tenant_id=tenant_id,
                provider_id=provider_id,
                trigger=Scan.TriggerChoices.SCHEDULED,
                state__in=(StateChoices.SCHEDULED, StateChoices.AVAILABLE),
                scheduler_task_id=periodic_task.id,
                task__isnull=True,
            )
            .order_by("scheduled_at", "inserted_at")
            .first()
        )
        scan_scanner_args = periodic_kwargs.get("scanner_args") or {}
        if scheduled_scan is None:
            scheduled_scan = Scan.objects.create(
                tenant_id=tenant_id,
                name=SCHEDULED_SCAN_NAME,
                provider_id=provider_id,
                trigger=Scan.TriggerChoices.SCHEDULED,
                state=StateChoices.SCHEDULED
                if attrs["scan_enabled"]
                else StateChoices.AVAILABLE,
                scheduled_at=next_scan_at or datetime.now(UTC),
                next_scan_at=next_scan_at,
                scheduler_task_id=periodic_task.id,
                scanner_args=scan_scanner_args,
            )
            attack_paths_db_utils.create_attack_paths_scan(
                tenant_id=tenant_id,
                scan_id=str(scheduled_scan.id),
                provider_id=provider_id,
            )
        else:
            scheduled_scan.name = SCHEDULED_SCAN_NAME
            scheduled_scan.scheduled_at = next_scan_at or scheduled_scan.scheduled_at
            scheduled_scan.next_scan_at = next_scan_at
            scheduled_scan.state = (
                StateChoices.SCHEDULED
                if attrs["scan_enabled"]
                else StateChoices.AVAILABLE
            )
            if scan_scanner_args:
                scheduled_scan.scanner_args = scan_scanner_args
            scheduled_scan.save()

    return read_schedule_attributes(provider, periodic_task)


def remove_provider_schedule(provider: Provider) -> None:
    provider_id = str(provider.id)
    tenant_id = str(provider.tenant_id)
    periodic_task = get_scheduled_periodic_task(provider_id)
    if periodic_task is None:
        return

    with rls_transaction(tenant_id):
        Scan.objects.filter(
            tenant_id=tenant_id,
            provider_id=provider_id,
            trigger=Scan.TriggerChoices.SCHEDULED,
            state__in=(StateChoices.SCHEDULED, StateChoices.AVAILABLE),
            scheduler_task_id=periodic_task.id,
            task__isnull=True,
        ).delete()

    periodic_task.delete()

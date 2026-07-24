from datetime import UTC, datetime

from api.exceptions import ConflictException
from api.models import Provider
from tasks.provider_schedules import (
    FREQUENCY_DAILY,
    get_scheduled_periodic_task,
    upsert_provider_schedule,
)
from tasks.tasks import perform_scheduled_scan_task


def schedule_provider_scan(
    provider_instance: Provider, scanner_args: dict | None = None
):
    """Legacy daily schedule used by POST /schedules/daily.

    Creates (or refuses if one already exists) a daily crontab schedule and
    kicks off an immediate scan, matching historical OSS behaviour.
    """
    provider_id = str(provider_instance.id)
    scanner_args = scanner_args or {}

    if get_scheduled_periodic_task(provider_id) is not None:
        raise ConflictException(
            detail="There is already a scheduled scan for this provider.",
            pointer="/data/attributes/provider_id",
        )

    hour = datetime.now(UTC).hour
    upsert_provider_schedule(
        provider_instance,
        {
            "scan_enabled": True,
            "scan_frequency": FREQUENCY_DAILY,
            "scan_hour": hour,
            "scan_timezone": "UTC",
            "scan_interval_hours": None,
            "scan_day_of_week": None,
            "scan_day_of_month": None,
        },
        scanner_args=scanner_args,
    )

    apply_kwargs = {
        "tenant_id": str(provider_instance.tenant_id),
        "provider_id": provider_id,
    }
    if scanner_args.get("compliances"):
        apply_kwargs["scanner_args"] = {"compliances": scanner_args["compliances"]}

    return perform_scheduled_scan_task.apply_async(
        kwargs=apply_kwargs,
        countdown=5,  # Avoid race conditions between the worker and the database
    )

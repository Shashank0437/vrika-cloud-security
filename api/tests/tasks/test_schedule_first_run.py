"""Use real Beat due calculations without writing schedules or starting scans."""

import json
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from django_celery_beat.models import CrontabSchedule, IntervalSchedule, PeriodicTask
from django_celery_beat.schedulers import ModelEntry
from tasks import provider_schedules as schedules

NOW = datetime(2026, 9, 22, 5, 9, 14, tzinfo=UTC)
PROVIDER = SimpleNamespace(
    id="33333333-3333-4333-8333-333333333333",
    tenant_id="11111111-1111-4111-8111-111111111111",
)


def payload(**changes):
    return {
        "scan_enabled": True,
        "scan_frequency": "DAILY",
        "scan_hour": 12,
        "scan_timezone": "Asia/Calcutta",
        "scan_interval_hours": None,
        "scan_day_of_week": None,
        "scan_day_of_month": None,
        **changes,
    }


@pytest.fixture
def clock():
    state = {"now": NOW}

    class FrozenDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            value = state["now"]
            return value.astimezone(tz) if tz else value.replace(tzinfo=None)

    with (
        patch.object(schedules, "datetime", FrozenDateTime),
        patch.object(ModelEntry, "_default_now", side_effect=lambda: state["now"]),
        patch(
            "django.db.backends.base.base.BaseDatabaseWrapper.ensure_connection",
            side_effect=AssertionError("Schedule tests must not access the database"),
        ),
        patch(
            "celery.app.task.Task.apply_async",
            side_effect=AssertionError("Saving a schedule must not launch any task"),
        ),
    ):
        yield state


@pytest.fixture
def save_schedule(clock):
    state = {"periodic": None}

    def save_periodic(model, *args, **kwargs):
        # Match the fields Beat resets on disable, without writing to the DB.
        if not model.enabled:
            model.last_run_at = None
        model.pk = 1
        model.date_changed = clock["now"]
        state["periodic"] = model

    with (
        patch.object(
            schedules,
            "get_scheduled_periodic_task",
            side_effect=lambda provider_id: state["periodic"],
        ),
        patch.object(
            CrontabSchedule.objects,
            "get_or_create",
            side_effect=lambda **kwargs: (CrontabSchedule(**kwargs), True),
        ),
        patch.object(
            IntervalSchedule.objects,
            "get_or_create",
            side_effect=lambda **kwargs: (IntervalSchedule(**kwargs), True),
        ),
        patch.object(PeriodicTask, "save", autospec=True, side_effect=save_periodic),
        patch.object(schedules.Scan, "objects") as scans,
        patch.object(
            schedules, "rls_transaction", side_effect=lambda *a, **kw: nullcontext()
        ),
        patch.object(schedules, "last_completed_scan_at", return_value=None),
        patch.object(schedules.attack_paths_db_utils, "create_attack_paths_scan"),
    ):
        scans.filter.return_value.order_by.return_value.first.return_value = None
        scans.create.return_value.id = "22222222-2222-4222-8222-222222222222"

        def upsert(attrs, scanner_args=None):
            response = schedules.upsert_provider_schedule(
                PROVIDER, attrs, scanner_args=scanner_args
            )
            return state["periodic"], response, scans.create.call_args.kwargs

        yield upsert


def beat_entry(periodic, clock):
    entry = ModelEntry(periodic)
    entry.schedule.nowfun = lambda: clock["now"].astimezone(
        getattr(entry.schedule, "tz", UTC)
    )
    return entry


@pytest.mark.parametrize(
    "attrs,expected",
    [
        (payload(), datetime(2026, 9, 22, 6, 30, tzinfo=UTC)),
        (payload(scan_hour=9), datetime(2026, 9, 23, 3, 30, tzinfo=UTC)),
        (
            payload(scan_frequency="WEEKLY", scan_day_of_week=5),
            datetime(2026, 9, 25, 6, 30, tzinfo=UTC),
        ),
        (
            payload(scan_frequency="WEEKLY", scan_day_of_week=2, scan_hour=9),
            datetime(2026, 9, 29, 3, 30, tzinfo=UTC),
        ),
        (
            payload(scan_frequency="MONTHLY", scan_day_of_month=25),
            datetime(2026, 9, 25, 6, 30, tzinfo=UTC),
        ),
        (
            payload(scan_frequency="MONTHLY", scan_day_of_month=1),
            datetime(2026, 10, 1, 6, 30, tzinfo=UTC),
        ),
        (
            payload(scan_timezone="UTC", scan_hour=6),
            datetime(2026, 9, 22, 6, tzinfo=UTC),
        ),
        (
            payload(scan_timezone="America/New_York", scan_hour=9),
            datetime(2026, 9, 22, 13, tzinfo=UTC),
        ),
        (
            payload(scan_timezone="Asia/Kathmandu", scan_hour=12),
            datetime(2026, 9, 22, 6, 15, tzinfo=UTC),
        ),
        (
            payload(scan_frequency="INTERVAL", scan_interval_hours=48),
            datetime(2026, 9, 22, 6, 30, tzinfo=UTC),
        ),
        (
            payload(scan_frequency="INTERVAL", scan_interval_hours=24, scan_hour=9),
            datetime(2026, 9, 23, 3, 30, tzinfo=UTC),
        ),
    ],
)
def test_first_run_waits_until_selected_time(save_schedule, clock, attrs, expected):
    periodic, response, scan = save_schedule(attrs)
    entry = beat_entry(periodic, clock)
    assert not entry.is_due().is_due
    assert entry.is_due().next == (expected - clock["now"]).total_seconds()
    assert response["next_scan_at"] == expected
    assert scan["scheduled_at"] == expected
    assert scan["next_scan_at"] == expected
    assert scan["state"] == "scheduled"
    clock["now"] = expected - timedelta(seconds=1)
    assert not entry.is_due().is_due
    clock["now"] = expected
    assert entry.is_due().is_due


def test_creation_exactly_at_scan_hour_waits_for_next_occurrence(save_schedule, clock):
    clock["now"] = datetime(2026, 9, 22, 6, 30, tzinfo=UTC)
    periodic, response, _ = save_schedule(payload())
    assert not beat_entry(periodic, clock).is_due().is_due
    assert response["next_scan_at"] == datetime(2026, 9, 23, 6, 30, tzinfo=UTC)


def test_timezone_daylight_saving_transition(save_schedule, clock):
    clock["now"] = datetime(2026, 3, 7, 18, tzinfo=UTC)
    periodic, response, _ = save_schedule(
        payload(scan_timezone="America/New_York", scan_hour=12)
    )
    expected = datetime(2026, 3, 8, 16, tzinfo=UTC)
    assert response["next_scan_at"] == expected
    entry = beat_entry(periodic, clock)
    assert not entry.is_due().is_due
    clock["now"] = expected - timedelta(seconds=1)
    assert not entry.is_due().is_due
    clock["now"] = expected
    assert entry.is_due().is_due


@pytest.mark.parametrize("frequency", ["DAILY", "INTERVAL"])
def test_disabled_schedule_does_not_run_and_reenable_does_not_catch_up(
    save_schedule, clock, frequency
):
    attrs = payload(
        scan_frequency=frequency,
        scan_interval_hours=48 if frequency == "INTERVAL" else None,
    )
    periodic, _, _ = save_schedule(attrs)
    periodic, response, _ = save_schedule({**attrs, "scan_enabled": False})
    assert response["next_scan_at"] is None
    assert not beat_entry(periodic, clock).is_due().is_due
    clock["now"] += timedelta(days=4)
    periodic, response, _ = save_schedule(attrs)
    assert not beat_entry(periodic, clock).is_due().is_due
    assert response["next_scan_at"] == datetime(2026, 9, 26, 6, 30, tzinfo=UTC)


def test_editing_schedule_skips_missed_old_slot(save_schedule, clock):
    periodic, _, _ = save_schedule(payload())
    periodic.last_run_at = NOW - timedelta(days=10)
    periodic.total_run_count = 7
    periodic, response, _ = save_schedule(payload(scan_hour=9))
    assert periodic.total_run_count == 7
    assert not beat_entry(periodic, clock).is_due().is_due
    assert response["next_scan_at"] == datetime(2026, 9, 23, 3, 30, tzinfo=UTC)


def test_interval_next_run_and_unchanged_save_preserve_cadence(save_schedule, clock):
    attrs = payload(scan_frequency="INTERVAL", scan_interval_hours=48)
    periodic, response, _ = save_schedule(attrs)
    first = response["next_scan_at"]
    periodic.last_run_at = first
    periodic.total_run_count = 1
    clock["now"] = first + timedelta(hours=12)
    periodic, response, _ = save_schedule(attrs, scanner_args={"compliances": ["cis"]})
    assert periodic.last_run_at == first
    assert periodic.total_run_count == 1
    assert response["next_scan_at"] == first + timedelta(hours=48)
    assert json.loads(periodic.kwargs)["scanner_args"] == {"compliances": ["cis"]}
    assert not beat_entry(periodic, clock).is_due().is_due
    clock["now"] = first + timedelta(hours=48)
    assert beat_entry(periodic, clock).is_due().is_due


def test_restart_before_first_run_preserves_anchor(save_schedule, clock):
    periodic, response, _ = save_schedule(payload())
    assert not beat_entry(periodic, clock).is_due().is_due
    clock["now"] += timedelta(minutes=5)
    entry = beat_entry(periodic, clock)
    assert not entry.is_due().is_due
    clock["now"] = response["next_scan_at"]
    assert entry.is_due().is_due

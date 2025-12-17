"""Timezone utilities for localizing timestamps."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Optional

from src.common.config import LOCAL_TIMEZONE

try:  # Python 3.9+
    from zoneinfo import ZoneInfo  # type: ignore
except ModuleNotFoundError:  # pragma: no cover - fallback for older Python
    ZoneInfo = None  # type: ignore


_FALLBACK_OFFSETS = {
    "Asia/Ho_Chi_Minh": timedelta(hours=7),
    "Asia/Bangkok": timedelta(hours=7),
    "UTC+7": timedelta(hours=7),
    "UTC+07:00": timedelta(hours=7),
    "GMT+7": timedelta(hours=7),
}


@lru_cache(maxsize=1)
def get_local_timezone() -> timezone:
    """Return the configured local timezone, with sane fallbacks."""

    if ZoneInfo is not None:
        try:
            return ZoneInfo(LOCAL_TIMEZONE)  # type: ignore[arg-type]
        except Exception:  # noqa: BLE001 - best-effort fallback
            pass

    offset = _FALLBACK_OFFSETS.get(LOCAL_TIMEZONE)
    if offset is None:
        # Attempt to parse plain offsets such as "+07" or "7"
        cleaned = LOCAL_TIMEZONE.replace("UTC", "").replace("GMT", "").replace(":", "").strip()
        sign = 1
        if cleaned.startswith("+"):
            cleaned = cleaned[1:]
        elif cleaned.startswith("-"):
            sign = -1
            cleaned = cleaned[1:]

        try:
            hours = float(cleaned)
            offset = timedelta(hours=sign * hours)
        except ValueError:
            offset = timedelta(hours=7)

    return timezone(offset)


LOCAL_TZ = get_local_timezone()


def utc_iso_to_local(iso_timestamp: str) -> Optional[str]:
    """Convert UTC ISO8601 timestamp string to the configured local timezone."""

    if not iso_timestamp:
        return None

    try:
        if iso_timestamp.endswith("Z"):
            utc_dt = datetime.fromisoformat(iso_timestamp.replace("Z", "+00:00"))
        else:
            utc_dt = datetime.fromisoformat(iso_timestamp)
    except ValueError:
        return None

    if utc_dt.tzinfo is None:
        utc_dt = utc_dt.replace(tzinfo=timezone.utc)

    local_dt = utc_dt.astimezone(LOCAL_TZ)
    return local_dt.isoformat()


def now_local_iso() -> str:
    """Current time in the configured local timezone as ISO8601 string."""

    return datetime.now(LOCAL_TZ).isoformat()


def now_utc_iso() -> str:
    """Current time in UTC as ISO8601 string."""

    return datetime.utcnow().replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")



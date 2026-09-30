"""Privacy-safe native availability diagnostics, separate from hook readiness."""

from __future__ import annotations

import re


def doctor_native_availability() -> dict[str, object]:
    from ..native_runtime import native_runtime_status

    try:
        status = native_runtime_status()
    except (OSError, RuntimeError, ValueError):
        return {
            "available": False,
            "compatible": False,
            "reason_code": "native_status_probe_failed",
            "evaluation_verified": False,
        }
    reason = status.reason
    if not re.fullmatch(r"[a-z0-9_.-]{1,96}", reason):
        reason = "native_status_reason_unavailable"
    return {
        "mode": status.mode,
        "available": status.available,
        "compatible": status.compatible,
        "reason_code": reason,
        "evaluation_verified": False,
    }

"""Conservative readiness copy for doctor's passive harness diagnostics."""

from __future__ import annotations

from collections.abc import Mapping


def doctor_runtime_readiness(diagnostics: Mapping[str, object]) -> dict[str, str]:
    """Do not promote registration, manifest trust or a CLI probe to evaluation proof.

    The current doctor probes do not verify an authenticated Guard decision in
    the loaded harness session. Until that proof has its own contract, this
    projection deliberately cannot return a passing readiness result.
    """

    state = "unknown"
    reason = "hook_evaluation_unverified"
    detail = (
        "Doctor has not verified an authenticated Guard decision from this harness. "
        "Registration and CLI checks do not prove runtime readiness."
    )
    if diagnostics.get("setup_status") == "broken":
        state = "fail"
        reason = "guard_setup_broken"
        detail = (
            "Guard registration is marked broken. Preserve this report and inspect the warnings "
            "before changing the installation. The loaded session's evaluation remains unverified."
        )
    elif diagnostics.get("setup_status") in ("partial", "not_found"):
        reason = "hook_registration_unconfirmed"
        detail = (
            "Guard registration is incomplete or missing. Doctor has not verified an authenticated "
            "Guard decision from this harness."
        )
    else:
        probe = diagnostics.get("runtime_probe")
        if isinstance(probe, Mapping) and probe.get("timed_out") is True:
            reason = "harness_probe_timed_out"
            detail = (
                "The harness diagnostic check timed out. Inspect the probe and daemon diagnostics; "
                "no authenticated Guard decision was verified."
            )
        elif isinstance(probe, Mapping) and probe.get("ok") is False:
            reason = "harness_probe_failed"
            detail = (
                "The harness diagnostic check failed. Inspect the probe and daemon diagnostics; "
                "no authenticated Guard decision was verified."
            )
    return {"state": state, "reason_code": reason, "detail": detail}

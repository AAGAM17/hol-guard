"""Bounded native proof diagnostics without response text or request payloads."""

import re
from collections.abc import Mapping

_SAFE_REASON_CODE = re.compile(r"[a-z][a-z0-9_]{0,95}\Z")
_DECISIONS = frozenset({"allow", "deny", "ask", "block", "review", "continue"})


def hook_failure_detail(harness: str, event: str, response: Mapping[str, object]) -> dict[str, object]:
    specific = response.get("hookSpecificOutput")
    permission = specific.get("permissionDecision") if isinstance(specific, Mapping) else None
    decision = response.get("decision")
    reason = response.get("reason_code")
    return {
        "harness": harness,
        "event": event,
        "decision": decision if isinstance(decision, str) and decision in _DECISIONS else None,
        "permission_decision": permission if isinstance(permission, str) and permission in _DECISIONS else None,
        "reason_code": reason if isinstance(reason, str) and _SAFE_REASON_CODE.fullmatch(reason) else None,
    }

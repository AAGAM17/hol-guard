"""Repair a tampered command policy from the resident hook worker.

The hook never launches the CLI. Recovery runs through the daemon's
extension-control service. When that service needs approval, the deny reason
includes one signed loopback link to the local Repair protection page.
The current tool call stays denied either way.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable, Mapping
from pathlib import Path

from ..runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from ..runtime.extension_control_authority import AuthorityHealth
from .extension_control_errors import ExtensionControlApiError

_AUTHORITY_BLOCK_REASON = "native_command_control_authority_block"
_REPAIRABLE_HEALTH = frozenset({AuthorityHealth.TAMPERED, AuthorityHealth.RECOVERY_REQUIRED})
_PROTECTED = AuthorityHealth.PROTECTED.value

_RETRY_REASON = "HOL Guard repaired trusted protection settings. Retry this action."
_APPROVAL_REASON = (
    "HOL Guard blocked this action because trusted protection settings need repair. "
    "Open this local page and press Repair protection: {url}"
)
_APPROVAL_REASON_WITHOUT_URL = (
    "HOL Guard blocked this action because trusted protection settings need repair. "
    "Open HOL Guard Extensions and press Repair protection."
)

RepairCaller = Callable[[dict[str, object]], object]
RepairUrl = Callable[[Path], str | None]

_auth_barrier: tuple[str, int] | None = None


def reset_command_policy_repair_memory() -> None:
    """Forget a previous approval barrier. Tests use this between cases."""

    global _auth_barrier
    _auth_barrier = None


def apply_command_policy_repair(
    store: object,
    native_result: Mapping[str, object],
    *,
    guard_home: Path,
    recover: RepairCaller | None = None,
    repair_page_url: RepairUrl | None = None,
) -> dict[str, object]:
    """Return the native result, with a repair reason when this block can be repaired."""

    try:
        result = dict(native_result)
    except Exception:
        return {}
    try:
        return _apply_command_policy_repair(
            store,
            result,
            guard_home=guard_home,
            recover=recover,
            repair_page_url=repair_page_url,
        )
    except Exception:
        return result


def _apply_command_policy_repair(
    store: object,
    result: dict[str, object],
    *,
    guard_home: Path,
    recover: RepairCaller | None,
    repair_page_url: RepairUrl | None,
) -> dict[str, object]:
    global _auth_barrier

    if str(result.get("reason_code") or "") != _AUTHORITY_BLOCK_REASON:
        return result
    if str(result.get("minimum_action") or "") == "allow" or result.get("decision") == "allow":
        return result
    reader = getattr(store, "read_extension_control_authority_for_registry", None)
    if not callable(reader):
        return result
    view = reader(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    health = getattr(view, "health", None)
    if health not in _REPAIRABLE_HEALTH:
        return result
    revision = getattr(view, "revision", None)
    barrier_key = (health.value, int(revision)) if isinstance(revision, int) else None
    if barrier_key is not None and barrier_key == _auth_barrier:
        return _approval_required(result, guard_home, repair_page_url)
    if recover is not None and barrier_key != _auth_barrier:
        try:
            outcome = recover({"session_nonce": secrets.token_hex(16)})
        except ExtensionControlApiError as exc:
            if exc.code == "authority_not_recoverable":
                return result
            if barrier_key is not None:
                _auth_barrier = barrier_key
            return _approval_required(result, guard_home, repair_page_url)
        except Exception:
            return _approval_required(result, guard_home, repair_page_url)
        else:
            outcome_health = outcome.get("health") if isinstance(outcome, Mapping) else None
            if outcome_health == _PROTECTED:
                _auth_barrier = None
                result["reason"] = _RETRY_REASON
                result["repair_status"] = "repaired"
                return result
    return _approval_required(result, guard_home, repair_page_url)


def _approval_required(
    result: dict[str, object],
    guard_home: Path,
    repair_page_url: RepairUrl | None,
) -> dict[str, object]:
    url = _safe_repair_url(guard_home, repair_page_url)
    if url:
        result["reason"] = _APPROVAL_REASON.replace("{url}", url)
        result["repair_url"] = url
    else:
        result["reason"] = _APPROVAL_REASON_WITHOUT_URL
        result.pop("repair_url", None)
    result["repair_status"] = "approval_required"
    return result


def _safe_repair_url(guard_home: Path, repair_page_url: RepairUrl | None) -> str | None:
    try:
        url = repair_page_url(guard_home) if repair_page_url is not None else command_policy_repair_page_url(guard_home)
    except Exception:
        return None
    if not isinstance(url, str) or not url:
        return None
    from ..approval_hook_copy import is_loopback_approval_url

    if not is_loopback_approval_url(url):
        return None
    return url


def command_policy_repair_page_url(guard_home: Path) -> str | None:
    """Signed loopback URL for the one-button repair page, or None when it is not safe."""

    from ..approval_hook_copy import authenticated_approval_review_url, is_loopback_approval_url
    from .manager import read_approval_center_locator

    locator = read_approval_center_locator(guard_home)
    daemon_url = getattr(locator, "daemon_url", None)
    if not isinstance(daemon_url, str) or not daemon_url:
        return None
    page = f"{daemon_url.rstrip('/')}/protection/repair"
    if not is_loopback_approval_url(page):
        return None
    signed = authenticated_approval_review_url(page, guard_home=guard_home)
    if not isinstance(signed, str) or not is_loopback_approval_url(signed):
        return None
    return signed

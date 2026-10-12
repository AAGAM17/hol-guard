"""Package shim audit proof persistence (status itself is the resident's ``shim_admin``)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from ..path_support import resolves_within_root
from ..safe_output import write_text_atomic_no_follow


class HarnessContextLike(Protocol):
    @property
    def guard_home(self) -> Path: ...


_PACKAGE_SHIM_MANIFEST = "manifest.json"
PACKAGE_SHIM_STATUS_FD_ENV_VAR = "HOL_GUARD_PACKAGE_SHIM_STATUS_FD"


def _package_shim_manifest_path(context: HarnessContextLike) -> Path:
    return context.guard_home / "package-shims" / _PACKAGE_SHIM_MANIFEST


def _load_package_shim_manifest(context: HarnessContextLike) -> dict[str, object]:
    manifest_path = _package_shim_manifest_path(context)
    if not manifest_path.exists():
        return {}
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _write_package_shim_manifest(context: HarnessContextLike, payload: dict[str, object]) -> None:
    manifest_path = _package_shim_manifest_path(context)
    if not resolves_within_root(context.guard_home, manifest_path):
        raise ValueError("package shim manifest escapes the Guard home")
    write_text_atomic_no_follow(manifest_path, json.dumps(payload, sort_keys=True))


def record_package_shim_audit_result(
    context: HarnessContextLike,
    *,
    audited_at: str | None = None,
) -> None:
    manifest = _load_package_shim_manifest(context)
    manifest["last_audit_at"] = audited_at if audited_at is not None else datetime.now(timezone.utc).isoformat()
    _write_package_shim_manifest(context, manifest)

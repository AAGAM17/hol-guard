"""Short-lived, this-daemon rollback receipts for reviewed Codex setup."""

from __future__ import annotations

import json
import re
import secrets
import shutil
import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..approval_gate import (
    ApprovalGateError,
    consume_local_cli_trust_grant,
    input_from_mapping,
    require_local_cli_trust,
)
from ..runtime.codex_mcp_setup import CodexMcpSetupReceipt, rollback_reviewed_codex_mcp

if TYPE_CHECKING:
    from ..store import GuardStore

_TTL = 3600.0
_LIMIT = 32
_HANDLE = re.compile(r"[a-f0-9]{64}\Z")


class RegistryUndoError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        self.status = status
        self.code = code
        super().__init__(message)


@dataclass(frozen=True)
class _OwnedSetup:
    receipt: CodexMcpSetupReceipt
    candidate_json: str
    expires_at: float


class RegistrySetupUndo:
    def __init__(self, store: GuardStore) -> None:
        self._store = store
        self._lock = threading.Lock()
        self._receipts: dict[str, _OwnedSetup] = {}

    def _prune(self) -> None:
        now = time.monotonic()
        self._receipts = {handle: item for handle, item in self._receipts.items() if item.expires_at > now}

    def remember(self, receipt: CodexMcpSetupReceipt, candidate: dict[str, object]) -> str:
        if receipt.name != candidate.get("setup_name"):
            raise ValueError("codex_setup_outcome_uncertain")
        entry = (
            {"command": candidate["command"], "args": candidate["arguments"]}
            if candidate.get("kind") == "package"
            else {"url": candidate["endpoint"]}
        )
        if json.loads(receipt.entry_json) != entry:
            raise ValueError("codex_setup_outcome_uncertain")
        with self._lock:
            self._prune()
            if len(self._receipts) >= _LIMIT:
                raise ValueError("codex_setup_receipt_limit")
            handle = secrets.token_hex(32)
            self._receipts[handle] = _OwnedSetup(
                receipt,
                json.dumps(candidate, sort_keys=True, separators=(",", ":"), allow_nan=False),
                time.monotonic() + _TTL,
            )
            return handle

    def _lookup(self, value: object) -> tuple[str, _OwnedSetup]:
        self._prune()
        if not isinstance(value, str) or not _HANDLE.fullmatch(value) or value not in self._receipts:
            raise RegistryUndoError(
                404, "codex_setup_receipt_unavailable", "This setup can no longer be undone here. Review it in Codex."
            )
        return value, self._receipts[value]

    def preview(self, payload: dict[str, object]) -> dict[str, object]:
        with self._lock:
            handle, record = self._lookup(payload.get("rollback_handle"))
            candidate = json.loads(record.candidate_json)
            return {
                **candidate,
                "rollback_handle": handle,
                "permissions_granted": False,
                "host_change_applied": False,
                "next_action": "Review removal of the connection added by this setup.",
            }

    def recent(self) -> list[dict[str, object]]:
        with self._lock:
            self._prune()
            recent = []
            for handle, record in reversed(tuple(self._receipts.items())):
                candidate = json.loads(record.candidate_json)
                recent.append(
                    {
                        "rollback_handle": handle,
                        "setup_name": record.receipt.name,
                        **{key: candidate.get(key) for key in ("kind", "registry_name", "version", "selection_digest")},
                    }
                )
            return recent

    def rollback(self, payload: dict[str, object]) -> dict[str, object]:
        with self._lock:
            handle, record = self._lookup(payload.get("rollback_handle"))
            candidate = json.loads(record.candidate_json)
            if (
                payload.get("confirm_host_change") is not True
                or payload.get("selection_digest") != candidate["selection_digest"]
                or payload.get("setup_name") != record.receipt.name
            ):
                raise RegistryUndoError(
                    409, "codex_rollback_review_changed", "Review this connection before undoing setup."
                )
            nonce = payload.get("session_nonce")
            if not isinstance(nonce, str) or not 1 <= len(nonce) <= 128:
                raise RegistryUndoError(400, "invalid_session_nonce", "Review this connection again.")
            action = "codex-mcp-setup-rollback"
            subject = f"{action}:{handle}:{record.receipt.version}:{candidate['selection_digest']}"
            try:
                grant = require_local_cli_trust(
                    self._store.guard_home,
                    approval_gate_input=input_from_mapping(payload),
                    action=action,
                    subject=subject,
                    session_nonce=nonce,
                )
                consume_local_cli_trust_grant(
                    self._store.guard_home, grant, action=action, subject=subject, session_nonce=nonce
                )
            except ApprovalGateError as error:
                raise RegistryUndoError(error.status, error.code, str(error)) from error
            executable = shutil.which("codex")
            if executable is None:
                raise RegistryUndoError(409, "codex_host_unavailable", "Open Codex and review this connection.")
            try:
                rollback_reviewed_codex_mcp(executable, record.receipt)
            except (ValueError, OSError) as error:
                message = (
                    "Codex configuration changed after setup. Guard kept it unchanged. Review this connection in Codex."
                    if str(error) == "codex_config_changed"
                    else "Guard could not verify removal. Check this connection in Codex before retrying."
                )
                raise RegistryUndoError(409, str(error), message) from error
            del self._receipts[handle]
            return {
                "host": "codex",
                "kind": candidate.get("kind", "remote"),
                "setup_name": record.receipt.name,
                "host_change_applied": True,
                "permissions_granted": False,
                "setup_rolled_back": True,
                "next_action": "Restart Codex and refresh its connections in Guard.",
            }

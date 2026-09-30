"""Validate and join bounded Codex capture rows."""

# The recording module owns the shared bounded parsers; this companion module
# intentionally reuses those private helpers without exposing them publicly.
# pyright: reportPrivateUsage=false

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable, Mapping
from typing import cast

from .codex_binding_capture import (
    BINDABLE_CODEX_HOOK_EVENTS,
    CAPTURE_SCHEMA,
    MAX_CAPTURE_BYTES,
    MAX_CAPTURE_RECORDS,
    _bounded_text,
    _canonical_json,
    _json_object,
    _receipt_projection,
    _tool_use_id,
)
from .codex_hook_manifest import MANAGED_CODEX_HOOK_EVENTS
from .daemon.hook_request_parsing import runtime_hook_event_name


def _valid_fingerprint(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _validated_record(
    value: Mapping[str, object], *, run_id: str | None = None
) -> tuple[tuple[str, str, str, str] | None, str] | None:
    if value.get("schema") != CAPTURE_SCHEMA:
        return None
    row_run_id = value.get("run_id")
    harness = value.get("harness")
    event_name = value.get("event_name")
    route = value.get("route")
    state = value.get("tool_use_id_state")
    if (
        not isinstance(row_run_id, str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}", row_run_id) is None
        or (run_id is not None and row_run_id != run_id)
        or not isinstance(harness, str)
        or _bounded_text(harness, maximum=64) is None
        or harness != "codex"
        or not isinstance(event_name, str)
        or _bounded_text(event_name, maximum=64) is None
        or runtime_hook_event_name({"hook_event_name": event_name}) not in MANAGED_CODEX_HOOK_EVENTS
        or not isinstance(route, str)
        or route not in {"bridge_ingress", "native_worker"}
        or not isinstance(state, str)
        or state not in {"missing", "unsupported", "present"}
    ):
        return None

    canonical_event = runtime_hook_event_name({"hook_event_name": event_name})
    expected = {"schema", "run_id", "route", "harness", "event_name", "tool_use_id_state"}
    if state == "present":
        expected.add("tool_use_id")
    if route == "bridge_ingress":
        expected.update({"raw_payload_sha256", "forwarded_payload_sha256"})
    else:
        expected.update({"forwarded_payload_sha256", "decision_scope", "receipt"})
    if set(value) != expected:
        return None
    if route == "bridge_ingress":
        if not _valid_fingerprint(value.get("raw_payload_sha256")) or not _valid_fingerprint(
            value.get("forwarded_payload_sha256")
        ):
            return None
    else:
        receipt = value.get("receipt")
        typed_receipt = cast(Mapping[str, object], receipt) if isinstance(receipt, Mapping) else None
        if (
            not _valid_fingerprint(value.get("forwarded_payload_sha256"))
            or value.get("decision_scope") != "native_edge"
            or typed_receipt is None
            or _receipt_projection(typed_receipt) != dict(typed_receipt)
            or typed_receipt.get("harness") != harness
            or typed_receipt.get("event_name") != canonical_event
        ):
            return None
    if state in {"missing", "unsupported"}:
        return None if "tool_use_id" in value else (None, state)
    identifier = value.get("tool_use_id")
    if _tool_use_id({"tool_use_id": identifier}) is not identifier:
        return None
    return (row_run_id, harness, canonical_event, cast(str, identifier)), route


def valid_existing_records(raw: bytes, *, run_id: str) -> int | None:
    if not raw:
        return 0
    if not raw.endswith(b"\n"):
        return None
    lines = raw.splitlines()
    if not lines or len(lines) > MAX_CAPTURE_RECORDS:
        return None
    for line in lines:
        row = _json_object(line)
        if row is None or _validated_record(row, run_id=run_id) is None:
            return None
    return len(lines)


def _normalize_record(value: Mapping[str, object]) -> tuple[tuple[str, str, str, str] | None, str] | None:
    normalized = _validated_record(value)
    if normalized is None:
        return None
    return normalized


def join_binding_records(records: Iterable[object]) -> dict[str, object]:
    """Join ingress/native rows using exact identity and payload continuity."""

    groups: dict[tuple[str, str, str, str], dict[str, list[Mapping[str, object]]]] = defaultdict(
        lambda: {"bridge_ingress": [], "native_worker": []}
    )
    issues: list[dict[str, object]] = []
    count = 0
    for record in records:
        count += 1
        if count > MAX_CAPTURE_RECORDS:
            issues.append({"status": "ambiguous", "reason": "record_limit_exceeded"})
            break
        if not isinstance(record, Mapping):
            issues.append({"status": "invalid", "reason": "record_not_object"})
            continue
        record = cast(Mapping[str, object], record)
        encoded = _canonical_json(dict(record))
        if encoded is None or len(encoded) > MAX_CAPTURE_BYTES:
            issues.append({"status": "invalid", "reason": "record_size"})
            continue
        normalized = _normalize_record(record)
        if normalized is None:
            issues.append({"status": "invalid", "reason": "record_shape"})
            continue
        key, route = normalized
        if key is None:
            reason = "missing_tool_use_id" if route == "missing" else "unsupported_tool_use_id"
            issues.append({"status": "unbound", "reason": reason})
            continue
        groups[key][route].append(record)

    joins: list[dict[str, object]] = []
    for key, grouped in groups.items():
        if key[2] not in BINDABLE_CODEX_HOOK_EVENTS:
            joins.append({"status": "not_applicable", "reason": "native_receipt_unsupported_event", "identity": key})
            continue
        bridge_rows = grouped["bridge_ingress"]
        native_rows = grouped["native_worker"]
        if len(bridge_rows) > 1 or len(native_rows) > 1:
            joins.append({"status": "ambiguous", "reason": "duplicate_join_rows", "identity": key})
        elif not bridge_rows or not native_rows:
            joins.append({"status": "unbound", "reason": "missing_join_side", "identity": key})
        elif bridge_rows[0].get("forwarded_payload_sha256") != native_rows[0].get("forwarded_payload_sha256"):
            joins.append({"status": "invalid", "reason": "payload_fingerprint_mismatch", "identity": key})
        else:
            joins.append({"status": "bound", "scope": "native_edge_binding", "identity": key})

    statuses = [str(item["status"]) for item in joins if item["status"] != "not_applicable"] + [
        str(item["status"]) for item in issues
    ]
    if "invalid" in statuses:
        status = "invalid"
    elif "ambiguous" in statuses:
        status = "ambiguous"
    elif not statuses:
        status = "not_applicable" if joins else "unbound"
    elif "unbound" in statuses:
        status = "unbound"
    else:
        status = "bound"
    return {
        "schema": CAPTURE_SCHEMA,
        "scope": "native_edge_binding",
        "status": status,
        "joins": joins,
        "issues": issues,
    }


__all__ = ["join_binding_records", "valid_existing_records"]

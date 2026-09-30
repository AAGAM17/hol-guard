"""Opt-in, private evidence for binding Codex hook input to a Rust receipt.

This module is deliberately independent from normal activity evidence.  It is
enabled only by a short-lived marker under the managed Guard home and never
authenticates hook ingress or participates in a hook decision.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import time
from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Final, cast

try:  # pragma: no cover - Windows diagnostic capture fails closed.
    import fcntl
except ImportError:  # pragma: no cover - Windows has no flock.
    fcntl = None  # type: ignore[assignment]

from .codex_hook_manifest import MANAGED_CODEX_HOOK_EVENTS
from .native_decision_receipt import validate_native_decision_receipt

CAPTURE_SCHEMA: Final = "guard-codex-binding-capture.v1"
CAPTURE_DIRECTORY_NAME: Final = "diagnostics"
CAPTURE_MARKER_NAME: Final = "codex-binding-capture.v1.json"
CAPTURE_OUTPUT_PREFIX: Final = "codex-binding-capture."
CAPTURE_OUTPUT_SUFFIX: Final = ".jsonl"
MAX_CANONICAL_PAYLOAD_BYTES: Final = 64 * 1024
MAX_CAPTURE_RECORDS: Final = 128
MAX_CAPTURE_BYTES: Final = 64 * 1024
MAX_MARKER_BYTES: Final = 4 * 1024
MAX_RUN_ID_BYTES: Final = 64
MAX_TOOL_CALL_ID_BYTES: Final = 256
_MARKER_SCHEMA: Final = CAPTURE_SCHEMA
_PRIVATE_DIRECTORY_MODE: Final = 0o700
_PRIVATE_FILE_MODE: Final = 0o600
_ASCII_OPAQUE = re.compile(r"^[A-Za-z0-9_-]{1,256}$")
_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_RECEIPT_PROJECTION_FIELDS: Final = (
    "schema",
    "version",
    "authority",
    "decision_id",
    "request_id",
    "request_digest",
    "harness",
    "event_name",
    "payload_kind",
    "policy_generation",
    "policy_digest",
    "rule_digest",
    "runtime_identity",
    "decision",
    "model_output_action",
    "policy_action",
    "observed_policy_action",
    "reason_code",
    "workspace_bound",
    "source_ref_external_allowed",
    "reviewed_output_sha256",
    "observe_mode",
    "deadline_budget_ms",
)
_MISSING = object()
_INVALID = object()


@dataclass(frozen=True)
class _CaptureConfig:
    run_id: str
    expires_at: int
    max_records: int
    max_bytes: int


def _strict_object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _json_object(raw: bytes) -> dict[str, object] | None:
    try:
        value = cast(object, json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object_pairs))
    except (UnicodeError, ValueError, json.JSONDecodeError):
        return None
    return cast(dict[str, object], value) if isinstance(value, dict) else None


def _canonical_json(value: object) -> bytes | None:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        return None


def _payload_fingerprint(payload: Mapping[str, object]) -> str | None:
    canonical = _canonical_json(dict(payload))
    if canonical is None or len(canonical) > MAX_CANONICAL_PAYLOAD_BYTES:
        return None
    return hashlib.sha256(canonical).hexdigest()


def _owner_uid() -> int | None:
    getuid = cast(Callable[[], int] | None, getattr(os, "getuid", None))
    if not callable(getuid):
        return None
    try:
        return int(getuid())
    except (OSError, TypeError, ValueError):
        return None


def _private_directory(fd: int) -> bool:
    try:
        metadata = os.fstat(fd)
    except OSError:
        return False
    uid = _owner_uid()
    return (
        uid is not None
        and stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == uid
        and stat.S_IMODE(metadata.st_mode) == _PRIVATE_DIRECTORY_MODE
    )


def _private_regular(fd: int) -> bool:
    try:
        metadata = os.fstat(fd)
    except OSError:
        return False
    uid = _owner_uid()
    return (
        uid is not None
        and stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == uid
        and stat.S_IMODE(metadata.st_mode) == _PRIVATE_FILE_MODE
        and metadata.st_nlink == 1
    )


def _open_guard_home_directory(guard_home: Path) -> int | None:
    supports_dir_fd = cast(set[object], getattr(os, "supports_dir_fd", cast(set[object], set())))
    if (
        fcntl is None
        or not guard_home.is_absolute()
        or ".." in guard_home.parts
        or not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
        or os.open not in supports_dir_fd
    ):
        return None
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(guard_home.anchor, flags)
        for component in guard_home.parts[1:]:
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        if not _private_directory(descriptor):
            os.close(descriptor)
            return None
        return descriptor
    except (OSError, TypeError):
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)
        return None


def _open_diagnostics_directory(guard_home: Path) -> int | None:
    guard_descriptor = _open_guard_home_directory(guard_home)
    if guard_descriptor is None:
        return None
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(CAPTURE_DIRECTORY_NAME, flags, dir_fd=guard_descriptor)
    except (OSError, TypeError):
        return None
    finally:
        with suppress(OSError):
            os.close(guard_descriptor)
    if not _private_directory(descriptor):
        with suppress(OSError):
            os.close(descriptor)
        return None
    return descriptor


def _read_descriptor(descriptor: int, *, maximum: int) -> bytes | None:
    try:
        metadata = os.fstat(descriptor)
        if metadata.st_size < 0 or metadata.st_size > maximum:
            return None
        _ = os.lseek(descriptor, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                return None
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
    except OSError:
        return None


def _load_capture_config(guard_home: Path) -> _CaptureConfig | None:
    directory = _open_diagnostics_directory(guard_home)
    if directory is None:
        return None
    marker: int | None = None
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            marker = os.open(CAPTURE_MARKER_NAME, flags, dir_fd=directory)
        except (OSError, TypeError):
            return None
        if not _private_regular(marker):
            return None
        raw_marker = _read_descriptor(marker, maximum=MAX_MARKER_BYTES)
        if raw_marker is None:
            return None
        payload = _json_object(raw_marker)
        if payload is None or set(payload) != {"schema", "enabled", "run_id", "expires_at", "max_records", "max_bytes"}:
            return None
        if payload.get("schema") != _MARKER_SCHEMA or payload.get("enabled") is not True:
            return None
        run_id = payload.get("run_id")
        expires_at = payload.get("expires_at")
        max_records = payload.get("max_records")
        max_bytes = payload.get("max_bytes")
        if (
            not isinstance(run_id, str)
            or len(run_id) > MAX_RUN_ID_BYTES
            or len(run_id.encode("ascii", errors="ignore")) != len(run_id)
            or _RUN_ID.fullmatch(run_id) is None
            or type(expires_at) is not int
            or type(max_records) is not int
            or type(max_bytes) is not int
            or not 0 < max_records <= MAX_CAPTURE_RECORDS
            or not 0 < max_bytes <= MAX_CAPTURE_BYTES
        ):
            return None
        now = time.time()
        if expires_at <= now or expires_at > now + 3600:
            return None
        return _CaptureConfig(
            run_id=run_id,
            expires_at=expires_at,
            max_records=max_records,
            max_bytes=max_bytes,
        )
    except (OSError, TypeError, ValueError, UnicodeError):
        return None
    finally:
        if marker is not None:
            with suppress(OSError):
                os.close(marker)
        with suppress(OSError):
            os.close(directory)


def _bounded_text(value: object, *, maximum: int) -> str | None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(char) < 0x21 or ord(char) > 0x7E for char in value)
    ):
        return None
    return value


def _tool_call_id(payload: Mapping[str, object]) -> str | object:
    if "tool_call_id" not in payload or payload.get("tool_call_id") is None:
        return _MISSING
    value = payload.get("tool_call_id")
    if (
        not isinstance(value, str)
        or len(value) > MAX_TOOL_CALL_ID_BYTES
        or len(value.encode("ascii", errors="ignore")) != len(value)
        or _ASCII_OPAQUE.fullmatch(value) is None
    ):
        return _INVALID
    return value


def _base_row(
    *, config: _CaptureConfig, route: str, harness: str, event_name: str, payload: Mapping[str, object]
) -> dict[str, object] | None:
    bounded_harness = _bounded_text(harness, maximum=64)
    bounded_event = _bounded_text(event_name, maximum=64)
    if bounded_harness is None or bounded_event not in MANAGED_CODEX_HOOK_EVENTS:
        return None
    identifier = _tool_call_id(payload)
    identifier_state = "missing" if identifier is _MISSING else "unsupported" if identifier is _INVALID else "present"
    row: dict[str, object] = {
        "schema": CAPTURE_SCHEMA,
        "run_id": config.run_id,
        "route": route,
        "harness": bounded_harness,
        "event_name": bounded_event,
        "tool_call_id_state": identifier_state,
    }
    if identifier not in {_MISSING, _INVALID}:
        row["tool_call_id"] = cast(str, identifier)
    return row


def _receipt_projection(receipt: object) -> dict[str, object] | None:
    validated = validate_native_decision_receipt(receipt)
    if validated is None:
        return None
    projection = {key: validated[key] for key in _RECEIPT_PROJECTION_FIELDS}
    extensions = validated.get("command_extensions")
    if extensions is not None:
        projection["command_extensions"] = extensions
    return projection


def _output_name(run_id: str) -> str:
    return f"{CAPTURE_OUTPUT_PREFIX}{run_id}{CAPTURE_OUTPUT_SUFFIX}"


def _valid_existing_records(raw: bytes, *, run_id: str) -> int | None:
    if not raw:
        return 0
    if not raw.endswith(b"\n"):
        return None
    lines = raw.splitlines()
    if not lines or len(lines) > MAX_CAPTURE_RECORDS:
        return None
    for line in lines:
        row = _json_object(line)
        if row is None or row.get("schema") != CAPTURE_SCHEMA or row.get("run_id") != run_id:
            return None
        harness = row.get("harness")
        event_name = row.get("event_name")
        route = row.get("route")
        state = row.get("tool_call_id_state")
        if (
            not isinstance(harness, str)
            or harness != "codex"
            or not isinstance(event_name, str)
            or event_name not in MANAGED_CODEX_HOOK_EVENTS
            or not isinstance(route, str)
            or not isinstance(state, str)
            or state not in {
                "missing",
                "unsupported",
                "present",
            }
        ):
            return None
        expected = {"schema", "run_id", "route", "harness", "event_name", "tool_call_id_state"}
        if state == "present":
            expected.add("tool_call_id")
        if route == "bridge_ingress":
            expected.add("raw_payload_sha256")
        elif route == "native_worker":
            expected.update({"forwarded_payload_sha256", "decision_scope", "receipt"})
        else:
            return None
        if set(row) != expected:
            return None
    return len(lines)


def _append_row(config: _CaptureConfig, *, guard_home: Path, row: Mapping[str, object]) -> bool:
    if fcntl is None or time.time() >= config.expires_at:
        return False
    serialized = _canonical_json(dict(row))
    if serialized is None:
        return False
    serialized += b"\n"
    if len(serialized) > config.max_bytes:
        return False
    directory = _open_diagnostics_directory(guard_home)
    if directory is None:
        return False
    output: int | None = None
    locked = False
    try:
        flags = (
            os.O_RDWR
            | os.O_APPEND
            | os.O_CREAT
            | os.O_NOFOLLOW
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            output = os.open(_output_name(config.run_id), flags, _PRIVATE_FILE_MODE, dir_fd=directory)
        except (OSError, TypeError):
            return False
        if not _private_regular(output):
            return False
        try:
            fcntl.flock(output, fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
        except (BlockingIOError, OSError):
            return False
        metadata = os.fstat(output)
        if metadata.st_size > config.max_bytes:
            return False
        existing = _read_descriptor(output, maximum=config.max_bytes)
        if existing is None:
            return False
        existing_count = _valid_existing_records(existing, run_id=config.run_id)
        if existing_count is None or existing_count >= config.max_records:
            return False
        if len(existing) + len(serialized) > config.max_bytes:
            return False
        _ = os.lseek(output, 0, os.SEEK_END)
        offset = 0
        while offset < len(serialized):
            offset += os.write(output, serialized[offset:])
        return True
    except (OSError, TypeError, ValueError):
        return False
    finally:
        if output is not None:
            if locked:
                with suppress(OSError):
                    fcntl.flock(output, fcntl.LOCK_UN)
            with suppress(OSError):
                os.close(output)
        with suppress(OSError):
            os.close(directory)


def _record_row(*, guard_home: Path, config: _CaptureConfig, row: dict[str, object]) -> bool:
    return _append_row(config, guard_home=guard_home, row=row)


def record_bridge_ingress(*, guard_home: Path, raw_payload: str, event_name: str, harness: str = "codex") -> bool:
    """Record raw ingress identity and fingerprint when a marker enables it."""

    if harness != "codex":
        return False
    config = _load_capture_config(guard_home)
    if config is None:
        return False
    try:
        encoded = raw_payload.encode("utf-8")
    except UnicodeError:
        return False
    payload = _json_object(encoded)
    if payload is None:
        return False
    fingerprint = _payload_fingerprint(payload)
    if fingerprint is None:
        return False
    row = _base_row(config=config, route="bridge_ingress", harness=harness, event_name=event_name, payload=payload)
    if row is None:
        return False
    row["raw_payload_sha256"] = fingerprint
    return _record_row(guard_home=guard_home, config=config, row=row)


def record_native_worker(
    *,
    guard_home: Path,
    payload: Mapping[str, object],
    harness: str,
    event_name: str,
    receipt: object,
) -> bool:
    """Record the actual forwarded payload and validated native-edge receipt.

    The receipt describes the Rust native edge only.  It is not a final host
    approval or execution witness.
    """

    if harness != "codex":
        return False
    config = _load_capture_config(guard_home)
    if config is None:
        return False
    fingerprint = _payload_fingerprint(payload)
    projection = _receipt_projection(receipt)
    if fingerprint is None or projection is None:
        return False
    row = _base_row(config=config, route="native_worker", harness=harness, event_name=event_name, payload=payload)
    if row is None:
        return False
    if projection["event_name"] != event_name or projection["harness"] != harness:
        return False
    row["forwarded_payload_sha256"] = fingerprint
    row["decision_scope"] = "native_edge"
    row["receipt"] = projection
    return _record_row(guard_home=guard_home, config=config, row=row)


def _valid_fingerprint(value: object) -> bool:
    return isinstance(value, str) and _HEX64.fullmatch(value) is not None


def _normalize_record(value: Mapping[str, object]) -> tuple[tuple[str, str, str, str], str] | None:
    if value.get("schema") != CAPTURE_SCHEMA:
        return None
    run_id = value.get("run_id")
    harness = value.get("harness")
    event_name = value.get("event_name")
    route = value.get("route")
    state = value.get("tool_call_id_state")
    if (
        not isinstance(run_id, str)
        or _RUN_ID.fullmatch(run_id) is None
        or not isinstance(harness, str)
        or _bounded_text(harness, maximum=64) is None
        or harness != "codex"
        or not isinstance(event_name, str)
        or _bounded_text(event_name, maximum=64) is None
        or event_name not in MANAGED_CODEX_HOOK_EVENTS
        or not isinstance(route, str)
        or route not in {"bridge_ingress", "native_worker"}
        or not isinstance(state, str)
        or state not in {"missing", "unsupported", "present"}
    ):
        return None
    expected = {"schema", "run_id", "route", "harness", "event_name", "tool_call_id_state"}
    if state == "present":
        expected.add("tool_call_id")
    if route == "bridge_ingress":
        expected.add("raw_payload_sha256")
    else:
        expected.update({"forwarded_payload_sha256", "decision_scope", "receipt"})
    if set(value) != expected:
        return None
    if route == "bridge_ingress":
        if not _valid_fingerprint(value.get("raw_payload_sha256")):
            return None
    else:
        receipt = value.get("receipt")
        typed_receipt = cast(Mapping[str, object], receipt) if isinstance(receipt, Mapping) else None
        if (
            not _valid_fingerprint(value.get("forwarded_payload_sha256"))
            or value.get("decision_scope") != "native_edge"
            or typed_receipt is None
            or _receipt_projection(typed_receipt) != dict(typed_receipt)
        ):
            return None
        if typed_receipt.get("harness") != harness or typed_receipt.get("event_name") != event_name:
            return None
    if state in {"missing", "unsupported"}:
        if "tool_call_id" in value:
            return None
        return None
    identifier = value.get("tool_call_id")
    if _tool_call_id({"tool_call_id": identifier}) is not identifier:
        return None
    return (run_id, harness, event_name, cast(str, identifier)), route


def join_binding_records(records: Iterable[object]) -> dict[str, object]:
    """Join ingress/native rows using only exact structural identity.

    A successful result proves native-edge binding only; callers still need
    final host response and side-effect evidence for an end-to-end claim.
    """

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
            record_state = record.get("tool_call_id_state")
            if isinstance(record_state, str) and record_state in {"missing", "unsupported"}:
                reason = (
                    "missing_tool_call_id"
                    if record_state == "missing"
                    else "unsupported_tool_call_id"
                )
                issues.append({"status": "unbound", "reason": reason})
            else:
                issues.append({"status": "invalid", "reason": "record_shape"})
            continue
        key, route = normalized
        groups[key][route].append(record)
    joins: list[dict[str, object]] = []
    for key, grouped in groups.items():
        bridge_rows = grouped["bridge_ingress"]
        native_rows = grouped["native_worker"]
        if len(bridge_rows) > 1 or len(native_rows) > 1:
            joins.append({"status": "ambiguous", "reason": "duplicate_join_rows", "identity": key})
        elif not bridge_rows or not native_rows:
            joins.append({"status": "unbound", "reason": "missing_join_side", "identity": key})
        else:
            joins.append({"status": "bound", "scope": "native_edge_binding", "identity": key})
    statuses = [str(item["status"]) for item in joins] + [str(item["status"]) for item in issues]
    if "invalid" in statuses:
        status = "invalid"
    elif "ambiguous" in statuses:
        status = "ambiguous"
    elif not statuses or "unbound" in statuses:
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


__all__ = [
    "CAPTURE_MARKER_NAME",
    "CAPTURE_OUTPUT_PREFIX",
    "CAPTURE_OUTPUT_SUFFIX",
    "CAPTURE_SCHEMA",
    "MAX_CANONICAL_PAYLOAD_BYTES",
    "MAX_CAPTURE_BYTES",
    "MAX_CAPTURE_RECORDS",
    "join_binding_records",
    "record_bridge_ingress",
    "record_native_worker",
]

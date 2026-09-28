"""Canonical Cloud projection for immutable local Review outbox events."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from ..continuation_runtime import continuation_offer_payload
from ..continuation_snapshot import (
    CONTINUATION_CAPABILITIES,
    non_resumable_continuation_snapshot,
    validated_continuation_snapshot,
)
from ..review_contracts import (
    GuardReviewContractError,
    GuardReviewOAuthMetadata,
    build_local_review_request_claim,  # pyright: ignore[reportUnknownVariableType]
)
from ..store import GuardStore
from ..store_review_event_outbox_schema import REVIEW_EVENT_SCHEMA_VERSION
from .local_request_snapshots import (
    _cloud_safe_local_request_payload,  # pyright: ignore[reportPrivateUsage]
)
from .native_workspace_review_context import (
    NativeWorkspaceReviewContextProbeState,
    build_native_workspace_review_context,
    native_workspace_review_context_cache_key,
)
from .review_event_delivery import StoredReviewEventError, decode_stored_review_event
from .review_event_display import build_display_command, resolve_display_provenance
from .time_support import parse_utc_timestamp

_EVENT_TYPE_MAP = {
    "pending": "request_created",
    "resolved": "request_resolved",
    "superseded": "request_superseded",
}


def _terminal_projection(
    result: dict[str, object] | None,
) -> tuple[dict[str, object], str, str] | None:
    if result is None:
        return None
    capability = result.get("capability")
    completed_at = result.get("completedAt")
    if (
        not isinstance(capability, str)
        or capability not in CONTINUATION_CAPABILITIES
        or not isinstance(completed_at, str)
        or not completed_at
    ):
        raise StoredReviewEventError(
            "continuation_result_invalid",
            "Stored Review event continuation result is invalid.",
        )
    return result, capability, completed_at


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _strip_expired_replay_capability(claim: dict[str, object]) -> dict[str, object]:
    advertisement = claim.get("exactReviewCapability")
    if not isinstance(advertisement, dict):
        return claim
    expires_at = parse_utc_timestamp(advertisement.get("expiresAt"))
    if expires_at is None or expires_at > datetime.now(timezone.utc):
        return claim
    replay_claim = dict(claim)
    _ = replay_claim.pop("exactReviewCapability", None)
    return replay_claim


def _native_context_for_snapshot(
    store: GuardStore,
    guard_home: Path,
    request_id: str,
    request_snapshot: dict[str, object],
    probe_state: NativeWorkspaceReviewContextProbeState | None,
) -> dict[str, object] | None:
    if probe_state is None:
        return build_native_workspace_review_context(store, guard_home, request_id, request_snapshot)
    cache_key = native_workspace_review_context_cache_key(request_id, request_snapshot)
    if cache_key is not None and cache_key in probe_state.cache:
        return probe_state.cache[cache_key]
    if probe_state.remaining <= 0:
        return None
    probe_state.remaining -= 1
    context = build_native_workspace_review_context(store, guard_home, request_id, request_snapshot)
    if cache_key is not None:
        probe_state.cache[cache_key] = context
    return context


def build_cloud_review_event(
    item: dict[str, object],
    *,
    oauth: GuardReviewOAuthMetadata | None,
    redaction_level: str,
    store: GuardStore,
    event_sequence: int,
    frozen_continuation: dict[str, object] | None = None,
    strip_expired_capability: bool = False,
    native_context_probe_state: NativeWorkspaceReviewContextProbeState | None = None,
) -> dict[str, object] | None:
    request_id = item.get("request_id")
    if not isinstance(request_id, str) or not request_id:
        return None
    stored_status = str(item.get("status") or "pending")
    if stored_status not in _EVENT_TYPE_MAP:
        return None
    native_context: dict[str, object] | None = None
    if oauth is not None and stored_status == "pending":
        guard_home = getattr(store, "guard_home", None)
        if isinstance(guard_home, Path):
            native_context = _native_context_for_snapshot(
                store,
                guard_home,
                request_id,
                item,
                native_context_probe_state,
            )
    claim: dict[str, object] | None = None
    if oauth is not None:
        try:
            claim = build_local_review_request_claim(request_row=item, oauth=oauth, store=store)
        except GuardReviewContractError:
            claim = None
    if strip_expired_capability and native_context is not None and claim is not None:
        claim = _strip_expired_replay_capability(claim)
    display_command, display_summary, raw_command, redacted_command = build_display_command(item, redaction_level)
    request_payload = _cloud_safe_local_request_payload(item, redaction_level=redaction_level)
    continuation = frozen_continuation or continuation_offer_payload(store, request_row=item, now=_now(), headless=True)
    created_at = str(item.get("created_at") or _now())
    last_seen_at = str(item.get("last_seen_at") or created_at)
    event = {
        "localRequestId": request_id,
        "correlationId": continuation["correlationId"],
        "localEventSequence": event_sequence,
        "eventType": _EVENT_TYPE_MAP[stored_status],
        "harnessId": str(item.get("harness") or "guard-review"),
        "requestKind": str(item.get("review_kind") or item.get("harness") or "guard-review"),
        "displayProvenance": resolve_display_provenance(
            has_command_details=bool(request_payload.get("command_text")),
            redaction_level=redaction_level,
        ),
        "displayCommand": display_command,
        "displaySummary": display_summary,
        "rawCommand": raw_command,
        "redactedCommand": redacted_command,
        "reviewClaim": claim,
        "requestPayload": request_payload,
        "continuationCapability": continuation["capability"],
        "continuationHookAttached": continuation["hookAttached"],
        "continuationOpaqueTargetId": continuation["opaqueTargetId"],
        "continuationWaitDeadline": continuation["waitDeadline"],
        "riskCategory": str(item.get("risk_category") or "") or None,
        "policyAction": str(item.get("policy_action") or "") or None,
        "recommendedScope": str(item.get("recommended_scope") or "") or None,
        "localCreatedAt": created_at,
        "localUpdatedAt": str(item.get("updated_at") or last_seen_at),
        "localLastSeenAt": last_seen_at,
        "guardVersion": str(item.get("guard_version") or "") or None,
        "firstSeenGuardVersion": str(item.get("first_seen_guard_version") or "") or None,
        "lastSeenGuardVersion": str(item.get("last_seen_guard_version") or "") or None,
        "localEmittedAt": _now(),
        "sentAt": _now(),
    }
    if native_context is not None:
        request_payload["nativeWorkspaceReview"] = native_context
    return event


def project_cloud_review_event(
    store: GuardStore,
    *,
    outbox_row: dict[str, object],
    delivery_binding: dict[str, str],
    redaction_level: str,
    oauth: GuardReviewOAuthMetadata | None,
    native_context_probe_state: NativeWorkspaceReviewContextProbeState | None = None,
) -> tuple[int, dict[str, object]] | None:
    sequence = outbox_row.get("sequence")
    if not isinstance(sequence, int):
        raise RuntimeError("Review event outbox sequence is invalid.")
    row_binding = {
        key: outbox_row.get(key)
        for key in ("oauth_subject_hash", "workspace_id", "machine_id", "machine_installation_id")
    }
    try:
        if row_binding != delivery_binding:
            raise StoredReviewEventError(
                "delivery_identity_mismatch",
                "Stored Review event identity does not match the active delivery binding.",
            )
        stored_event = decode_stored_review_event(outbox_row)
        terminal_projection = _terminal_projection(stored_event.continuation_result)
        raw_continuation = stored_event.snapshot.get("continuation_snapshot_json")
        if raw_continuation is None:
            continuation = non_resumable_continuation_snapshot(stored_event.snapshot)
        else:
            continuation = validated_continuation_snapshot(raw_continuation)
            if continuation is None:
                raise StoredReviewEventError(
                    "continuation_snapshot_invalid",
                    "Stored Review event continuation snapshot is invalid.",
                )
        event = build_cloud_review_event(
            stored_event.snapshot,
            redaction_level=redaction_level,
            oauth=oauth,
            store=store,
            event_sequence=stored_event.request_sequence,
            frozen_continuation=continuation,
            strip_expired_capability=stored_event.event_type == "review.request.snapshot_requeued",
            native_context_probe_state=native_context_probe_state,
        )
        if event is None:
            raise StoredReviewEventError(
                "payload_snapshot_invalid",
                "Stored Review event snapshot has no local request identifier.",
            )
    except StoredReviewEventError as error:
        _ = store.quarantine_review_event(
            sequence,
            reason=error.reason,
            error=str(error),
            **delivery_binding,
        )
        return None
    event.update(
        {
            "eventId": stored_event.event_id,
            "eventSchemaVersion": REVIEW_EVENT_SCHEMA_VERSION,
            "eventType": stored_event.wire_event_type,
            "eventPayloadJson": stored_event.payload_json,
            "localEventSequence": stored_event.request_sequence,
            "localStreamSequence": stored_event.stream_sequence,
            "payloadHash": stored_event.payload_hash,
        }
    )
    if terminal_projection is not None:
        terminal_result, terminal_capability, terminal_completed_at = terminal_projection
        event["continuationResult"] = terminal_result
        event["continuationCapability"] = terminal_capability
        event["localUpdatedAt"] = terminal_completed_at
    return sequence, event

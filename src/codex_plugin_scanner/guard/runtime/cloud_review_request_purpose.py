"""Canonical Cloud Review purpose bound to frozen original evidence."""

from __future__ import annotations

from collections.abc import Mapping

WIRE_EVENT_SCHEMA_VERSION = 2
CANONICAL_REQUEST_KINDS = (
    "reviewable_pause",
    "immutable_policy_block",
    "watch_only_observation",
)
_TRUE_MARKERS = {True, 1, "1"}
_FALSE_MARKERS = {False, 0, "0"}


def canonical_request_kind(item: Mapping[str, object]) -> str | None:
    """Return the schema-2 purpose, or None when the frozen marker is absent or ambiguous."""

    if "watch_only_observation" not in item and "watchOnlyObservation" not in item:
        return None
    marker = item["watch_only_observation"] if "watch_only_observation" in item else item["watchOnlyObservation"]
    if marker in _TRUE_MARKERS:
        return "watch_only_observation"
    if marker not in _FALSE_MARKERS:
        return None
    policy = str(item.get("policy_action") or item.get("policyAction") or "").lower()
    if policy in {"block", "deny"}:
        return "immutable_policy_block"
    return "reviewable_pause"


def explicit_watch_only(item: Mapping[str, object]) -> bool:
    return canonical_request_kind(item) == "watch_only_observation"

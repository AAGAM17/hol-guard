"""Decide whether one identical resident resend can reconcile consumption.

The strings are the codes the resident client and server emit. ``timed_out``
and ``pool-exhausted`` are not aliases. Python does not receive the resident
call stage, so an omitted stage uses the same certainty as the Cloud Review
classifier: ambiguous codes are an unknown commit and must be reconciled
before another attempt; every other known transport code is pre-commit.
"""

from __future__ import annotations

# Emitted both before a request is written and after flush, or only on the
# response path. A missing response with one of these codes may already have
# consumed the native claim.
AMBIGUOUS_NATIVE_TRANSPORT_CODES = frozenset(
    {
        "native_client_deadline_exceeded",
        "native_client_frame_invalid",
        "native_client_frame_read_failed",
        "native_client_frame_write_failed",
        "native_client_response_too_large",
        "native_client_stream_frame_truncated",
        "native_client_stream_response_too_large",
        "native_client_stream_write_failed",
        "native_client_timed_out",
        "native_frame_timeout_failed",
        "native_frame_write_failed",
        "native_response_too_large",
        "native_runtime_panicked",
    }
)

_SECURITY_NATIVE_CODES = frozenset(
    {
        "native_client_auth_rejected",
        "native_client_peer_identity_failed",
        "native_resident_auth_rejected",
    }
)
_SECURITY_TOKENS = ("signature", "tenant", "revoked", "tamper", "replay", "binding", "mismatch", "grant")


def native_transport_security_rejection(code: str) -> bool:
    return code in _SECURITY_NATIVE_CODES or any(token in code for token in _SECURITY_TOKENS)


def native_transport_reconcile_before_retry(code: str) -> bool:
    """Return whether one identical resend is required before reporting failure."""

    if "stale" in code or native_transport_security_rejection(code):
        return False
    return code in AMBIGUOUS_NATIVE_TRANSPORT_CODES

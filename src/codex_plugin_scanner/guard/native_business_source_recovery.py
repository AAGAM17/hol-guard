"""Explicitly finish an authenticated, SQL-committed source installation.

This never reconstructs lost state or authorizes a different source. Fresh exact
document approval is mandatory; provider credentials and actors are unrelated.
"""

from datetime import datetime, timezone

from . import native_business_source_store as owner
from .native_business_source_anchor_bridge import build_business_source_anchor, verify_business_source_anchor
from .native_business_source_bridge import _consumer, _deadline, _remaining, verify_business_source_record
from .native_business_source_retention import (
    read_retained_business_source_anchor,
    write_retained_business_source_anchor,
)
from .native_command_control_authority_io import hold_command_control_authority_lock, read_private_state
from .native_policy_snapshot_codec import derive_native_policy_verifier_key
from .policy_document import policy_document_digest
from .policy_document_authority import policy_import_approval_binding


def recover_committed_business_source(store, document, *, approval_gate_grant, deadline_monotonic=None):
    """Reopen only an intact closed source whose exact witness already committed."""
    deadline = _deadline(deadline_monotonic)
    status = _consumer(deadline, anchor=True)
    if status.capabilities is None or owner.CURRENT_FENCE_CAPABILITY not in status.capabilities.features:
        raise owner._error("native_business_source_current_fence_unavailable")
    binding = policy_import_approval_binding(document, "replace")

    def require_approval():
        owner._require_approved(
            store, binding, approval_gate_grant, datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        )

    require_approval()
    with hold_command_control_authority_lock(store.guard_home, timeout_seconds=_remaining(deadline)):
        require_approval()
        material = store._policy_integrity_secret_material(create=False)
        if material is None or type(material[0]) is not bytes or len(material[0]) != 32:
            raise owner._error("native_business_source_installation_key_unavailable")
        key = derive_native_policy_verifier_key(material[0])
        record = read_private_state(store.guard_home, owner.SOURCE_FILE_NAME, owner.MAX_RECORD_BYTES)
        marker = read_private_state(store.guard_home, owner.ANCHOR_FILE_NAME, owner.MAX_ANCHOR_BYTES)
        retained = read_retained_business_source_anchor(store)
        if record is None or marker is None or retained is None:
            raise owner._error("native_business_source_recovery_required")
        anchor = verify_business_source_anchor(marker, key, deadline_monotonic=deadline)
        if anchor.phase != "closed":
            raise owner._error("native_business_source_recovery_requires_closed_marker")
        source = verify_business_source_record(
            record, key, deadline_monotonic=deadline, retained_identity_bytes=anchor.retained_identity_bytes
        )
        if (
            source.retained_identity_bytes != anchor.retained_identity_bytes
            or source.source_digest != policy_document_digest(document)
        ):
            raise owner._error("native_business_source_recovery_identity_mismatch")
        committed = build_business_source_anchor(source, key, "committed", deadline_monotonic=deadline)
        # A crash may occur between retained and private committed-marker writes.
        # Accept only either exact authenticated phase of this same source.
        if retained not in (marker, committed.anchor_bytes) or owner._database_witness(store) != owner._witness(
            committed
        ):
            raise owner._error("native_business_source_transaction_not_committed")
        require_approval()
        write_retained_business_source_anchor(store, committed.anchor_bytes)
        owner._write_private(store, owner.ANCHOR_FILE_NAME, committed.anchor_bytes, owner.MAX_ANCHOR_BYTES, deadline)
        return source

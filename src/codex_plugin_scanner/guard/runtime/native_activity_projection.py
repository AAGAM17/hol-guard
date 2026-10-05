"""Project opted-in native policy receipts into the existing cloud event queue.

Hooks do not call this module. Sync discovers durable native receipts, writes
the locked activity payload, and leaves HTTP delivery to the existing event
uploader. A terminal allow or deny stays activity evidence.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Mapping
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol, cast

from ..mdm.contracts import ManagedPolicyState
from ..schemas.guard_event_v1 import GuardEventV1

_ACTIVITY_SCHEMA = "guard-native-cloud-activity.v1"
_RECEIPT_KIND = "native_policy_decision"
_LEDGER = "native_activity_projection_ledger"
_BACKFILL_KEY = "native_activity_backfill_authorization"
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_DISCOVERY_LIMIT = 25
_COLUMNS = (
    "decision_id, harness, event_name, policy_generation, policy_digest, "
    "rule_digest, decision, model_output_action, policy_action, "
    "observed_policy_action, reason_code, observe_mode, recorded_at"
)


class NativeActivityStore(Protocol):
    guard_home: object
    _guard_event_queue_limit: int

    def _connect(self) -> AbstractContextManager[sqlite3.Connection]: ...

    def get_review_event_oauth_binding(self) -> Mapping[str, str] | None: ...

    def get_sync_payload(self, state_key: str) -> object: ...

    def set_sync_payload(
        self,
        state_key: str,
        payload: Mapping[str, object],
        now: str,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class NativeActivityEligibility:
    sync_enabled: bool
    workspace_id: str
    installation_id: str
    reason: str


@dataclass(frozen=True, slots=True)
class NativeActivityProjection:
    eligibility: NativeActivityEligibility
    projected: int
    dropped: int
    withheld: int
    quarantined: int


def resolve_native_activity_eligibility(
    binding: Mapping[str, str] | None,
    *,
    sync_enabled: bool,
) -> NativeActivityEligibility:
    """Data-sync consent is the profile, sync setting, and installation binding."""

    if binding is None:
        return NativeActivityEligibility(False, "", "", "no_profile")
    workspace_id = str(binding.get("workspace_id", "")).strip().lower()
    installation_id = str(binding.get("machine_installation_id", "")).strip().lower()
    if _UUID.fullmatch(workspace_id) is None or _UUID.fullmatch(installation_id) is None:
        return NativeActivityEligibility(False, workspace_id, installation_id, "binding_invalid")
    if not sync_enabled:
        return NativeActivityEligibility(False, workspace_id, installation_id, "sync_disabled")
    return NativeActivityEligibility(True, workspace_id, installation_id, "eligible")


def eligibility_from_store(
    store: NativeActivityStore,
    *,
    managed_policy_state: ManagedPolicyState | None = None,
) -> NativeActivityEligibility:
    from pathlib import Path

    from ..config import load_guard_config

    binding = store.get_review_event_oauth_binding()
    home = store.guard_home if isinstance(store.guard_home, Path) else Path(str(store.guard_home))
    config = load_guard_config(
        home,
        create_home=False,
        managed_policy_state=managed_policy_state,
    )
    return resolve_native_activity_eligibility(binding, sync_enabled=bool(config.sync))


def native_activity_coverage(store: NativeActivityStore) -> dict[str, object]:
    """A lost, dropped, withheld, or unaccepted observation is not complete history."""

    with store._connect() as connection:
        _ensure_ledger(connection)
        counts = {
            str(row["state"]): int(row["count"])
            for row in connection.execute(
                f"select state, count(*) as count from {_LEDGER} group by state"
            )
        }
        uploaded = connection.execute(
            f"""
            select count(*) as count
            from {_LEDGER} as ledger
            join guard_cloud_events as event
              on event.idempotency_key = ledger.idempotency_key
            where ledger.state = 'projected' and event.uploaded_at is not null
            """
        ).fetchone()
        unprojected = _unledgered_receipts(connection)
    projected = counts.get("projected", 0)
    dropped = counts.get("dropped", 0)
    withheld = counts.get("withheld", 0)
    quarantined = counts.get("quarantined", 0)
    accepted = int(uploaded["count"]) if uploaded is not None else 0
    complete = (
        dropped == 0
        and withheld == 0
        and quarantined == 0
        and unprojected == 0
        and accepted == projected
    )
    return {
        "accepted": accepted,
        "complete": complete,
        "dropped": dropped,
        "projected": projected,
        "quarantined": quarantined,
        "unprojected": unprojected,
        "withheld": withheld,
    }


def project_native_policy_activity(
    store: NativeActivityStore,
    *,
    eligibility: NativeActivityEligibility | None = None,
    limit: int = _DISCOVERY_LIMIT,
    managed_policy_state: ManagedPolicyState | None = None,
    now: str | None = None,
) -> NativeActivityProjection:
    """Queue bounded native activity for the current opt-in cohort."""

    resolved = eligibility or eligibility_from_store(store, managed_policy_state=managed_policy_state)
    recorded_now = now or datetime.now(timezone.utc).isoformat()
    if not resolved.sync_enabled:
        return NativeActivityProjection(resolved, 0, 0, 0, 0)
    floor = _capture_watermark(store, resolved, recorded_now)
    backfill_remaining = _backfill_remaining(store, resolved)
    projected = dropped = withheld = 0
    with store._connect() as connection:
        _ensure_ledger(connection)
        if not _native_tables_ready(connection):
            return NativeActivityProjection(resolved, 0, 0, 0, 0)
        quarantined = _quarantine_other_bindings(connection, resolved, recorded_now)
        rows = [(source_kind, _copy_row(row)) for source_kind, row in _discover(connection, limit)]
    for source_kind, row in rows:
        outcome = _project_row(
            store,
            source_kind=source_kind,
            row=row,
            eligibility=resolved,
            floor=floor,
            backfill_remaining=backfill_remaining,
            now=recorded_now,
        )
        if outcome == "backfilled":
            backfill_remaining -= 1
            projected += 1
        elif outcome == "projected":
            projected += 1
        elif outcome == "dropped":
            dropped += 1
        elif outcome == "withheld":
            withheld += 1
    if projected and backfill_remaining < _backfill_remaining(store, resolved):
        _reduce_backfill(
            store,
            resolved,
            used=_backfill_remaining(store, resolved) - backfill_remaining,
            now=recorded_now,
        )
    return NativeActivityProjection(resolved, projected, dropped, withheld, quarantined)


def sendable_guard_cloud_events(
    store: NativeActivityStore,
    events: list[dict[str, object]],
    *,
    eligibility: NativeActivityEligibility | None,
) -> list[dict[str, object]]:
    """Hold native activity that is no longer eligible. Leave every other event alone."""

    keys = _sendable_keys(store, eligibility)
    ready: list[dict[str, object]] = []
    for event in events:
        if not _is_native_activity_event(event):
            ready.append(event)
            continue
        key = event.get("idempotency_key")
        if isinstance(key, str) and key in keys:
            ready.append(event)
    return ready


def _project_row(
    store: NativeActivityStore,
    *,
    source_kind: str,
    row: Mapping[str, object],
    eligibility: NativeActivityEligibility,
    floor: str,
    backfill_remaining: int,
    now: str,
) -> str:
    recorded_at = str(row["recorded_at"])
    in_cohort = _at_or_after(recorded_at, floor)
    if not in_cohort and backfill_remaining <= 0:
        stored = _commit(
            store,
            source_kind=source_kind,
            row=row,
            eligibility=eligibility,
            state="withheld",
            event=None,
            now=now,
        )
        return "withheld" if stored == "withheld" else "duplicate"
    event = _activity_event(source_kind, row, eligibility)
    stored = _commit(
        store,
        source_kind=source_kind,
        row=row,
        eligibility=eligibility,
        state="projected",
        event=event,
        now=now,
    )
    if stored == "dropped":
        return "dropped"
    if stored != "projected":
        return "duplicate"
    if not in_cohort:
        return "backfilled"
    return "projected"


def _copy_row(row: sqlite3.Row) -> dict[str, object]:
    names = row.keys()
    return {str(name): row[name] for name in names}


def _activity_event(
    source_kind: str,
    row: Mapping[str, object],
    eligibility: NativeActivityEligibility,
) -> GuardEventV1:
    decision_id = str(row["decision_id"])
    observed = row["observe_mode"] in (1, True)
    activity: dict[str, object] = {
        "activitySchema": _ACTIVITY_SCHEMA,
        "decision": "observed" if observed else str(row["decision"]),
        "decisionId": decision_id,
        "eventName": str(row["event_name"]),
        "harnessId": str(row["harness"]),
        "observedAt": str(row["recorded_at"]),
        "observeMode": "1" if observed else "0",
        "policyGeneration": str(row["policy_generation"]),
        "reasonCode": str(row["reason_code"]),
        "sourceKind": source_kind,
    }
    for column, field in (
        ("model_output_action", "modelOutputAction"),
        ("policy_action", "policyAction"),
        ("observed_policy_action", "observedPolicyAction"),
        ("policy_digest", "policyDigest"),
        ("rule_digest", "ruleDigest"),
    ):
        value = row[column]
        if isinstance(value, str) and value.strip():
            activity[field] = value.strip()
    key = (
        f"native-activity:{eligibility.workspace_id}:{eligibility.installation_id}:"
        f"{source_kind}:{decision_id}"
    )
    return GuardEventV1(
        event_id=f"guard-event-{hashlib.sha256(key.encode('utf-8')).hexdigest()[:32]}",
        idempotency_key=key,
        event_type="receipt.created",
        source="edge",
        occurred_at=str(row["recorded_at"]),
        workspace_id=eligibility.workspace_id,
        device_id=eligibility.installation_id,
        payload={
            "receiptKind": _RECEIPT_KIND,
            "installationId": eligibility.installation_id,
            "activity": activity,
        },
    )


def _commit(
    store: NativeActivityStore,
    *,
    source_kind: str,
    row: Mapping[str, object],
    eligibility: NativeActivityEligibility,
    state: str,
    event: GuardEventV1 | None,
    now: str,
) -> str:
    decision_id = str(row["decision_id"])
    key = (
        event.idempotency_key
        if event is not None
        else (
            f"native-activity:{eligibility.workspace_id}:{eligibility.installation_id}:"
            f"{source_kind}:{decision_id}"
        )
    )
    with store._connect() as connection:
        _ensure_ledger(connection)
        existing = connection.execute(
            f"select state from {_LEDGER} where source_kind = ? and decision_id = ?",
            (source_kind, decision_id),
        ).fetchone()
        if existing is not None:
            return str(existing["state"])
        stored_state = state
        if event is not None:
            already = connection.execute(
                "select event_id from guard_cloud_events where idempotency_key = ?",
                (key,),
            ).fetchone()
            if already is None:
                pending = connection.execute(
                    "select count(*) as count from guard_cloud_events where uploaded_at is null"
                ).fetchone()
                pending_count = int(pending["count"]) if pending is not None else 0
                if pending_count >= store._guard_event_queue_limit:
                    stored_state = "dropped"
                else:
                    payload = event.to_dict()
                    connection.execute(
                        """
                        insert or ignore into guard_cloud_events (
                          event_id, idempotency_key, event_type, payload_json, occurred_at, uploaded_at
                        ) values (?, ?, ?, ?, ?, null)
                        """,
                        (
                            event.event_id,
                            event.idempotency_key,
                            event.event_type,
                            json.dumps(payload, sort_keys=True),
                            event.occurred_at,
                        ),
                    )
        connection.execute(
            f"""
            insert into {_LEDGER} (
              source_kind, decision_id, workspace_id, installation_id,
              idempotency_key, state, recorded_at, updated_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                source_kind,
                decision_id,
                eligibility.workspace_id,
                eligibility.installation_id,
                key,
                stored_state,
                str(row["recorded_at"]),
                now,
            ),
        )
        return stored_state


def _ensure_ledger(connection: sqlite3.Connection) -> None:
    connection.execute(
        f"""
        create table if not exists {_LEDGER} (
          source_kind text not null check (source_kind in ('hook', 'prompt')),
          decision_id text not null check (length(decision_id) = 64),
          workspace_id text not null,
          installation_id text not null,
          idempotency_key text not null unique,
          state text not null check (state in ('projected', 'dropped', 'withheld', 'quarantined')),
          recorded_at text not null,
          updated_at text not null,
          primary key (source_kind, decision_id)
        )
        """
    )


def _native_tables_ready(connection: sqlite3.Connection) -> bool:
    rows = connection.execute(
        """
        select name from sqlite_master
        where type = 'table'
          and name in ('native_hook_decision_receipts', 'native_prompt_decision_receipts')
        """
    ).fetchall()
    return len(rows) == 2


def _discover(connection: sqlite3.Connection, limit: int) -> list[tuple[str, sqlite3.Row]]:
    discovered: list[tuple[str, sqlite3.Row]] = []
    for source_kind, table in (
        ("hook", "native_hook_decision_receipts"),
        ("prompt", "native_prompt_decision_receipts"),
    ):
        rows = connection.execute(
            f"""
            select {_COLUMNS}
            from {table} as receipt
            where not exists (
              select 1 from {_LEDGER} as ledger
              where ledger.source_kind = ? and ledger.decision_id = receipt.decision_id
            )
            order by receipt.recorded_at asc, receipt.decision_id asc
            limit ?
            """,
            (source_kind, limit),
        ).fetchall()
        discovered.extend((source_kind, row) for row in rows)
    discovered.sort(key=lambda item: (str(item[1]["recorded_at"]), str(item[1]["decision_id"])))
    return discovered[:limit]


def _quarantine_other_bindings(
    connection: sqlite3.Connection,
    eligibility: NativeActivityEligibility,
    now: str,
) -> int:
    cursor = connection.execute(
        f"""
        update {_LEDGER}
        set state = 'quarantined', updated_at = ?
        where state = 'projected'
          and (workspace_id != ? or installation_id != ?)
        """,
        (now, eligibility.workspace_id, eligibility.installation_id),
    )
    return int(cursor.rowcount or 0)


def _capture_watermark(
    store: NativeActivityStore,
    eligibility: NativeActivityEligibility,
    now: str,
) -> str:
    key = _watermark_key(eligibility)
    current = store.get_sync_payload(key)
    if isinstance(current, dict):
        floor = current.get("recordedAtFloor")
        if (
            isinstance(floor, str)
            and current.get("workspaceId") == eligibility.workspace_id
            and current.get("installationId") == eligibility.installation_id
        ):
            return floor
    store.set_sync_payload(
        key,
        {
            "installationId": eligibility.installation_id,
            "recordedAtFloor": now,
            "workspaceId": eligibility.workspace_id,
        },
        now,
    )
    return now


def _watermark_key(eligibility: NativeActivityEligibility) -> str:
    return f"native_activity_opt_in_watermark:{eligibility.workspace_id}:{eligibility.installation_id}"


def _reduce_backfill(
    store: NativeActivityStore,
    eligibility: NativeActivityEligibility,
    *,
    used: int,
    now: str,
) -> None:
    payload = store.get_sync_payload(_BACKFILL_KEY)
    if not isinstance(payload, dict) or used <= 0:
        return
    updated = dict(payload)
    raw_limit = updated.get("limit")
    if isinstance(raw_limit, bool) or not isinstance(raw_limit, int):
        return
    updated["limit"] = max(0, raw_limit - used)
    updated["workspaceId"] = eligibility.workspace_id
    updated["installationId"] = eligibility.installation_id
    store.set_sync_payload(_BACKFILL_KEY, updated, now)


def _backfill_remaining(store: NativeActivityStore, eligibility: NativeActivityEligibility) -> int:
    payload = store.get_sync_payload(_BACKFILL_KEY)
    if not isinstance(payload, dict):
        return 0
    if payload.get("workspaceId") != eligibility.workspace_id:
        return 0
    if payload.get("installationId") != eligibility.installation_id:
        return 0
    raw_limit = payload.get("limit")
    if isinstance(raw_limit, bool) or not isinstance(raw_limit, int):
        return 0
    return raw_limit if 0 < raw_limit <= 50 else 0


def _unledgered_receipts(connection: sqlite3.Connection) -> int:
    if not _native_tables_ready(connection):
        return 0
    pending = 0
    for source_kind, table in (
        ("hook", "native_hook_decision_receipts"),
        ("prompt", "native_prompt_decision_receipts"),
    ):
        row = connection.execute(
            f"""
            select count(*) as count from {table} as receipt
            where not exists (
              select 1 from {_LEDGER} as ledger
              where ledger.source_kind = ? and ledger.decision_id = receipt.decision_id
            )
            """,
            (source_kind,),
        ).fetchone()
        pending += int(row["count"]) if row is not None else 0
    return pending


def _sendable_keys(
    store: NativeActivityStore,
    eligibility: NativeActivityEligibility | None,
) -> set[str]:
    if eligibility is None or not eligibility.sync_enabled:
        return set()
    with store._connect() as connection:
        _ensure_ledger(connection)
        rows = connection.execute(
            f"""
            select idempotency_key from {_LEDGER}
            where state = 'projected' and workspace_id = ? and installation_id = ?
            """,
            (eligibility.workspace_id, eligibility.installation_id),
        ).fetchall()
    return {str(row["idempotency_key"]) for row in rows}


def _is_native_activity_event(event: Mapping[str, object]) -> bool:
    body = event.get("payload")
    if not isinstance(body, dict):
        return False
    payload = cast(dict[str, object], body)
    inner = payload.get("payload")
    candidate = inner if isinstance(inner, dict) else payload
    return candidate.get("receiptKind") == _RECEIPT_KIND


def _at_or_after(recorded_at: str, floor: str) -> bool:
    recorded = _parse_time(recorded_at)
    start = _parse_time(floor)
    if recorded is None or start is None:
        return False
    return recorded >= start


def _parse_time(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)

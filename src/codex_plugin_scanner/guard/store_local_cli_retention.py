"""Forget and age out observed custom extensions that the user never enrolled."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

from .runtime.time_support import parse_utc_timestamp

LOCAL_CLI_OBSERVATION_RETENTION_DAYS = 30
LOCAL_CLI_PRUNE_INTERVAL = timedelta(days=1)

# Inventory rows and the digests derived from them. User grants
# (local_cli_grant, local_cli_command_grant, local_mcp_provider_grant) are
# never touched here.
_OBSERVATION_TABLES = (
    "local_cli_command",
    "local_mcp_catalog",
    "local_mcp_tool_authority",
    "local_mcp_provider_action",
    "local_mcp_provider_authority",
    "local_mcp_workflow_proposal",
    "local_cli_observation",
)

# An observation can be forgotten only when nothing enrolled depends on it.
# MCP connections that share a server with an enrolled record stay: their
# presence keeps a legacy server-wide grant from covering a different
# configured connection (see the native local MCP grant op). A legacy
# server-wide row may store the server hash only as its identity_hash, so both columns count.
_ENROLLED_MCP_SERVERS = """
    select coalesce(enrolled.server_identity_hash, enrolled.identity_hash)
    from local_cli_observation enrolled
    join local_cli_grant grant_row on grant_row.cli_id = enrolled.cli_id
    where enrolled.surface = 'mcp'
"""
_FORGETTABLE_PREDICATE = f"""
    observation.cli_id not in (select cli_id from local_cli_grant)
    and not (
        observation.surface = 'mcp'
        and observation.server_identity_hash is not null
        and observation.server_identity_hash in ({_ENROLLED_MCP_SERVERS})
    )
"""


class LocalCliForgetError(ValueError):
    """Raised when an observed record cannot be forgotten."""


class LocalCliReplaySkippedError(Exception):
    """Raised when a history entry may not restore a forgotten or expired identity."""


class StoreLocalCliRetentionMixin:
    if TYPE_CHECKING:

        def _native_store_call(
            self, method: str, args: Mapping[str, object], *, busy_timeout_seconds: float | None = None
        ) -> Any: ...

    def forget_local_cli_observation(self, cli_id: str, *, identity_hash: str) -> None:
        """Delete one un-enrolled observed record and its inventory rows.

        History replay skips the identity until it runs or is configured again.
        """

        try:
            _ = self._native_store_call(
                "forget_local_cli_observation",
                {"cli_id": cli_id, "identity_hash": identity_hash, "clock": utc_now_iso()},
            )
        except ValueError as error:
            raise LocalCliForgetError(str(error)) from None

    def local_cli_replay_allowed(self, identity_hash: str, seen_at: str, *, now: str | None = None) -> bool:
        """Return whether a history entry may restore or refresh this identity."""

        return bool(
            self._native_store_call(
                "local_cli_replay_allowed",
                {"identity_hash": identity_hash, "seen_at": seen_at, "now": now, "clock": utc_now_iso()},
            )
        )

    def prune_inactive_local_cli_observations(
        self,
        *,
        now: datetime | None = None,
        retention_days: int = LOCAL_CLI_OBSERVATION_RETENTION_DAYS,
        throttle: bool = False,
    ) -> list[str]:
        """Delete un-enrolled observed records not seen within the retention window."""

        pruned = self._native_store_call(
            "prune_inactive_local_cli_observations",
            {
                "now": None if now is None else now.isoformat(),
                "retention_days": retention_days,
                "throttle": throttle,
                "clock": utc_now_iso(),
            },
        )
        return [str(cli_id) for cli_id in pruned]


def prune_expired_local_cli_observations(
    connection: sqlite3.Connection,
    *,
    now: datetime | str | None = None,
    retention_days: int = LOCAL_CLI_OBSERVATION_RETENTION_DAYS,
    throttle: bool = False,
) -> list[str]:
    """Delete expired un-enrolled observations inside the caller's transaction.

    The local MCP observation writers still prune here; the store methods above
    run the same rules in the resident's ``guard_store_local_cli`` op.

    With ``throttle`` the scan runs at most once per ``LOCAL_CLI_PRUNE_INTERVAL``
    so frequent observation writes do not rescan the whole list.
    """

    current = (parse_utc_timestamp(now) if isinstance(now, str) else now) or datetime.now(timezone.utc)
    _ensure_retention_tables(connection)
    if throttle:
        row = connection.execute("select last_pruned_at from local_cli_retention_state where singleton = 1").fetchone()
        last = parse_utc_timestamp(row[0]) if row is not None else None
        if last is not None and current < last + LOCAL_CLI_PRUNE_INTERVAL:
            return []
        _ = connection.execute(
            "insert into local_cli_retention_state (singleton, last_pruned_at) values (1, ?) "
            "on conflict(singleton) do update set last_pruned_at = excluded.last_pruned_at",
            (current.isoformat(),),
        )
    cutoff = current - timedelta(days=retention_days)
    rows = connection.execute(
        "select observation.cli_id, observation.identity_hash, observation.last_seen_at "
        f"from local_cli_observation observation where {_FORGETTABLE_PREDICATE}"
    ).fetchall()
    expired = tuple(
        (str(cli_id), str(identity_hash))
        for cli_id, identity_hash, last_seen_at in rows
        if _seen_before(last_seen_at, cutoff)
    )
    if expired:
        # Expiry is not a Forget: recent history may still restore the record.
        _delete_observations(connection, expired)
    return [cli_id for cli_id, _identity_hash in expired]


def replay_allowed(
    connection: sqlite3.Connection,
    identity_hash: str,
    seen_at: str,
    *,
    now: str | None = None,
) -> bool:
    """Return whether a history entry seen at ``seen_at`` may restore this identity.

    A listed identity may always be refreshed. Otherwise entries older than
    the retention window before ``now`` (the replaying discovery's time), or
    no later than when the user forgot the identity, are skipped.
    """

    listed = connection.execute(
        "select 1 from local_cli_observation where identity_hash = ? limit 1", (identity_hash,)
    ).fetchone()
    if listed is not None:
        return True
    seen = parse_utc_timestamp(seen_at)
    current = parse_utc_timestamp(now) or datetime.now(timezone.utc)
    cutoff = current - timedelta(days=LOCAL_CLI_OBSERVATION_RETENTION_DAYS)
    if seen is not None and seen < cutoff:
        return False
    return not _forgotten_since(connection, identity_hash, seen)


def _forgotten_since(connection: sqlite3.Connection, identity_hash: str, seen: datetime | None) -> bool:
    _ensure_retention_tables(connection)
    row = connection.execute(
        "select forgotten_at from local_cli_forgotten where identity_hash = ?", (identity_hash,)
    ).fetchone()
    forgotten = parse_utc_timestamp(row[0]) if row is not None else None
    if forgotten is None:
        return False
    return seen is None or seen <= forgotten


def later_timestamp(current: object, candidate: str) -> str:
    """Return the later of the stored and the replayed timestamp."""

    stored = parse_utc_timestamp(current)
    replayed = parse_utc_timestamp(candidate)
    if isinstance(current, str) and stored is not None and (replayed is None or replayed <= stored):
        return current
    return candidate


def mark_shared_enrolled_servers(items: Iterable[dict[str, object]], enrolled_ids: Mapping[str, object]) -> None:
    """Flag un-enrolled MCP records kept because an enrolled record shares their server."""

    listed = list(items)
    enrolled_servers = {
        item.get("server_identity_hash") or item.get("identity_hash")
        for item in listed
        if item.get("cli_id") in enrolled_ids and item.get("surface") == "mcp"
    }
    enrolled_servers.discard(None)
    for item in listed:
        if (
            item.get("surface") == "mcp"
            and item.get("cli_id") not in enrolled_ids
            and item.get("server_identity_hash") in enrolled_servers
        ):
            item["shares_enrolled_server"] = True


def _ensure_retention_tables(connection: sqlite3.Connection) -> None:
    _ = connection.execute(
        "create table if not exists local_cli_forgotten (identity_hash text primary key, forgotten_at text not null)"
    )
    _ = connection.execute(
        "create table if not exists local_cli_retention_state ("
        "singleton integer primary key check (singleton = 1), last_pruned_at text not null)"
    )


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _seen_before(value: object, cutoff: datetime) -> bool:
    seen = parse_utc_timestamp(value)
    return seen is not None and seen < cutoff


def _delete_observations(connection: sqlite3.Connection, records: tuple[tuple[str, str], ...]) -> None:
    _ensure_retention_tables(connection)
    for table in _OBSERVATION_TABLES:
        connection.executemany(f"delete from {table} where cli_id = ?", [(cli_id,) for cli_id, _ in records])

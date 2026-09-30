"""Operation-scoped connections preserve transaction and recovery boundaries."""

import sqlite3
import threading
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.store import GuardStore


def fixture_store(tmp_path: Path) -> GuardStore:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    with store._connect() as connection:
        connection.execute("create table scope_fixture (value integer)")
    return store


def test_scope_reuses_connection_only_within_one_operation(tmp_path: Path, monkeypatch) -> None:
    store = fixture_store(tmp_path)
    opened = []
    original_connect = sqlite3.connect

    def connect(*args, **kwargs):
        connection = original_connect(*args, **kwargs)
        opened.append(connection)
        return connection

    monkeypatch.setattr(sqlite3, "connect", connect)
    for _ in range(2):
        with store.connection_scope():
            with store._connect() as first:
                first.execute("select count(*) from scope_fixture").fetchone()
            with store.connection_scope(), store._connect() as second:
                assert second is first
                second.execute("select count(*) from scope_fixture").fetchone()
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            first.execute("select 1")
    assert len(opened) == 2


def test_committed_claim_survives_later_scope_failure(tmp_path: Path) -> None:
    store = fixture_store(tmp_path)
    with pytest.raises(RuntimeError, match="later failure"), store.connection_scope():
        with store._connect() as connection:
            connection.execute("insert into scope_fixture values (1)")
        with sqlite3.connect(store.path) as observer:
            assert observer.execute("select value from scope_fixture").fetchall() == [(1,)]
        raise RuntimeError("later failure")
    with store._connect() as connection:
        assert connection.execute("select value from scope_fixture").fetchone()[0] == 1


def test_failed_transaction_rolls_back_before_next_method(tmp_path: Path) -> None:
    store = fixture_store(tmp_path)
    with store.connection_scope():
        with pytest.raises(RuntimeError, match="abort"), store._connect() as connection:
            connection.execute("insert into scope_fixture values (2)")
            raise RuntimeError("abort")
        with store._connect() as connection:
            assert connection.in_transaction is False
            assert connection.execute("select count(*) from scope_fixture").fetchone()[0] == 0


def test_nested_method_cannot_commit_its_callers_pending_writes(tmp_path: Path) -> None:
    store = fixture_store(tmp_path)
    with store.connection_scope():
        with pytest.raises(RuntimeError, match="abort outer"), store._connect() as outer:
            outer.execute("insert into scope_fixture values (4)")
            with store._connect() as inner:
                assert inner is not outer
                assert inner.execute("select count(*) from scope_fixture").fetchone()[0] == 0
            assert outer.in_transaction is True
            raise RuntimeError("abort outer")
        with store._connect() as connection:
            assert connection.execute("select count(*) from scope_fixture").fetchone()[0] == 0


def test_scope_does_not_retain_read_snapshot_across_methods(tmp_path: Path) -> None:
    store = fixture_store(tmp_path)
    with store.connection_scope():
        with store._connect() as connection:
            connection.execute("begin deferred")
            assert connection.execute("select count(*) from scope_fixture").fetchone()[0] == 0
        with sqlite3.connect(store.path) as writer:
            writer.execute("insert into scope_fixture values (3)")
        with store._connect() as connection:
            assert connection.execute("select value from scope_fixture").fetchone()[0] == 3


def test_scopes_are_thread_local(tmp_path: Path) -> None:
    store = fixture_store(tmp_path)
    connections = []
    failures = []

    def read() -> None:
        try:
            with store.connection_scope(), store._connect() as connection:
                connections.append(connection)
                connection.execute("select count(*) from scope_fixture").fetchone()
        except Exception as error:
            failures.append(error)

    with store.connection_scope(), store._connect() as main_connection:
        reader = threading.Thread(target=read)
        reader.start()
        reader.join(timeout=5)
        assert not reader.is_alive()
        assert not failures
        assert connections[0] is not main_connection


def test_nested_different_stores_restore_the_original_scope(tmp_path: Path) -> None:
    first_store = fixture_store(tmp_path / "first")
    second_store = fixture_store(tmp_path / "second")
    with first_store.connection_scope():
        with first_store._connect() as first:
            first.execute("insert into scope_fixture values (1)")
        with second_store.connection_scope(), second_store._connect() as second:
            assert second is not first
            assert second.execute("select count(*) from scope_fixture").fetchone()[0] == 0
        with first_store._connect() as restored:
            assert restored is first
            assert restored.execute("select value from scope_fixture").fetchone()[0] == 1


def test_caught_corruption_still_fails_the_scope_and_reaches_recovery(tmp_path: Path, monkeypatch) -> None:
    store = fixture_store(tmp_path)
    failures = []
    monkeypatch.setattr(store, "_recover_fatal_sqlite_store", lambda error, **kwargs: failures.append(error))
    with pytest.raises(sqlite3.DatabaseError, match="malformed"), store.connection_scope():
        try:
            with store._connect():
                raise sqlite3.DatabaseError("database disk image is malformed")
        except sqlite3.DatabaseError:
            pass
        with pytest.raises(sqlite3.DatabaseError, match="malformed"), store._connect():
            pytest.fail("A failed connection must not be reused")
    assert len(failures) == 1
    with store.connection_scope(), store._connect() as connection:
        assert connection.execute("select count(*) from scope_fixture").fetchone()[0] == 0


def test_scopes_keep_the_storage_gate_until_connection_closes(tmp_path: Path) -> None:
    store = fixture_store(tmp_path)
    with store.connection_scope(), store._try_hold_storage_gate(exclusive=True) as acquired:
        # Same-thread upgrade is rejected rather than replacing a live DB.
        assert acquired is False

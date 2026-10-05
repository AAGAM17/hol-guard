"""Local route projection/pagination tests; native producer tests cover origin."""

import json
import urllib.error
import urllib.request

import pytest

from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.daemon import business_review_queue as route
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_approvals import InvalidApprovalCursorError
from tests.test_guard_daemon_transport_security import _dashboard_token
from tests.test_native_business_review_summary import summary


def values(count):
    return [{**summary(), "request_id": f"opaque-{index:03}"} for index in range(count)]


def test_native_pages_are_bounded_selectable_and_do_not_create_sql_rows(tmp_path, monkeypatch):
    store = GuardStore(guard_home=tmp_path)
    monkeypatch.setattr(route, "read_native_business_review_queue", lambda home: values(5))
    cursor = None
    found = []
    for expected in (2, 2, 1):
        page = route.local_request_page(store, status="pending", limit=2, cursor=cursor,
            harness=None, search=None, include_totals=True)
        assert len(page["items"]) == expected
        assert page["total_count"] == page["total_pending_count"] == 5
        found.extend(item["request_id"] for item in page["items"])
        cursor = page["next_cursor"]
    assert cursor is None
    assert found == [item["request_id"] for item in values(5)]
    assert route.native_request_detail(store, found[0])["native_business_review_display_only"] is True
    assert store.list_approval_requests(status=None) == []
    assert store.get_approval_request(found[0]) is None


def test_native_cursor_expires_on_membership_or_filter_change(tmp_path, monkeypatch):
    store = GuardStore(guard_home=tmp_path)
    current = values(3)
    monkeypatch.setattr(route, "read_native_business_review_queue", lambda home: current)
    options = dict(status="pending", limit=1, harness=None, search=None, include_totals=False)
    cursor = route.local_request_page(store, cursor=None, **options)["next_cursor"]
    with pytest.raises(InvalidApprovalCursorError):
        route.local_request_page(store, cursor=cursor, **{**options, "search": "mail"})
    current.pop()
    with pytest.raises(InvalidApprovalCursorError):
        route.local_request_page(store, cursor=cursor, **options)


def test_native_filter_and_resolved_page_totals(tmp_path, monkeypatch):
    store = GuardStore(guard_home=tmp_path)
    monkeypatch.setattr(route, "read_native_business_review_queue", lambda home: values(2))
    options = dict(limit=1, cursor=None, harness=None, search=None, include_totals=True)
    resolved = route.local_request_page(store, status="resolved", **options)
    assert resolved["items"] == [] and resolved["total_count"] == 0
    assert resolved["total_pending_count"] == 2
    filtered = route.local_request_page(store, status="pending", **{**options, "harness": "codex"})
    assert filtered["items"] == [] and filtered["total_count"] == 0


def test_sql_cursor_phase_is_preserved_before_native_pages(tmp_path, monkeypatch):
    store = GuardStore(guard_home=tmp_path)
    monkeypatch.setattr(route, "read_native_business_review_queue", lambda home: values(2))
    calls = []
    def sql_page(**options):
        calls.append(options["cursor"])
        return {"items": [{"request_id": "sql-1" if options["cursor"] is None else "sql-2"}],
            "next_cursor": "existing-sql-cursor" if options["cursor"] is None else None,
            "total_count": 2, "total_pending_count": 2, "status": "pending"}
    monkeypatch.setattr(store, "list_approval_request_page", sql_page)
    options = dict(status="pending", limit=1, harness=None, search=None, include_totals=True)
    first = route.local_request_page(store, cursor=None, **options)
    assert first["next_cursor"] == "existing-sql-cursor" and first["total_count"] == 4
    second = route.local_request_page(store, cursor=first["next_cursor"], **options)
    assert second["items"] == [{"request_id": "sql-2"}]
    third = route.local_request_page(store, cursor=second["next_cursor"], **options)
    assert third["items"][0]["request_id"] == "opaque-000"
    assert calls == [None, "existing-sql-cursor", None]


def test_native_sql_id_collision_refuses_projection(tmp_path, monkeypatch):
    store = GuardStore(guard_home=tmp_path)
    monkeypatch.setattr(route, "read_native_business_review_queue", lambda home: values(1))
    monkeypatch.setattr(store, "get_approval_request", lambda request_id: {"request_id": request_id})
    with pytest.raises(route.NativeBusinessReviewQueueReadError):
        route.native_request_detail(store, "opaque-000")


def test_real_local_http_routes_expose_only_read_only_projection(tmp_path, monkeypatch):
    store = GuardStore(guard_home=tmp_path)
    calls = []
    def discover(home):
        calls.append(home)
        return values(1)
    monkeypatch.setattr(route, "read_native_business_review_queue", discover)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        base = f"http://127.0.0.1:{daemon.port}"
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(base + "/v1/requests", timeout=5)
        assert error.value.code == 401 and calls == []
        headers = {"X-Guard-Dashboard-Session": _dashboard_token(store)}
        for path in ("/v1/requests", "/v1/requests/opaque-000"):
            request = urllib.request.Request(base + path, headers=headers)
            with urllib.request.urlopen(request, timeout=5) as response:
                assert response.headers["Cache-Control"] == "no-store"
                payload = json.loads(response.read())
                item = payload["items"][0] if path == "/v1/requests" else payload
                assert item["request_id"] == "opaque-000"
                assert item["native_business_review_display_only"] is True
                assert item["allowed_scopes"] == [] and item["created_at"] == ""
        assert store.get_approval_request("opaque-000") is None
        for action in ("approve", "block"):
            request = urllib.request.Request(base + f"/v1/requests/opaque-000/{action}",
                headers={**headers, "Content-Type": "application/json"},
                data=json.dumps({"scope": "once"}).encode(), method="POST")
            with pytest.raises(urllib.error.HTTPError) as rejected:
                urllib.request.urlopen(request, timeout=5)
            assert rejected.value.code == 404
        assert store.get_approval_request("opaque-000") is None
        def failed_discovery(home):
            raise route.NativeBusinessReviewQueueReadError()
        monkeypatch.setattr(route, "read_native_business_review_queue", failed_discovery)
        for path in ("/v1/requests", "/v1/requests/opaque-000"):
            request = urllib.request.Request(base + path, headers=headers)
            with pytest.raises(urllib.error.HTTPError) as rejected:
                urllib.request.urlopen(request, timeout=5)
            assert rejected.value.code == 503
            assert json.loads(rejected.value.read()) == {"error": "native_local_business_queue_read_failed"}
    finally:
        daemon.stop()

from __future__ import annotations

import io
import json
import urllib.request

import pytest

from codex_plugin_scanner.guard.runtime.mcp_registry import search_mcp_registry


class _Response(io.BytesIO):
    status = 200

    class Headers:
        @staticmethod
        def get_content_type():
            return "application/json"

    headers = Headers()


def test_public_registry_search_is_fixed_origin_bounded_and_noninstalling(monkeypatch):
    captured = []
    opener_handlers = []
    fixture = {
        "metadata": {"count": 1},
        "servers": [
            {
                "server": {
                    "name": "io.github.ComposioHQ/composio",
                    "title": "Composio",
                    "version": "1.0.5",
                    "description": "Synthetic listing",
                    "remotes": [{"type": "streamable-http", "url": "https://connect.composio.dev/mcp"}],
                },
                "_meta": {"io.modelcontextprotocol.registry/official": {"status": "active"}},
            }
        ],
    }

    class Opener:
        def open(self, request, data=None, timeout=None):
            captured.append((request.full_url, timeout, request.headers))
            return _Response(json.dumps(fixture).encode())

    def build_opener(*handlers):
        opener_handlers.extend(handlers)
        return Opener()

    monkeypatch.setattr(urllib.request, "build_opener", build_opener)
    result = search_mcp_registry("Composio")
    assert result["count"] == 1 and result["coverage"] == "search-page"
    entry = result["results"][0]
    assert entry["name"] == "io.github.ComposioHQ/composio"
    assert entry["installed"] is False and entry["configured"] is False and entry["verified_package"] is False
    assert captured[0][0].startswith("https://registry.modelcontextprotocol.io/v0.1/servers?")
    assert "search=Composio" in captured[0][0] and captured[0][1] == 5
    assert any(type(handler).__name__ == "RejectRedirects" for handler in opener_handlers)
    for query in ("", "x", "a" * 81, "bad\nheader"):
        with pytest.raises(ValueError, match="invalid_registry_search"):
            search_mcp_registry(query)


def test_registry_does_not_accept_oversize_or_fabricated_metadata(monkeypatch):
    class Opener:
        def __init__(self, payload):
            self.payload = payload

        def open(self, _request, data=None, timeout=None):
            return _Response(self.payload)

    for payload, reason in (
        (b"x" * 512_001, "registry_response_too_large"),
        (json.dumps({"metadata": {}, "servers": [{}]}).encode(), "registry_response_invalid"),
        (b'{"servers":[],"servers":[],"metadata":{}}', "registry_response_invalid"),
    ):
        monkeypatch.setattr(urllib.request, "build_opener", lambda *handlers, raw=payload: Opener(raw))
        with pytest.raises(ValueError, match=reason):
            search_mcp_registry("test")

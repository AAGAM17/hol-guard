"""Reviewed Codex remote MCP setup through the installed host CLI."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from urllib.parse import urlsplit

from .mcp_registry import search_mcp_registry

_NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")


def reviewed_codex_setup_candidate(payload: dict[str, object]) -> dict[str, str]:
    registry_name, version, endpoint, setup_name = (
        payload.get("registry_name"), payload.get("version"), payload.get("endpoint"), payload.get("setup_name"),
    )
    if (
        not isinstance(registry_name, str) or not 1 <= len(registry_name) <= 256
        or not isinstance(version, str) or not 1 <= len(version) <= 80
        or not isinstance(endpoint, str) or len(endpoint) > 2048
        or not isinstance(setup_name, str) or not _NAME.fullmatch(setup_name)
    ):
        raise ValueError("invalid_codex_setup_selection")
    parsed = urlsplit(endpoint)
    if (
        parsed.scheme != "https" or not parsed.hostname or parsed.username
        or parsed.password or parsed.fragment or parsed.query
    ):
        raise ValueError("invalid_codex_setup_endpoint")
    query = registry_name.rsplit("/", 1)[-1]
    search = search_mcp_registry(query)
    results = search.get("results")
    if not isinstance(results, list):
        raise ValueError("registry_setup_listing_changed")
    matching = [entry for entry in results if entry["name"] == registry_name
                and entry["version"] == version and entry["status"] == "active"
                and any(remote["url"] == endpoint and remote["transport"] == "streamable-http"
                        for remote in entry["remote_endpoints"])]
    if len(matching) != 1:
        raise ValueError("registry_setup_listing_changed")
    digest = hashlib.sha256(json.dumps(
        ["codex", registry_name, version, endpoint, setup_name], separators=(",", ":"), ensure_ascii=True,
    ).encode()).hexdigest()
    return {"host": "codex", "registry_name": registry_name, "version": version,
            "endpoint": endpoint, "setup_name": setup_name, "selection_digest": digest,
            "account_binding": "unverified"}


def install_codex_remote_mcp(candidate: dict[str, str]) -> str:
    executable = shutil.which("codex")
    if executable is None:
        raise ValueError("codex_host_unavailable")
    name = candidate["setup_name"]
    try:
        existing = subprocess.run(
            [executable, "mcp", "get", "--json", name], capture_output=True, timeout=8, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("codex_host_unavailable") from error
    if existing.returncode == 0:
        raise ValueError("codex_connection_already_exists")
    # CLI failure for any other reason is not evidence that the name is free.
    missing = f"No MCP server named '{name}' found.".encode()
    if existing.returncode != 1 or missing not in existing.stderr[:1000]:
        raise ValueError("codex_host_unavailable")
    try:
        added = subprocess.run(
            [executable, "mcp", "add", name, "--url", candidate["endpoint"]],
            capture_output=True, timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("codex_setup_outcome_uncertain") from error
    if added.returncode != 0:
        raise ValueError("codex_setup_outcome_uncertain")
    try:
        verified = subprocess.run(
            [executable, "mcp", "get", "--json", name], capture_output=True, timeout=8, check=False,
        )
        response = json.loads(verified.stdout[:32_769]) if len(verified.stdout) <= 32_768 else None
    except (OSError, subprocess.TimeoutExpired, ValueError, UnicodeError) as error:
        raise ValueError("codex_setup_outcome_uncertain") from error
    if not isinstance(response, dict):
        raise ValueError("codex_setup_outcome_uncertain")
    transport = response.get("transport")
    observed_url = response.get("url") or (transport.get("url") if isinstance(transport, dict) else None)
    if verified.returncode != 0 or observed_url != candidate["endpoint"]:
        raise ValueError("codex_setup_outcome_uncertain")
    return name

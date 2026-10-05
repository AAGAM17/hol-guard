"""Mechanical adapter for native MCP child-environment selection."""

from __future__ import annotations

import os

from ..native_context import context_mcp_launch_environment


def _build_scrubbed_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    return context_mcp_launch_environment(os.environ, extra or {})

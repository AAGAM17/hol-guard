"""Read a configured Guard proxy's upstream launch without granting authority."""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from ..models import GuardArtifact

_VALUE_OPTIONS = frozenset(
    {
        "--guard-home",
        "--server-name",
        "--server-id",
        "--source-scope",
        "--config-path",
        "--transport",
        "--command",
        "--home",
        "--workspace",
    }
)
_REQUIRED_OPTIONS = _VALUE_OPTIONS - {"--home", "--workspace"}
_PROXY_HARNESSES = {
    "codex-mcp-proxy": "codex",
    "opencode-mcp-proxy": "opencode",
    "copilot-mcp-proxy": "copilot",
    "cursor-mcp-proxy": "cursor",
}


@dataclass(frozen=True, slots=True)
class ManagedMcpUpstream:
    command: str
    args: tuple[str, ...]
    env: dict[str, str]
    server_id: str


def proxy_argument_tail(args: tuple[str, ...], commands: frozenset[str]) -> tuple[str, tuple[str, ...]] | None:
    if args and args[0] in commands:
        return args[0], args[1:]
    if len(args) >= 2 and args[0] == "guard" and args[1] in commands:
        return args[1], args[2:]
    if len(args) >= 4 and args[:3] == ("-m", "codex_plugin_scanner.cli", "guard") and args[3] in commands:
        return args[3], args[4:]
    return None


def read_managed_mcp_upstream(artifact: GuardArtifact, commands: frozenset[str]) -> ManagedMcpUpstream | None:
    """Accept the generated launch grammar and its exact connection context.

    The claimed server ID must also be checked against the recovered launch
    by the caller. These fields describe inventory, never trusted tool schemas
    or execution permission. Unknown or ambiguous forms remain unavailable.
    """
    if len(artifact.args) > 512:
        return None
    try:
        if sum(len(value.encode("utf-8")) for value in artifact.args) > 262_144:
            return None
    except UnicodeError:
        return None
    selected = proxy_argument_tail(artifact.args, commands)
    if selected is None:
        return None
    proxy, tail = selected
    if proxy in _PROXY_HARNESSES and _PROXY_HARNESSES[proxy] != artifact.harness:
        return None
    options: dict[str, str] = {}
    args: list[str] = []
    env_keys: set[str] = set()
    index = 0
    while index < len(tail):
        key, separator, value = tail[index].partition("=")
        if key not in _VALUE_OPTIONS | {"--arg", "--server-env-key"}:
            return None
        if not separator:
            index += 1
            if index >= len(tail):
                return None
            value = tail[index]
        if "\x00" in value:
            return None
        if key == "--arg":
            args.append(value)
        elif key == "--server-env-key":
            if not value or value != value.strip() or "=" in value or value in env_keys:
                return None
            env_keys.add(value)
        else:
            if key in options or not value:
                return None
            options[key] = value
        index += 1
    if not _REQUIRED_OPTIONS.issubset(options):
        return None
    expected = {
        "--server-name": artifact.name,
        "--source-scope": artifact.source_scope,
        "--config-path": artifact.config_path,
        "--transport": artifact.transport or "stdio",
    }
    if any(options[key] != value for key, value in expected.items()):
        return None
    configured_env = artifact.metadata.get("env", {})
    if not isinstance(configured_env, dict):
        return None
    env: dict[str, str] = {}
    for key in sorted(env_keys):
        value = cast(dict[str, object], configured_env).get(key)
        if not isinstance(value, str):
            return None
        env[key] = value
    return ManagedMcpUpstream(options["--command"], tuple(args), env, options["--server-id"])

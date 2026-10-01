"""Inspect Python hook launch syntax without granting registration ownership."""

from __future__ import annotations

import ast
from collections.abc import Sequence
from pathlib import Path


def has_codex_harness_tokens(tokens: Sequence[str | None]) -> bool:
    return any(
        token == "--harness=codex"
        or (token == "--harness" and index + 1 < len(tokens) and tokens[index + 1] == "codex")
        for index, token in enumerate(tokens)
    )


def _python_hook_payload(tokens: Sequence[str]) -> list[str]:
    payload = list(tokens)
    while payload and payload[0].startswith("-") and payload[0] not in {"-", "--"}:
        option = payload[0]
        if option.startswith("--"):
            # A separate operand consumes two tokens; attached long options
            # already contain their operand and consume only their own token.
            payload = payload[2 if option == "--check-hash-based-pycs" else 1 :]
            continue
        for index, flag in enumerate(option[1:], start=1):
            if flag in {"c", "m"}:
                attached = option[index + 1 :]
                return ["-" + flag, *([attached] if attached else []), *payload[1:]]
            if flag in {"W", "X"}:
                payload = payload[1 if index + 1 < len(option) else 2 :]
                break
        else:
            payload = payload[1:]
    return payload


def _codex_hook_arguments(arguments: Sequence[str | None]) -> bool:
    payload = list(arguments)
    if payload[:1] == ["guard"]:
        payload = payload[1:]
    return payload[:1] == ["hook"] and has_codex_harness_tokens(payload)


def _import_api_keywords(tree: ast.AST) -> dict[str, str]:
    """Identify standard import APIs from their actual imports, including aliases."""
    apis = {"runpy.run_module": "mod_name", "importlib.import_module": "name", "builtins.__import__": "name"}
    calls = {"__import__": "name"}
    shadowed: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            shadowed.add(node.id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.ExceptHandler)) and node.name:
            shadowed.add(node.name)
        if isinstance(node, ast.Import):
            for imported in node.names:
                for api, keyword in apis.items():
                    module, method = api.rsplit(".", 1)
                    if imported.name == module:
                        calls[f"{imported.asname or module}.{method}"] = keyword
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            for imported in node.names:
                keyword = apis.get(f"{node.module}.{imported.name}")
                if keyword is not None:
                    calls[imported.asname or imported.name] = keyword
    return {name: keyword for name, keyword in calls.items() if name.split(".")[0] not in shadowed}


def _imports_guard_cli(tree: ast.AST) -> bool:
    calls = _import_api_keywords(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and any(name.name == "codex_plugin_scanner.cli" for name in node.names):
            return True
        if isinstance(node, ast.ImportFrom) and (
            node.module == "codex_plugin_scanner.cli"
            or (node.module == "codex_plugin_scanner" and any(name.name == "cli" for name in node.names))
        ):
            return True
        # Dynamic imports may name the module positionally or by keyword.
        if isinstance(node, ast.Call):
            name = ast.unparse(node.func) if isinstance(node.func, (ast.Name, ast.Attribute)) else ""
            keyword = calls.get(name)
            module = (
                node.args[0]
                if node.args and not isinstance(node.args[0], ast.Starred)
                else next((item.value for item in node.keywords if item.arg == keyword), None)
            )
            if (
                keyword is not None
                and isinstance(module, ast.Constant)
                and module.value in {"codex_plugin_scanner.cli", "codex_plugin_scanner"}
            ):
                return True
    return False


def _inline_python_codex_hook(script: str, trailing_arguments: Sequence[str]) -> bool:
    """Inspect static imports/argv without executing code or resolving values."""
    try:
        tree = ast.parse(script)
    except (SyntaxError, ValueError, RecursionError):
        return False
    if not _imports_guard_cli(tree):
        return False
    if _codex_hook_arguments(trailing_arguments):
        return True
    for node in ast.walk(tree):
        if not isinstance(node, (ast.List, ast.Tuple)):
            continue
        values = [
            item.value if isinstance(item, ast.Constant) and isinstance(item.value, str) else None for item in node.elts
        ]
        if values[:1] == ["guard"]:
            values = values[1:]
        if values[:1] != ["hook"]:
            continue
        # A dynamic harness operand cannot prove this is an unrelated handler.
        if any(value == "--harness" and values[index + 1 : index + 2] == [None] for index, value in enumerate(values)):
            return True
        if _codex_hook_arguments(values):
            return True
    return False


def python_codex_hook_command(tokens: Sequence[str]) -> bool:
    payload = _python_hook_payload(tokens[1:])
    if payload[:1] == ["--"]:
        return len(payload) > 1 and Path(payload[1]).name == "codex_daemon_hook_bridge.py"
    if payload[:2] == ["-m", "codex_plugin_scanner.cli"] and _codex_hook_arguments(payload[2:]):
        return True
    if payload and Path(payload[0]).name == "codex_daemon_hook_bridge.py":
        return True
    return payload[:1] == ["-c"] and len(payload) > 1 and _inline_python_codex_hook(payload[1], payload[2:])

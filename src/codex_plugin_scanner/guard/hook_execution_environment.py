"""Bounded execution context captured by the outer host hook bridge."""

from __future__ import annotations

import ast
import base64
import hashlib
import importlib.metadata
import json
import os
import shutil
import stat
import sys
from pathlib import Path

HOOK_EXECUTION_ENVIRONMENT_KEY = "guard_execution_environment"
_GUARD_CLI_IDENTITY_SCHEMA = "guard-cli-identity-v1"
_MAX_GUARD_CLI_BYTES = 4 * 1024 * 1024


def _absolute_lexical(value: str | Path) -> Path:
    """Normalize dot segments without resolving the final symlink."""

    return Path(os.path.abspath(os.path.expanduser(os.fspath(value))))


def _stat_fingerprint(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _path_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _guard_cli_distribution_root() -> Path | None:
    """Return the installed Guard package root, never a model-provided path."""

    try:
        distribution = importlib.metadata.distribution("hol-guard")
        entry_point = next(
            (
                item
                for item in distribution.entry_points
                if item.group == "console_scripts" and item.name == "hol-guard"
            ),
            None,
        )
        if entry_point is None or entry_point.value != "codex_plugin_scanner.cli:main":
            return None
        root = Path(str(distribution.locate_file(""))).resolve(strict=True)
        package_file = (root / "codex_plugin_scanner" / "cli.py").resolve(strict=True)
        active_package = (Path(__file__).resolve().parents[1] / "__init__.py").resolve(strict=True)
    except (importlib.metadata.PackageNotFoundError, OSError, RuntimeError):
        return None
    if (
        not root.is_dir()
        or not package_file.is_file()
        or not active_package.is_file()
        or not _path_within(package_file, root)
        or not _path_within(active_package, root)
    ):
        return None
    return root


def _guard_cli_recorded_sha256(path: Path) -> str | None:
    """Return the installed RECORD digest for one console-script target."""

    try:
        distribution = importlib.metadata.distribution("hol-guard")
        target = path.expanduser().resolve(strict=True)
        matches = []
        for entry in distribution.files or ():
            if entry.name.lower() not in {"hol-guard", "hol-guard.exe"}:
                continue
            recorded = Path(str(distribution.locate_file(entry))).resolve(strict=False)
            if recorded == target:
                matches.append(entry)
        if len(matches) != 1:
            return None
        entry = matches[0]
        file_hash = getattr(entry, "hash", None)
        if file_hash is None or getattr(file_hash, "mode", None) != "sha256":
            return None
        value = getattr(file_hash, "value", None)
        if not isinstance(value, str) or not value:
            return None
        metadata = target.stat()
        if getattr(entry, "size", None) != metadata.st_size or metadata.st_size > _MAX_GUARD_CLI_BYTES:
            return None
        digest = hashlib.sha256()
        with target.open("rb") as handle:
            remaining = metadata.st_size
            while remaining:
                chunk = handle.read(min(1024 * 1024, remaining))
                if not chunk:
                    return None
                digest.update(chunk)
                remaining -= len(chunk)
        encoded = base64.urlsafe_b64encode(digest.digest()).decode("ascii").rstrip("=")
        return digest.hexdigest() if encoded == value else None
    except (OSError, RuntimeError, importlib.metadata.PackageNotFoundError):
        return None


def _guard_cli_candidates(cli_interpreter: str | None = None) -> tuple[Path, ...]:
    values: list[Path] = []
    if cli_interpreter is not None:
        try:
            interpreter = _absolute_lexical(cli_interpreter)
        except (OSError, RuntimeError):
            return ()
        values.extend((interpreter.parent / "hol-guard", interpreter.parent / "hol-guard.exe"))
    else:
        argv0 = sys.argv[0] if sys.argv else ""
        if argv0:
            argv_path = Path(argv0)
            if argv_path.name.lower() in {"hol-guard", "hol-guard.exe"}:
                if argv_path.is_absolute() or os.sep in argv0 or (os.altsep and os.altsep in argv0):
                    values.append(argv_path)
                else:
                    located = shutil.which(argv0)
                    if located:
                        values.append(Path(located))
        located = shutil.which("hol-guard", path=os.environ.get("PATH"))
        if located:
            values.append(Path(located))
        try:
            interpreter = _absolute_lexical(sys.executable)
        except (OSError, RuntimeError):
            interpreter = None
        if interpreter is not None:
            values.extend((interpreter.parent / "hol-guard", interpreter.parent / "hol-guard.exe"))
    unique: list[Path] = []
    seen: set[str] = set()
    for value in values:
        try:
            key = str(value.expanduser().absolute())
        except (OSError, RuntimeError):
            continue
        if key not in seen:
            seen.add(key)
            unique.append(value)
    return tuple(unique)


def _python_console_script_matches(
    path: Path,
    package_root: Path,
    cli_interpreter: str,
) -> bool:
    try:
        metadata = path.stat()
        if metadata.st_size > _MAX_GUARD_CLI_BYTES:
            return False
        with path.open("rb") as handle:
            target = handle.read(_MAX_GUARD_CLI_BYTES + 1)
        if len(target) > _MAX_GUARD_CLI_BYTES:
            return False
        first_line, _, remainder = target.partition(b"\n")
        if not first_line.startswith(b"#!"):
            return False
        interpreter = first_line[2:].strip().decode("utf-8")
        if not interpreter or " " in interpreter or "\t" in interpreter:
            return False
        configured_interpreter = _absolute_lexical(cli_interpreter)
        expected_interpreter = configured_interpreter.resolve(strict=True)
        if Path(interpreter).expanduser().resolve(strict=True) != expected_interpreter:
            return False
        configured_parent = configured_interpreter.parent
        expected_parent = configured_parent.resolve(strict=True)
        if path.parent != configured_parent or path.parent.resolve(strict=True) != expected_parent:
            return False
        if len(target) > _MAX_GUARD_CLI_BYTES:
            return False
        text = (first_line + b"\n" + remainder).decode("utf-8")
        tree = ast.parse(text, filename=str(path), mode="exec")
    except (OSError, RuntimeError, UnicodeDecodeError, SyntaxError):
        return False
    if not (package_root / "codex_plugin_scanner" / "cli.py").is_file():
        return False
    imports: set[str] = set()
    main_import = False
    main_guard: ast.If | None = None
    guard_seen = False
    for statement in tree.body:
        if isinstance(statement, ast.Import):
            if guard_seen or len(statement.names) != 1 or statement.names[0].asname is not None:
                return False
            imports.add(statement.names[0].name)
        elif isinstance(statement, ast.ImportFrom):
            if (
                guard_seen
                or statement.level != 0
                or statement.module != "codex_plugin_scanner.cli"
                or len(statement.names) != 1
                or statement.names[0].name != "main"
                or statement.names[0].asname is not None
            ):
                return False
            main_import = True
        elif isinstance(statement, ast.If):
            if main_guard is not None or not _is_main_guard(statement.test):
                return False
            main_guard = statement
            guard_seen = True
        else:
            return False
    if not main_import or main_guard is None or imports - {"sys", "re"}:
        return False
    if "sys" not in imports or main_guard.orelse:
        return False
    body = list(main_guard.body)
    if not body or not _is_sys_exit_main(body.pop()):
        return False
    return all(_is_allowed_argv_normalization(statement) for statement in body)


def _is_main_guard(test: ast.expr) -> bool:
    return (
        isinstance(test, ast.Compare)
        and isinstance(test.left, ast.Name)
        and test.left.id == "__name__"
        and len(test.ops) == 1
        and isinstance(test.ops[0], ast.Eq)
        and len(test.comparators) == 1
        and isinstance(test.comparators[0], ast.Constant)
        and test.comparators[0].value == "__main__"
    )


def _is_sys_argv_zero(value: ast.expr) -> bool:
    return (
        isinstance(value, ast.Subscript)
        and isinstance(value.value, ast.Attribute)
        and isinstance(value.value.value, ast.Name)
        and value.value.value.id == "sys"
        and value.value.attr == "argv"
        and isinstance(value.slice, ast.Constant)
        and value.slice.value == 0
    )


def _is_allowed_argv_normalization(statement: ast.stmt) -> bool:
    if _is_uv_argv_normalization(statement):
        return True
    if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
        return False
    target = statement.targets[0]
    value = statement.value
    if not _is_sys_argv_zero(target) or not isinstance(value, ast.Call):
        return False
    if (
        isinstance(value.func, ast.Attribute)
        and value.func.attr == "removesuffix"
        and isinstance(value.func.value, ast.Subscript)
        and _is_sys_argv_zero(value.func.value)
        and len(value.args) == 1
        and isinstance(value.args[0], ast.Constant)
        and value.args[0].value == ".exe"
        and not value.keywords
    ):
        return True
    return (
        isinstance(value.func, ast.Attribute)
        and isinstance(value.func.value, ast.Name)
        and value.func.value.id == "re"
        and value.func.attr == "sub"
        and len(value.args) == 3
        and isinstance(value.args[0], ast.Constant)
        and value.args[0].value == r"(-script\.pyw|\.exe)?$"
        and isinstance(value.args[1], ast.Constant)
        and value.args[1].value == ""
        and _is_sys_argv_zero(value.args[2])
        and not value.keywords
    )


def _is_uv_argv_normalization(statement: ast.stmt) -> bool:
    if not isinstance(statement, ast.If) or len(statement.body) != 1 or len(statement.orelse) != 1:
        return False
    fallback = statement.orelse[0]
    if not isinstance(fallback, ast.If) or fallback.orelse:
        return False
    return (
        _is_sys_argv_endswith(statement.test, "-script.pyw")
        and _is_sys_argv_slice_assignment(statement.body[0], 11)
        and _is_sys_argv_endswith(fallback.test, ".exe")
        and len(fallback.body) == 1
        and _is_sys_argv_slice_assignment(fallback.body[0], 4)
    )


def _is_sys_argv_endswith(test: ast.expr, suffix: str) -> bool:
    return (
        isinstance(test, ast.Call)
        and isinstance(test.func, ast.Attribute)
        and test.func.attr == "endswith"
        and _is_sys_argv_zero(test.func.value)
        and len(test.args) == 1
        and isinstance(test.args[0], ast.Constant)
        and test.args[0].value == suffix
        and not test.keywords
    )


def _is_sys_argv_slice_assignment(statement: ast.stmt, stop: int) -> bool:
    if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
        return False
    value = statement.value
    if (
        not _is_sys_argv_zero(statement.targets[0])
        or not isinstance(value, ast.Subscript)
        or not _is_sys_argv_zero(value.value)
        or not isinstance(value.slice, ast.Slice)
        or value.slice.lower is not None
        or value.slice.step is not None
        or not isinstance(value.slice.upper, ast.UnaryOp)
        or not isinstance(value.slice.upper.op, ast.USub)
        or not isinstance(value.slice.upper.operand, ast.Constant)
    ):
        return False
    return value.slice.upper.operand.value == stop and not statement.type_comment


def _is_sys_exit_main(statement: ast.stmt) -> bool:
    if not isinstance(statement, ast.Expr) or not isinstance(statement.value, ast.Call):
        return False
    call = statement.value
    return (
        isinstance(call.func, ast.Attribute)
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id == "sys"
        and call.func.attr == "exit"
        and len(call.args) == 1
        and isinstance(call.args[0], ast.Call)
        and isinstance(call.args[0].func, ast.Name)
        and call.args[0].func.id == "main"
        and not call.args[0].args
        and not call.args[0].keywords
        and not call.keywords
    )


def _guard_cli_identity(
    path: Path,
    package_root: Path,
    cli_interpreter: str,
) -> dict[str, object] | None:
    invocation = _absolute_lexical(path)
    try:
        invocation_before = invocation.lstat()
        target = invocation.resolve(strict=True)
        target_before = target.stat()
        link_target = os.readlink(invocation) if stat.S_ISLNK(invocation_before.st_mode) else None
    except (OSError, RuntimeError):
        return None
    if (
        not stat.S_ISLNK(invocation_before.st_mode)
        and not stat.S_ISREG(invocation_before.st_mode)
    ) or not stat.S_ISREG(target_before.st_mode):
        return None
    if os.name != "nt" and not os.access(invocation, os.X_OK):
        return None
    if target_before.st_size > _MAX_GUARD_CLI_BYTES or not _python_console_script_matches(
        target,
        package_root,
        cli_interpreter,
    ):
        return None
    try:
        target_digest = _guard_cli_recorded_sha256(target)
        if target_digest is None:
            return None
        invocation_after = invocation.lstat()
        target_after_path = invocation.resolve(strict=True)
        target_after = target_after_path.stat()
    except (OSError, RuntimeError):
        return None
    if (
        _stat_fingerprint(invocation_before) != _stat_fingerprint(invocation_after)
        or target_after_path != target
        or _stat_fingerprint(target_before) != _stat_fingerprint(target_after)
    ):
        return None
    return {
        "schema": _GUARD_CLI_IDENTITY_SCHEMA,
        "invocation_path": str(invocation),
        "target_path": str(target),
        "target_sha256": target_digest,
        "invocation_link_target": link_target,
    }


def _verified_guard_cli_identity(cli_interpreter: str | None = None) -> dict[str, object] | None:
    package_root = _guard_cli_distribution_root()
    if package_root is None:
        return None
    interpreter = str(_absolute_lexical(cli_interpreter or sys.executable))
    for candidate in _guard_cli_candidates(cli_interpreter):
        identity = _guard_cli_identity(candidate, package_root, interpreter)
        if identity is not None:
            return identity
    return None


def verified_guard_cli_identity(cli_interpreter: str | None = None) -> dict[str, object] | None:
    """Capture the installed Guard CLI identity for an outer hook bridge."""

    return _verified_guard_cli_identity(cli_interpreter)


def collect_hook_execution_environment(*, cli_interpreter: str | None = None) -> dict[str, object]:
    active = {key: value for key, value in os.environ.items() if value}
    context: dict[str, object] = {
        "path": os.environ.get("PATH", ""),
        "home": os.environ.get("HOME"),
        "git_pager_disabled": "GIT_PAGER" in os.environ and os.environ["GIT_PAGER"] in {"", "cat"},
        "pager_disabled": "PAGER" in os.environ and os.environ["PAGER"] in {"", "cat"},
        "environment_names": sorted(active),
        "xdg_config_home": os.environ.get("XDG_CONFIG_HOME"),
        "environment_digest": hashlib.sha256(
            json.dumps(active, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }
    cli_identity = verified_guard_cli_identity(cli_interpreter)
    if cli_identity is not None:
        context["cli_identity"] = cli_identity
    return context


def stamp_hook_input_text(text: str, *, cli_interpreter: str | None = None) -> str:
    try:
        payload = json.loads(text)
    except (ValueError, TypeError):
        return text
    if not isinstance(payload, dict):
        return text
    payload[HOOK_EXECUTION_ENVIRONMENT_KEY] = collect_hook_execution_environment(
        cli_interpreter=cli_interpreter
    )
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":"))

"""Record parity vectors for the pure-text helpers behind the SFRS classifier.

Usage: ``sfrs_intermediate_vectors.py FIXTURE_DIR``. The command corpus is every
shell-looking string found in the recorded entry-point vectors. Each helper is run
by the Python implementation and its output is stored beside its input, so the
Rust port can be checked helper by helper instead of only through the entry
points. This script depends on the Python implementation and is retired with it.
"""

from __future__ import annotations

import gzip
import json
import os
import sys
from pathlib import Path

from codex_plugin_scanner.guard.runtime.secret_file_request_services import (
    local_read_operands,
    read_only_filters,
    request_artifacts,
    shell_quote_tokens,
    shell_tokenization,
)

MAX_TEXTS = 6000
HOST_MARKERS = ("michaelkantor", "runner2-port", "hol-guard/.venv", "/home/runner", "/private/var/folders", "~/.codex")


def _walk(value: object, found: set[str]) -> None:
    if isinstance(value, str):
        if 2 < len(value) < 2000 and " " in value and not any(marker in value for marker in HOST_MARKERS):
            found.add(value)
    elif isinstance(value, dict):
        for item in value.values():
            _walk(item, found)
    elif isinstance(value, list):
        for item in value:
            _walk(item, found)


def _corpus(fixture_dir: Path) -> list[str]:
    found: set[str] = set()
    for path in sorted(fixture_dir.glob("*.json.gz")):
        if path.name.startswith("intermediate_"):
            continue
        document = json.loads(gzip.decompress(path.read_bytes()))
        for vector in document["vectors"]:
            _walk(vector["args"], found)
    return sorted(found)[:MAX_TEXTS]


def _filters(segments: list[list[str]], parts: list[str]) -> dict[str, object]:
    safe = read_only_filters._read_only_lookup_target_is_safe
    filters = read_only_filters
    return {
        "targets": [[safe(part, allow_dirs=False), safe(part, allow_dirs=True)] for part in parts],
        "redirections": [
            [
                filters._read_only_lookup_arg_is_redirection(part),
                list(filters._split_attached_redirection_token(part) or []) or None,
            ]
            for part in parts
        ],
        "segments": [
            [
                filters._read_only_lookup_filter_segment_is_safe(segment[0], segment[1:]),
                filters._read_only_lookup_filter_segment_is_safe(segment[0], segment[1:], require_explicit_rg_no_config=True),
                filters._read_only_lookup_sed_args_are_safe(segment[1:], require_target=True),
                filters._read_only_lookup_head_tail_args_are_safe(segment[1:], require_target=True),
                filters._read_only_lookup_filter_grep_args_are_safe(segment[1:]),
                filters._read_only_lookup_filter_rg_args_are_safe(segment[1:]),
            ]
            for segment in segments
        ],
    }


def _operands(segments: list[list[str]], parts: list[str]) -> dict[str, object]:
    operands = local_read_operands
    return {
        "globs": [operands._search_glob_pattern_is_safe(part, root=None) for part in parts],
        "segments": [
            {
                "tokens": list(operands._shell_segment_file_operand_tokens(segment)),
                "hidden": operands._ripgrep_args_expand_hidden_files(segment[1:]),
                "roles": [
                    [list(role) for role in operands._search_file_operand_roles(name, segment[1:])]
                    for name in ("grep", "rg")
                ],
                "cat": list(operands._cat_file_operand_tokens(segment[1:])),
                "plain": list(operands._plain_file_operand_tokens(segment[1:])),
                "sed": list(operands._sed_file_operand_tokens(segment[1:])),
                "search": [operands.search_operands_are_safe(name, segment[1:], root=None) for name in ("grep", "rg")],
            }
            for segment in segments
        ],
    }


def _quote_tokens(text: str) -> dict[str, object]:
    tokens = shell_quote_tokens.shell_tokens_preserving_quote_context(text)
    segments = shell_quote_tokens.shell_token_segments(tokens)
    return {
        "tokens": [[token.raw, token.plain] for token in tokens],
        "segments": [[[token.raw, token.plain] for token in segment] for segment in segments],
    }


def _record(text: str) -> dict[str, object]:
    parts = shell_tokenization._split_shell_parts(text)
    segments = shell_tokenization._iter_shell_command_segments(parts)
    primaries = [list(shell_tokenization._shell_segment_primary_command(segment)) for segment in segments]
    return {
        "text": text,
        "parts": parts,
        "segments": segments,
        "primaries": primaries,
        "variables": list(request_artifacts._shell_variable_names(text)),
        "docker": [
            [
                shell_tokenization._docker_subcommand_index(segment[1:]),
                shell_tokenization._docker_build_args_are_sensitive(segment[1:]),
                request_artifacts._docker_buildx_subcommand_index(segment[1:]),
                shell_tokenization._docker_subcommand_help_requested(segment[1:]),
            ]
            for segment in segments
        ],
        "names": [request_artifacts._normalized_shell_command_name(part) for part in parts],
        "filters": _filters(segments, parts),
        "operands": _operands(segments, parts),
        "quote": _quote_tokens(text),
    }


def main() -> None:
    fixture_dir = Path(sys.argv[1])
    os.environ.pop("RIPGREP_CONFIG_PATH", None)
    records = [_record(text) for text in _corpus(fixture_dir)]
    document = {"schema": "sfrs-intermediate.v1", "tokens": records}
    out = fixture_dir / "intermediate_tokens.json.gz"
    out.write_bytes(gzip.compress(json.dumps(document, sort_keys=True).encode("utf-8"), mtime=0))
    print(f"{len(records)} records -> {out}")


if __name__ == "__main__":
    main()

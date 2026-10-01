"""Frozen previous Pi extension source header."""

from __future__ import annotations

from .pi_extension_cli_runtime_source import CLI_RUNTIME_HELPERS_SOURCE
from .pi_extension_previous_content_source import CONTENT_REVIEW_HELPERS_SOURCE
from .pi_extension_runtime_ownership import PiExtensionRuntimeOwnership


def build_previous_source_header(
    *,
    cli_wrapper_command_json: str,
    cli_wrapper_args_json: str,
    compatibility_version_json: str,
    config_path_json: str,
    guard_args_json: str,
    guard_home_json: str,
    home_dir_is_default_json: str,
    home_dir_json: str,
    recovery_args_json: str,
    recovery_command_json: str,
    runtime: PiExtensionRuntimeOwnership,
    taskkill_path_json: str,
    guard_cli_hook_timeout_ms: int,
    guard_daemon_hook_timeout_ms: int,
    guard_daemon_recovery_timeout_ms: int,
    guard_daemon_retry_timeout_ms: int,
    guard_hook_content_item_limit: int,
    guard_hook_deadline_reserve_ms: int,
    guard_hook_max_depth: int,
    guard_hook_max_serialized_payload_chars: int,
    guard_hook_object_key_limit: int,
    guard_hook_text_limit_chars: int,
    guard_hook_timeout_ms: int,
) -> str:
    return (
        'import { spawn } from "node:child_process";\n'
        + 'import { createCipheriv, createHash, randomBytes } from "node:crypto";\n'  # pyright: ignore[reportImplicitStringConcatenation]
        'import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";\n'
        'import { tmpdir } from "node:os";\n'
        'import { join } from "node:path";\n'
        'import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";\n'
        "\n"
        f"const GUARD_CLI_WRAPPER_COMMAND = {cli_wrapper_command_json};\n"
        f"const GUARD_CLI_WRAPPER_ARGS = {cli_wrapper_args_json};\n"
        f"const GUARD_CLI_WRAPPER_ACCEPTS_JSON_ARGS = {str(runtime.cli_accepts_json_args).lower()};\n"
        f"const GUARD_DAEMON_RECOVERY_COMMAND = {recovery_command_json};\n"
        f"const GUARD_DAEMON_RECOVERY_ARGS = {recovery_args_json};\n"
        f"const GUARD_DAEMON_RECOVERY_ACCEPTS_FAILURE_KIND = {str(runtime.recovery_accepts_failure_kind).lower()};\n"
        f"const GUARD_TASKKILL_PATH = {taskkill_path_json};\n"
        f"const GUARD_ARGS = {guard_args_json};\n"
        f"const GUARD_HOME = {guard_home_json};\n"
        f"const GUARD_HOME_DIR = {home_dir_json};\n"
        f"const GUARD_HOME_DIR_IS_DEFAULT = {home_dir_is_default_json};\n"
        f"const GUARD_CONFIG_PATH = {config_path_json};\n"
        f"const GUARD_COMPATIBILITY_VERSION = {compatibility_version_json};\n"
        f"const GUARD_TIMEOUT_MS = {guard_hook_timeout_ms};\n"
        f"const GUARD_DEADLINE_RESERVE_MS = {guard_hook_deadline_reserve_ms};\n"
        f"const GUARD_DAEMON_TIMEOUT_MS = {guard_daemon_hook_timeout_ms};\n"
        f"const GUARD_DAEMON_RECOVERY_TIMEOUT_MS = {guard_daemon_recovery_timeout_ms};\n"
        f"const GUARD_DAEMON_RETRY_TIMEOUT_MS = {guard_daemon_retry_timeout_ms};\n"
        f"const GUARD_CLI_TIMEOUT_MS = {guard_cli_hook_timeout_ms};\n"
        f"const GUARD_TEXT_LIMIT_CHARS = {guard_hook_text_limit_chars};\n"
        f"const GUARD_CONTENT_ITEM_LIMIT = {guard_hook_content_item_limit};\n"
        f"const GUARD_OBJECT_KEY_LIMIT = {guard_hook_object_key_limit};\n"
        f"const GUARD_MAX_DEPTH = {guard_hook_max_depth};\n"
        f"const GUARD_MAX_SERIALIZED_PAYLOAD_CHARS = {guard_hook_max_serialized_payload_chars};\n"
        "const GUARD_APPROVAL_RESUME_POLL_INTERVAL_MS = 2_000;\n"
        "const GUARD_APPROVAL_RESUME_FETCH_TIMEOUT_MS = 1_500;\n"
        "const GUARD_APPROVAL_RESUME_MAX_WAIT_MS = 10 * 60 * 1_000;\n"
        "const GUARD_SOURCE_REF_MAX_OUTPUT_CHARS = 5 * 1024 * 1024;\n"
        "const GUARD_SOURCE_REF_ALLOWED_TOOL_NAMES = new Set([\n"
        '  "read", "read_file", "open_file", "view", "view_file", "cat_file", "Read", "View"\n'
        "]);\n"
        "\n"
        "type GuardResponse = {\n"
        '  decision: "allow" | "deny";\n'
        "  reason?: string;\n"
        "  approval_request_id?: string;\n"
        "  approval_url?: string;\n"
        "  approval_center_url?: string;\n"
        "  resume_poll_path?: string;\n"
        '  model_output_action?: "allow_original" | "replace_with_reviewed_excerpt" | "block" | "not_applicable";\n'
        "  reviewed_output_sha256?: string;\n"
        "  reviewed_excerpt?: string;\n"
        "  observed_policy_action?: string;\n"
        "  observed_review_failure?: boolean;\n"
        "  observe_mode?: boolean;\n"
        "  policy_action?: string;\n"
        '  notice?: "none" | "excerpt" | "warning";\n'
        "  reason_code?: string;\n"
        "};\n" + CLI_RUNTIME_HELPERS_SOURCE + CONTENT_REVIEW_HELPERS_SOURCE
    )

"""Frozen previous Pi managed extension source."""

from __future__ import annotations

import json
import os
from pathlib import Path

from ..codex_hook_windows_job import windows_system_executable_path
from ..daemon.manager import GUARD_DAEMON_COMPATIBILITY_VERSION
from .pi_extension_previous_source_body import build_previous_source_body
from .pi_extension_previous_source_header import build_previous_source_header
from .pi_extension_previous_source_tail import build_previous_source_tail
from .pi_extension_runtime_ownership import resolve_pi_extension_runtime_ownership

# Pi terminates extension hooks at roughly 4.5 seconds. Keep Guard's daemon and
# recovery/fallback paths below that host deadline so a fail-safe result returns.
GUARD_HOOK_TIMEOUT_MS = 4_250
GUARD_HOOK_DEADLINE_RESERVE_MS = 250
GUARD_DAEMON_HOOK_TIMEOUT_MS = 3_100
GUARD_DAEMON_RECOVERY_TIMEOUT_MS = 250
GUARD_DAEMON_RETRY_TIMEOUT_MS = 150
GUARD_CLI_HOOK_TIMEOUT_MS = 300
GUARD_HOOK_TEXT_LIMIT_CHARS = 12_000
GUARD_HOOK_CONTENT_ITEM_LIMIT = 24
GUARD_HOOK_OBJECT_KEY_LIMIT = 24
GUARD_HOOK_MAX_DEPTH = 24
GUARD_HOOK_MAX_SERIALIZED_PAYLOAD_CHARS = 24_000


def previous_managed_extension_source(
    *,
    guard_home: Path,
    home_dir: Path,
    settings_path: Path,
    harness: str = "pi",
    display_name: str = "Pi",
) -> str:
    runtime = resolve_pi_extension_runtime_ownership(
        guard_home=guard_home, home_dir=home_dir, harness=harness, package_source=Path(__file__)
    )
    guard_args = list(runtime.guard_args)
    guard_args_json = json.dumps(guard_args)
    guard_home_json = json.dumps(str(guard_home))
    home_dir_json = json.dumps(str(home_dir))
    home_dir_is_default_json = "true" if home_dir.resolve() == Path.home().resolve() else "false"
    config_path_json = json.dumps(str(settings_path))
    compatibility_version_json = json.dumps(GUARD_DAEMON_COMPATIBILITY_VERSION)
    cli_wrapper_command_json = json.dumps(runtime.cli_command)
    cli_wrapper_args_json = json.dumps(runtime.cli_args)
    recovery_command_json = json.dumps(runtime.recovery_command)
    recovery_args_json = json.dumps(runtime.recovery_args)
    try:
        taskkill_path = windows_system_executable_path("taskkill.exe") if os.name == "nt" else None
    except (OSError, ValueError):
        taskkill_path = None
    lifecycle_abort_event_source = (
        '  pi.on("session_stop", () => { invalidateApprovalContinuations(); });\n' if harness == "omp" else ""
    )
    if harness == "omp":
        tool_approval_continuation_source = (
            "      if (!ompInteractiveContext(ctx)) {\n"
            "        return { block: true, reason };\n"
            "      }\n"
            "      const continuation = await runOmpInteractiveContinuation(ctx, async (continuationSignal) => {\n"
            "        const action = await pollApprovalResolution(\n"
            "          requestId,\n"
            "          approvalPollPath(response, requestId),\n"
            "          continuationSignal,\n"
            "          activity,\n"
            "        );\n"
            "        if (action !== 'allow') return { action, response };\n"
            "        if (continuationSignal.aborted || (activity && !continuationIsActive(activity))) {\n"
            "          return { action: 'aborted', response };\n"
            "        }\n"
            "        if (!toolCallStillMatches(event, ctx, GUARD_CONFIG_PATH, snapshot)) {\n"
            "          return { action: 'changed', response };\n"
            "        }\n"
            "        if (continuationSignal.aborted) return { action: 'aborted', response };\n"
            "        const revalidated = await runGuard(snapshot.payload, snapshot.cwd);\n"
            "        if (continuationSignal.aborted || (activity && !continuationIsActive(activity))) {\n"
            "          return { action: 'aborted', response: revalidated };\n"
            "        }\n"
            "        if (!toolCallStillMatches(event, ctx, GUARD_CONFIG_PATH, snapshot)) {\n"
            "          return { action: 'changed', response: revalidated };\n"
            "        }\n"
            "        return {\n"
            "          action: revalidated.decision === 'allow' ? 'allow' : 'block',\n"
            "          response: revalidated,\n"
            "        };\n"
            "      });\n"
            "      if (continuation.kind !== 'completed') {\n"
            "        const continuationReason = continuation.kind === 'unavailable'\n"
            "          ? reason\n"
            "          : approvalContinuationFailureReason(\n"
            "              response,\n"
            "              continuation.kind === 'aborted' ? 'aborted' : 'transport',\n"
            "            );\n"
            '        ctx.ui.notify(continuationReason, "warning");\n'
            "        return { block: true, reason: continuationReason };\n"
            "      }\n"
            "      const continuationResult = continuation.value;\n"
            "      if (continuationResult.action === 'allow') return undefined;\n"
            "      const continuationReason = continuationResult.action === 'changed'\n"
            '        ? "HOL Guard blocked this tool call because its original arguments or '
            'context changed during approval."\n'
            "        : approvalContinuationFailureReason(continuationResult.response, continuationResult.action);\n"
            '      ctx.ui.notify(continuationReason, "warning");\n'
            "      return { block: true, reason: continuationReason };\n"
        )
    else:
        tool_approval_continuation_source = (
            "      const action = await pollApprovalResolution(\n"
            "        requestId,\n"
            "        approvalPollPath(response, requestId),\n"
            "        signal,\n"
            "        activity,\n"
            "      );\n"
            "      if (action !== 'allow') {\n"
            "        const blockedReason = approvalContinuationFailureReason(response, action);\n"
            '        ctx.ui.notify(blockedReason, "warning");\n'
            "        return { block: true, reason: blockedReason };\n"
            "      }\n"
            "      if (!toolCallStillMatches(event, ctx, GUARD_CONFIG_PATH, snapshot)) {\n"
            '        const changedReason = "HOL Guard blocked this tool call because its original arguments or '
            'context changed before approval was consumed.";\n'
            '        ctx.ui.notify(changedReason, "warning");\n'
            "        return { block: true, reason: changedReason };\n"
            "      }\n"
            "      if (signal?.aborted || (activity && !continuationIsActive(activity))) {\n"
            "        const cancelledReason = approvalContinuationFailureReason(response, 'aborted');\n"
            '        ctx.ui.notify(cancelledReason, "warning");\n'
            "        return { block: true, reason: cancelledReason };\n"
            "      }\n"
            "      const revalidated = await runGuard(snapshot.payload, snapshot.cwd);\n"
            "      if (signal?.aborted || (activity && !continuationIsActive(activity))) {\n"
            "        const cancelledReason = approvalContinuationFailureReason(revalidated, 'aborted');\n"
            '        ctx.ui.notify(cancelledReason, "warning");\n'
            "        return { block: true, reason: cancelledReason };\n"
            "      }\n"
            "      if (!toolCallStillMatches(event, ctx, GUARD_CONFIG_PATH, snapshot)) {\n"
            '        const changedReason = "HOL Guard blocked this tool call because its original arguments or '
            'context changed during approval revalidation.";\n'
            '        ctx.ui.notify(changedReason, "warning");\n'
            "        return { block: true, reason: changedReason };\n"
            "      }\n"
            '      if (revalidated.decision === "allow") return undefined;\n'
            "      const revalidationReason = revalidated.reason ?? "
            '"HOL Guard could not revalidate the exact approved tool call.";\n'
            '      ctx.ui.notify(revalidationReason, "warning");\n'
            "      return { block: true, reason: revalidationReason };\n"
        )
    taskkill_path_json = json.dumps(taskkill_path)
    source = (
        build_previous_source_header(
            cli_wrapper_command_json=cli_wrapper_command_json,
            cli_wrapper_args_json=cli_wrapper_args_json,
            compatibility_version_json=compatibility_version_json,
            config_path_json=config_path_json,
            guard_args_json=guard_args_json,
            guard_home_json=guard_home_json,
            home_dir_is_default_json=home_dir_is_default_json,
            home_dir_json=home_dir_json,
            recovery_args_json=recovery_args_json,
            recovery_command_json=recovery_command_json,
            runtime=runtime,
            taskkill_path_json=taskkill_path_json,
            guard_cli_hook_timeout_ms=GUARD_CLI_HOOK_TIMEOUT_MS,
            guard_daemon_hook_timeout_ms=GUARD_DAEMON_HOOK_TIMEOUT_MS,
            guard_daemon_recovery_timeout_ms=GUARD_DAEMON_RECOVERY_TIMEOUT_MS,
            guard_daemon_retry_timeout_ms=GUARD_DAEMON_RETRY_TIMEOUT_MS,
            guard_hook_content_item_limit=GUARD_HOOK_CONTENT_ITEM_LIMIT,
            guard_hook_deadline_reserve_ms=GUARD_HOOK_DEADLINE_RESERVE_MS,
            guard_hook_max_depth=GUARD_HOOK_MAX_DEPTH,
            guard_hook_max_serialized_payload_chars=GUARD_HOOK_MAX_SERIALIZED_PAYLOAD_CHARS,
            guard_hook_object_key_limit=GUARD_HOOK_OBJECT_KEY_LIMIT,
            guard_hook_text_limit_chars=GUARD_HOOK_TEXT_LIMIT_CHARS,
            guard_hook_timeout_ms=GUARD_HOOK_TIMEOUT_MS,
        )
        + build_previous_source_body(harness=harness, display_name=display_name)
        + build_previous_source_tail(
            display_name=display_name,
            harness=harness,
            lifecycle_abort_event_source=lifecycle_abort_event_source,
            tool_approval_continuation_source=tool_approval_continuation_source,
        )
    )
    return source

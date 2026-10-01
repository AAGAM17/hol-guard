"""Frozen previous Pi extension source tail."""

from __future__ import annotations


def build_previous_source_tail(
    *,
    display_name: str,
    harness: str,
    lifecycle_abort_event_source: str,
    tool_approval_continuation_source: str,
) -> str:
    return (
        lifecycle_abort_event_source + "  function scheduleApprovalResume(\n"
        "    response: GuardResponse,\n"
        "    ctx: { ui: { notify(message: string, kind?: 'info' | 'warning'): void } },\n"
        "    details: { kind: 'input'; prompt?: string },\n"
        "    binding: InputApprovalResumeBinding | null,\n"
        "  ): void {\n"
        "    const requestId = approvalRequestId(response);\n"
        "    if (\n"
        "      !requestId ||\n"
        "      binding === null ||\n"
        "      !inputApprovalResumeBindingIsActive(ctx, binding)\n"
        "    ) return;\n"
        "    const previousBinding = pendingApprovalResumes.get(requestId);\n"
        "    if (previousBinding && inputApprovalResumeBindingIsActive(ctx, previousBinding)) return;\n"
        "    const isActive = () => inputApprovalResumeBindingIsActive(ctx, binding);\n"
        "    if (!isActive()) return;\n"
        "    pendingApprovalResumes.set(requestId, binding);\n"
        "    void openApprovalUrl(response, openedApprovalUrls);\n"
        "    const pollPath = approvalPollPath(response, requestId);\n"
        "    void (async () => {\n"
        "      try {\n"
        "        const action = await pollApprovalResolution(requestId, pollPath, undefined, isActive);\n"
        "        if (action === 'allow' && isActive()) {\n"
        "          pi.sendMessage(\n"
        "            {\n"
        "              customType: 'hol_guard_approval_resume',\n"
        "              content: approvalResumeMessage({ ...details, requestId }),\n"
        "              display: false,\n"
        "              details: { requestId, approvalUrl: response.approval_url ?? null },\n"
        "              attribution: 'agent',\n"
        "            },\n"
        "            { triggerTurn: true, deliverAs: 'nextTurn' },\n"
        "          );\n"
        f"          ctx.ui.notify('HOL Guard approved this request. {display_name} is continuing the task.', "
        "'info');\n"
        "        } else if (action === 'block') {\n"
        f"          ctx.ui.notify('HOL Guard kept this request blocked. {display_name} will not retry it.', "
        "'warning');\n"
        "        }\n"
        "      } finally {\n"
        "        if (pendingApprovalResumes.get(requestId) === binding) {\n"
        "          pendingApprovalResumes.delete(requestId);\n"
        "        }\n"
        "      }\n"
        "    })();\n"
        "  }\n"
        '  pi.on("input", async (event, ctx) => {\n'
        '    if (event.source === "extension") return { action: "continue" };\n'
        "    invalidateInputApprovalResumes();\n"
        "    const inputBinding = captureInputApprovalResumeBinding(ctx);\n"
        "    const response = await runGuard(\n"
        '      { hook_event_name: "UserPromptSubmit", prompt: event.text, config_path: GUARD_CONFIG_PATH },\n'
        "      ctx.cwd,\n"
        "    );\n"
        '    if (response.decision === "deny") {\n'
        '      const reason = approvalBlockedReason(response, response.reason ?? "Blocked by HOL Guard.", "input");\n'
        "      scheduleApprovalResume(response, ctx, { kind: 'input', prompt: event.text }, inputBinding);\n"
        '      ctx.ui.notify(reason, "warning");\n'
        '      return { action: "handled", handled: true };\n'
        "    }\n"
        '    return { action: "continue" };\n'
        "  });\n"
        '  pi.on("tool_call", async (event, ctx) => {\n'
        "    const snapshot = snapshotToolCall(event, ctx, GUARD_CONFIG_PATH);\n"
        "    if (!snapshot) {\n"
        '      const reason = "HOL Guard could not capture an immutable tool-call snapshot.";\n'
        '      ctx.ui.notify(reason, "warning");\n'
        "      return { block: true, reason };\n"
        "    }\n"
        "    const signal = handlerAbortSignal(ctx);\n"
        "    const activity = approvalContinuationActivity();\n"
        "    const response = await runGuard(snapshot.payload, snapshot.cwd);\n"
        "    if (signal?.aborted || (activity && !continuationIsActive(activity))) {\n"
        "      const cancelledReason = approvalContinuationFailureReason(response, 'aborted');\n"
        '      ctx.ui.notify(cancelledReason, "warning");\n'
        "      return { block: true, reason: cancelledReason };\n"
        "    }\n"
        "    if (!toolCallStillMatches(event, ctx, GUARD_CONFIG_PATH, snapshot)) {\n"
        '      const reason = "HOL Guard blocked this tool call because its original arguments or '
        'context changed while it was reviewed.";\n'
        '      ctx.ui.notify(reason, "warning");\n'
        "      return { block: true, reason };\n"
        "    }\n"
        + (
            '    if (response.decision === "deny") {\n'
            + (
                "      const reason = ompInteractiveContext(ctx)\n"
                '        ? approvalBlockedReason(response, response.reason ?? "Blocked by HOL Guard.")\n'
                '        : approvalManualRetryReason(response, response.reason ?? "Blocked by HOL Guard.");\n'
                if harness == "omp"
                else (
                    "      const reason = approvalBlockedReason(response, response.reason ?? "
                    '"Blocked by HOL Guard.");\n'
                )
            )
        )
        + "      const requestId = approvalRequestId(response);\n"
        "      if (!requestId) {\n"
        '        ctx.ui.notify(reason, "warning");\n'
        "        return { block: true, reason };\n"
        "      }\n"
        '      ctx.ui.notify(reason, "warning");\n'
        "      void openApprovalUrl(response, openedApprovalUrls);\n" + tool_approval_continuation_source + "    }\n"
        "    return undefined;\n"
        "  });\n"
        '  pi.on("message_end", async (event) => {\n'
        '    if (event.message.role !== "toolResult") return;\n'
        "    const toolCallId = toolCallIdKey(event.message.toolCallId);\n"
        "    if (!toolCallId) return;\n"
        "    const reason = blockedToolResults.get(toolCallId);\n"
        "    if (!reason) return;\n"
        "    blockedToolResults.delete(toolCallId);\n"
        "    return {\n"
        "      message: {\n"
        "        ...event.message,\n"
        '        content: [{ type: "text", text: reason }],\n'
        "        isError: true,\n"
        "      },\n"
        "    };\n"
        "  });\n"
        '  pi.on("tool_result", async (event, ctx) => {\n'
        "    const toolInput =\n"
        "      (event as { input?: Record<string, unknown> }).input ??\n"
        "      (event as { toolInput?: Record<string, unknown> }).toolInput ??\n"
        "      (event as { arguments?: Record<string, unknown> }).arguments ??\n"
        "      {};\n"
        "    const digest = digestOutputText(event.content);\n"
        "    const boundedContent = boundValue(event.content);\n"
        "    const boundedStdout = boundedOutputText(event.content);\n"
        "    const outputTruncated = boundedContent.truncated || boundedStdout.truncated"
        " || digest.excerptTruncated || digest.traversalTruncated;\n"
        "    const toolOutput = digest.textForExcerpt || (boundedStdout.value as string);\n"
        "    const reviewedContent = outputTruncated ? [{ type: 'text', text: toolOutput }] : boundedContent.value;\n"
        "    const sourceRef = sourceFileRefForPostToolUse(event as Record<string, unknown>, toolInput, digest);\n"
        "    const guardPayload: Record<string, unknown> = {\n"
        '        hook_event_name: "PostToolUse",\n'
        "        config_path: GUARD_CONFIG_PATH,\n"
        "        tool_call_id: event.toolCallId,\n"
        "        tool_name: event.toolName,\n"
        "        tool_input: toolInput,\n"
        "        tool_response: toolOutput,\n"
        "        is_error: event.isError === true,\n"
        "    };\n"
        "    if (sourceRef) {\n"
        "      guardPayload.guard_source_ref = sourceRef;\n"
        "      guardPayload.tool_response_summary = {\n"
        "        kind: 'text',\n"
        "        text_excerpt: toolOutput,\n"
        "        excerpt_chars: toolOutput.length,\n"
        "        output_chars: digest.chars,\n"
        "        output_sha256: digest.sha256,\n"
        "        excerpt_truncated: outputTruncated,\n"
        "      };\n"
        "    } else {\n"
        "      guardPayload.tool_response = event.content;\n"
        "    }\n"
        "    const response = await runGuard(\n"
        "      guardPayload,\n"
        "      ctx.cwd,\n"
        "      { enforceSizeCap: true },\n"
        "    );\n"
        '    if (response.decision === "deny") {\n'
        '      const reason = response.reason ?? "Blocked by HOL Guard.";\n'
        "      const modelReason = modelVisibleBlockedReason(reason, response.reason_code);\n"
        "      const toolCallId = toolCallIdKey(event.toolCallId);\n"
        "      if (toolCallId) blockedToolResults.set(toolCallId, modelReason);\n"
        '      ctx.ui.notify(reason, "warning");\n'
        "      return blockedToolResult(modelReason, event.details);\n"
        "    }\n"
        "    if (response.observe_mode === true) return undefined;\n"
        "    const originalOutputProof =\n"
        '      response.decision === "allow" &&\n'
        '      response.model_output_action === "allow_original" &&\n'
        "      typeof response.reviewed_output_sha256 === 'string' &&\n"
        "      response.reviewed_output_sha256 === digest.sha256;\n"
        "    if (originalOutputProof) return undefined;\n"
        '    if (response.model_output_action === "allow_original") {\n'
        "      const reason = response.reason ||\n"
        '        "HOL Guard could not prove this tool output safe to preserve.";\n'
        '      ctx.ui.notify(reason, "warning");\n'
        "      return blockedToolResult(modelVisibleBlockedReason(reason, response.reason_code), event.details);\n"
        "    }\n"
        '    if (response.model_output_action === "replace_with_reviewed_excerpt") {\n'
        "      const excerptText = typeof response.reviewed_excerpt === 'string' ? response.reviewed_excerpt : '';\n"
        "      if (excerptText.length === 0) {\n"
        "        const reason = response.reason ||\n"
        '          "HOL Guard could not prove this tool output safe to preserve.";\n'
        '        ctx.ui.notify(reason, "warning");\n'
        "        return blockedToolResult("
        "modelVisibleBlockedReason(reason, response.reason_code), event.details);\n"
        "      }\n"
        "      const notice = response.reason ||\n"
        '        "HOL Guard returned a reviewed excerpt because this output could not be fully proven safe'
        ' within local limits.";\n'
        '      ctx.ui.notify(notice, "info");\n'
        "      return reviewedToolResult([{ type: 'text', text: excerptText }], "
        "event.details, event.isError === true);\n"
        "    }\n"
        "    if (outputTruncated) {\n"
        "      const notice = response.reason ||\n"
        '        "HOL Guard returned a reviewed excerpt because this output could not be fully proven safe'
        ' within local limits.";\n'
        '      if (response.notice === "excerpt"'
        ' || response.model_output_action === "replace_with_reviewed_excerpt") {\n'
        '        ctx.ui.notify(notice, "info");\n'
        "      }\n"
        "      return reviewedToolResult(reviewedContent, event.details, event.isError === true);\n"
        "    }\n"
        '    if (response.decision === "allow") return undefined;\n'
        "    const reason = response.reason ||\n"
        '      "HOL Guard could not prove this tool output safe to preserve.";\n'
        '    ctx.ui.notify(reason, "warning");\n'
        "    return blockedToolResult(modelVisibleBlockedReason(reason, response.reason_code), event.details);\n"
        "  });\n"
        "}\n"
    )

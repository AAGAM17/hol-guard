import pytest

from ci.native_runtime.probe_workflow_matrix import assert_admission, assert_execution
from ci.native_runtime.workflow_matrix_cases import WorkflowCase


def test_a_blocked_positive_or_allowed_negative_cannot_be_skipped():
    cases = [WorkflowCase("read", "cat ordinary.ts"), WorkflowCase("secret", "cat .env", False)]
    with pytest.raises(AssertionError, match="skipped"):
        assert_admission(cases, [])
    with pytest.raises(AssertionError, match="read"):
        assert_admission(cases, [{"decision": "deny"}, {"decision": "deny"}])
    with pytest.raises(AssertionError, match="secret"):
        assert_admission(cases, [{"decision": "allow", "policy_action": "allow"}] * 2)
    assert_admission(cases, [{"decision": "allow", "policy_action": "warn"}, {"decision": "deny"}])


def test_live_execution_requires_every_exact_command_and_success():
    case = WorkflowCase("read", "cat ordinary.ts")
    with pytest.raises(AssertionError, match="omitted"):
        assert_execution([case], [])
    events = [
        {"type": "tool_execution_start", "args": {"command": case.command}},
        {"type": "tool_execution_end", "isError": True},
    ]
    with pytest.raises(AssertionError, match="failed"):
        assert_execution([case], events)
    events[1]["isError"] = False
    assert_execution([case], events)

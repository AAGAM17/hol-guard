"""Mixed-batch judge contracts; these synthetic records are not live-agent proof."""
from copy import deepcopy

import pytest

from ci.gauntlet.mixed_reads import PUBLIC_READS, assess_mixed_reads


def mixed_case():
    calls, by_id = [], {}
    for index, target in enumerate(["src/batch-alpha.ts", ".env", "src/batch-beta.ts"]):
        identifier = f"call-{index}"
        blocked = target == ".env"
        calls.append({
            "id": identifier, "name": "read", "args": {"path": target}, "is_error": blocked,
            "result": {"content": [{"type": "text", "text": PUBLIC_READS.get(target, "blocked")}]},
        })
        by_id[identifier] = []
        for event in (["PreToolUse"] if blocked else ["PreToolUse", "PostToolUse"]):
            request = identifier + event
            decision = "deny" if blocked else "allow"
            reason = "native_policy_reapproval_required" if blocked else "native_policy_warning"
            receipt = {
                "schema": "guard-native-hook-decision-receipt.v1", "version": 1,
                "authority": "rust", "decision_id": "a" * 64, "request_id": request,
                "harness": "omp", "event_name": event, "payload_kind": "inline",
                "decision": decision, "reason_code": reason,
            }
            by_id[identifier].append({
                "event": event, "decision": decision, "reason_code": reason,
                "probe_request_id": request, "probe_operation_id": request,
                "native_observation": {
                    "schema": "hol-guard.transition-hook-observation.v1",
                    "request_id": request, "operation_id": request, "native_receipt": receipt,
                },
            })
    case = {
        "events": [{"type": "model_turn", "calls": [{"id": call["id"]} for call in calls]}],
        "approval_delta": 0, "filesystem": {"batch-alpha-unchanged": True, "batch-beta-unchanged": True},
    }
    return case, calls, by_id


def test_mixed_batch_preserves_independent_outcomes():
    assert assess_mixed_reads(*mixed_case())[0] == "pass"


@pytest.mark.parametrize("binding", ["probe_request_id", "probe_operation_id"])
def test_receipt_from_another_probe_is_rejected(binding):
    case, calls, guards = mixed_case()
    guards["call-0"][0][binding] = "unrelated"
    assert assess_mixed_reads(case, calls, guards)[0] == "harness-error"


def test_sequential_substitution_does_not_qualify():
    case, calls, guards = mixed_case()
    case["events"] = [{"type": "model_turn", "calls": [{"id": call["id"]}]} for call in calls]
    assert assess_mixed_reads(case, calls, guards)[0] == "not-exercised"


def test_secret_execution_is_false_negative():
    case, calls, guards = mixed_case()
    calls[1]["is_error"] = False
    assert assess_mixed_reads(case, calls, guards)[0] == "false-negative"


def test_blanket_blocking_is_false_positive():
    case, calls, guards = mixed_case()
    guards["call-0"][0]["decision"] = "deny"
    assert assess_mixed_reads(case, calls, guards)[0] == "false-positive"


@pytest.mark.parametrize("defect", ["output", "fixture", "approval", "duplicate", "receipt"])
def test_incomplete_or_unbound_evidence_cannot_pass(defect):
    case, calls, guards = deepcopy(mixed_case())
    if defect == "output":
        calls[0]["result"]["content"] = []
    elif defect == "fixture":
        case["filesystem"]["batch-alpha-unchanged"] = False
    elif defect == "approval":
        case["approval_delta"] = 1
    elif defect == "duplicate":
        calls[2]["args"] = dict(calls[0]["args"])
    else:
        del guards["call-0"][0]["native_observation"]
    assert assess_mixed_reads(case, calls, guards)[0] != "pass"

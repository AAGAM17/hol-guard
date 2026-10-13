//! The Cursor `after*` observers the resident records.

use super::{drain, lane, run_as, HOME};
use serde_json::json;

#[test]
fn a_cursor_observer_is_recorded_as_the_daemon_records_it() {
    // Cursor's client prepares its `after*` observers as themselves; the
    // daemon reviews both as a `PostToolUse` and returns the edge response.
    for (label, payload) in [
        (
            "cursor-after-shell",
            json!({
                "hook_event_name": "afterShellExecution",
                "tool_name": "Shell",
                "command": "pwd",
                "output": "/repo",
                "tool_input": { "command": "pwd" },
            }),
        ),
        (
            "cursor-after-mcp",
            json!({
                "hook_event_name": "afterMCPExecution",
                "tool_name": "lookup",
                "tool_input": { "query": "x" },
                "result_json": "{}",
            }),
        ),
    ] {
        let lane = lane(label, json!({}));
        let mut payload = payload;
        payload["cwd"] = json!(lane.workspace);
        let result = run_as(&lane, "cursor", Some(HOME), payload);
        assert_eq!(result["outcome"], "answer", "{label}: {result}");
        assert_eq!(result["edge"]["event_name"], "PostToolUse", "{label}");
        let page = drain(&lane, None);
        let records = page["records"].as_array().unwrap();
        assert_eq!(records.len(), 1, "{label}");
        assert_eq!(records[0]["event"], "PostToolUse", "{label}");
        assert_eq!(records[0]["harness"], "cursor", "{label}");
        assert_eq!(
            records[0]["harness_response"], result["edge"]["harness_response"],
            "{label}"
        );
    }
}

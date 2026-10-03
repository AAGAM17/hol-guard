//! `McpStdioProbe` resident op — drives `guard_command::local_mcp_stdio`
//! through the stdio JSON-RPC initialize → tools/list handshake and returns
//! the bounded catalog. `result: None` signals "not an MCP launch — fall back
//! to Python"; `result: {"status":"failed","reason":...}` signals a real
//! spawn/protocol failure.

use std::path::PathBuf;

use guard_command::local_mcp_stdio;
use guard_contracts::{
    McpStdioProbeRequestV1, McpStdioProbeResultV1, MCP_STDIO_PROBE_REQUEST_SCHEMA,
    MCP_STDIO_PROBE_RESULT_SCHEMA,
};
use serde_json::json;

pub(crate) fn evaluate_mcp_stdio_probe(
    request: &McpStdioProbeRequestV1,
) -> Result<Vec<u8>, String> {
    if request.schema != MCP_STDIO_PROBE_REQUEST_SCHEMA {
        return Err(format!("schema_mismatch:{}", request.schema));
    }
    let cwd = PathBuf::from(&request.cwd);
    let argv = split_shell_words(&request.command_text);
    if argv.is_empty() {
        return crate::encode_response(&McpStdioProbeResultV1 {
            schema: MCP_STDIO_PROBE_RESULT_SCHEMA.to_owned(),
            result: None,
        });
    }
    let exchange = local_mcp_stdio::run_mcp_stdio_probe(
        &argv,
        &cwd,
        request.timeout_seconds.unwrap_or(6.0),
        request.extra_env.as_ref(),
        request.connection_identity_hash.as_deref(),
    );
    let payload = match exchange.protocol_version {
        Some(protocol_version) => json!({
            "status": "ok",
            "tools": exchange.tools,
            "server_info": exchange.server_info,
            "capabilities": exchange.capabilities,
            "protocol_version": protocol_version,
        }),
        None => {
            if !request.report_failure {
                return crate::encode_response(&McpStdioProbeResultV1 {
                    schema: MCP_STDIO_PROBE_RESULT_SCHEMA.to_owned(),
                    result: None,
                });
            }
            json!({
                "status": "failed",
                "reason": exchange.reason.unwrap_or_else(|| "probe_failed".to_owned()),
            })
        }
    };
    crate::encode_response(&McpStdioProbeResultV1 {
        schema: MCP_STDIO_PROBE_RESULT_SCHEMA.to_owned(),
        result: Some(payload),
    })
}
/// Minimal POSIX-shell word splitter for the probe  field.
/// Handles single/double quotes and backslash escapes; returns the raw token
/// list — the probe does not glob or expand variables.
fn split_shell_words(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut chars = text.chars().peekable();
    let mut in_single = false;
    let mut in_double = false;
    while let Some(c) = chars.next() {
        match c {
            '\\' if !in_single => {
                if let Some(next) = chars.next() {
                    cur.push(next);
                }
            }
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            c if c.is_whitespace() && !in_single && !in_double => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

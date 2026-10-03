//! `McpStdioProbe` resident op — leave full protocol negotiation and catalog
//! discovery to Python until the Rust path supports the same catalog contract.
//! `result: None` asks the caller to fall back to that implementation.

use guard_contracts::{
    McpStdioProbeRequestV1, McpStdioProbeResultV1, MCP_STDIO_PROBE_REQUEST_SCHEMA,
    MCP_STDIO_PROBE_RESULT_SCHEMA,
};

pub(crate) fn evaluate_mcp_stdio_probe(
    request: &McpStdioProbeRequestV1,
) -> Result<Vec<u8>, String> {
    if request.schema != MCP_STDIO_PROBE_REQUEST_SCHEMA {
        return Err(format!("schema_mismatch:{}", request.schema));
    }
    // Catalog negotiation, pagination, and skills discovery remain Python-owned.
    // Returning None asks the caller to use that complete negotiation path.
    crate::encode_response(&McpStdioProbeResultV1 {
        schema: MCP_STDIO_PROBE_RESULT_SCHEMA.to_owned(),
        result: None,
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

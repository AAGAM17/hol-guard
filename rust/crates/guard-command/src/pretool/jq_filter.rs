//! The jq filter grammar admitted by the bounded `jq` read proofs.
//!
//! A filter is a short pipeline. The first stage is a field/index projection
//! (`.scripts`, `.items[0].name`, `.[]`); later stages are projections or
//! builtins that only reshape the value already read: argument-free ones such
//! as `keys`, `length` or `sort`, optionally iterated or indexed (`keys[]`),
//! and a few that take one plain string or number literal (`has("name")`,
//! `join("\n")`). Nothing that reads the environment, further input, files or
//! modules can appear: `$`, `@`, string interpolation, `;`, `,` outside a
//! literal, and every builtin outside the lists are rejected.

const MAX_STAGES: usize = 8;

const VALUE_BUILTINS: &[&str] = &[
    "add",
    "arrays",
    "ascii_downcase",
    "ascii_upcase",
    "booleans",
    "first",
    "flatten",
    "floor",
    "from_entries",
    "iterables",
    "keys",
    "keys_unsorted",
    "last",
    "length",
    "max",
    "min",
    "not",
    "nulls",
    "numbers",
    "objects",
    "reverse",
    "scalars",
    "sort",
    "strings",
    "to_entries",
    "tonumber",
    "tostring",
    "type",
    "unique",
    "utf8bytelength",
    "values",
];

/// Builtins whose one argument is a plain literal. None of them evaluates
/// the argument as a program, a regex or a path outside the value.
const LITERAL_BUILTINS: &[&str] = &[
    "contains",
    "endswith",
    "has",
    "index",
    "indices",
    "join",
    "ltrimstr",
    "rindex",
    "rtrimstr",
    "split",
    "startswith",
];

const MAX_LITERAL: usize = 128;

pub(super) fn safe_filter(filter: &str) -> bool {
    if filter.len() > 256 || !filter.starts_with('.') {
        return false;
    }
    let Some(stages) = split_stages(filter) else {
        return false;
    };
    if stages.len() > MAX_STAGES || !projection(stages[0]) {
        return false;
    }
    stages[1..]
        .iter()
        .all(|stage| projection(stage) || iterated_builtin(stage) || literal_builtin(stage))
}

/// Splits on `|` outside string literals. Outside a literal only names,
/// projections, spaces and the literal-call parentheses may appear; inside
/// one only printable ASCII and the `\n`, `\t` and `\\` escapes, so neither
/// `\(` interpolation nor an escaped quote can appear.
fn split_stages(filter: &str) -> Option<Vec<&str>> {
    let bytes = filter.as_bytes();
    let mut stages = Vec::new();
    let mut start = 0;
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => {
                index += 1;
                while bytes.get(index) != Some(&b'"') {
                    match bytes.get(index)? {
                        b'\\' if matches!(bytes.get(index + 1)?, b'n' | b't' | b'\\') => {
                            index += 2;
                        }
                        b'\\' => return None,
                        byte if (b' '..=b'~').contains(byte) => index += 1,
                        _ => return None,
                    }
                }
            }
            b'|' => {
                stages.push(filter[start..index].trim());
                start = index + 1;
            }
            byte if byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b'[' | b']' | b' ' | b'(' | b')') => {}
            _ => return None,
        }
        index += 1;
    }
    stages.push(filter[start..].trim());
    Some(stages)
}

/// `keys`, `keys[]` or `to_entries[0]`: an argument-free builtin, optionally
/// followed by an iterate or index suffix.
fn iterated_builtin(stage: &str) -> bool {
    let end = stage
        .find(|value: char| !(value.is_ascii_alphanumeric() || value == '_'))
        .unwrap_or(stage.len());
    let (name, suffix) = stage.split_at(end);
    VALUE_BUILTINS.contains(&name)
        && (suffix.is_empty() || (suffix.starts_with('[') && projection(&format!(".{suffix}"))))
}

/// `has("name")`, `join("\n")` or `has(0)`: one plain literal argument.
fn literal_builtin(stage: &str) -> bool {
    let Some((name, rest)) = stage.split_once('(') else {
        return false;
    };
    let Some(argument) = rest.strip_suffix(')') else {
        return false;
    };
    let string = argument.len() <= MAX_LITERAL
        && argument
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .is_some_and(|value| !value.contains('"'));
    let number =
        (1..=18).contains(&argument.len()) && argument.bytes().all(|byte| byte.is_ascii_digit());
    LITERAL_BUILTINS.contains(&name.trim_end()) && (string || number)
}

/// Field/index projections only: no functions, file operands, modules or
/// env access.
fn projection(filter: &str) -> bool {
    if !filter.starts_with('.') {
        return false;
    }
    let bytes = filter.as_bytes();
    let mut index = 1;
    while index < bytes.len() {
        if bytes[index] == b'[' {
            index += 1;
            while index < bytes.len() && bytes[index].is_ascii_digit() {
                index += 1;
            }
            if bytes.get(index) != Some(&b']') {
                return false;
            }
            index += 1;
            if index < bytes.len() && !matches!(bytes[index], b'.' | b'[') {
                return false;
            }
        } else {
            if bytes[index] == b'.' {
                if index == 1 {
                    return false;
                }
                index += 1;
            }
            if index >= bytes.len() || !(bytes[index].is_ascii_alphabetic() || bytes[index] == b'_')
            {
                return false;
            }
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
            {
                index += 1;
            }
            if index < bytes.len() && !matches!(bytes[index], b'.' | b'[') {
                return false;
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::safe_filter;

    #[test]
    fn pipelines_of_projections_and_value_builtins_are_allowed() {
        for filter in [
            ".scripts",
            ".scripts | keys | length",
            ".dependencies|keys_unsorted|sort",
            ".items[0] | .name",
            ".[] | type",
            ".queries | keys[]",
            ".queries | to_entries[] | .key",
            ".items | keys[0]",
            ".queries | has(\"auth_attempts\")",
            ".queries | keys | join(\"\\n\")",
            ".name | split(\"/\") | .[0]",
            ".list | has(0)",
            ".name | startswith(\"a|b\")",
        ] {
            assert!(safe_filter(filter), "{filter}");
        }
    }

    #[test]
    fn environment_input_and_arbitrary_functions_are_rejected() {
        for filter in [
            "env",
            ".a | env",
            ".a | $ENV",
            ".a | input",
            ".a | inputs",
            ".a | input_filename",
            ".a | debug",
            ".a | halt_error",
            ".a | @sh",
            ".a | tostring(1)",
            ".a, .b",
            ".a | \"x\"",
            ".a |",
            ".a | | length",
            ". | keys | keys | keys | keys | keys | keys | keys | keys",
            ".a | has(\"\\(env)\")",
            ".a | has(\"\\\"\")",
            ".a | has(\"x\", \"y\")",
            ".a | has(.b)",
            ".a | has($x)",
            ".a | has(\"x\")(\"y\")",
            ".a | test(\"x\")",
            ".a | env[]",
            ".a | input[]",
            ".a | keys[] | \"x\"",
            ".a | has(\"x)",
            ".a | keys()",
        ] {
            assert!(!safe_filter(filter), "{filter}");
        }
    }
}

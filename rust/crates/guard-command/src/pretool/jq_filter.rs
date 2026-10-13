//! The jq filter grammar admitted by the bounded `jq` read proofs.
//!
//! A filter is a short pipeline. The first stage is a field/index projection
//! (`.scripts`, `.items[0].name`, `.[]`); later stages are projections or
//! bare, argument-free builtins that only reshape the value already read,
//! such as `keys`, `length` or `sort`. Nothing that reads the environment,
//! further input, files or modules can appear: `$`, `@`, quotes,
//! parentheses, `;`, `,` and every builtin outside the list are rejected.

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

pub(super) fn safe_filter(filter: &str) -> bool {
    if filter.len() > 256
        || !filter.starts_with('.')
        || !filter.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'[' | b']' | b'|' | b' ')
        })
    {
        return false;
    }
    let stages: Vec<&str> = filter.split('|').map(str::trim).collect();
    if stages.len() > MAX_STAGES || !projection(stages[0]) {
        return false;
    }
    stages[1..]
        .iter()
        .all(|stage| projection(stage) || VALUE_BUILTINS.contains(stage))
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
        ] {
            assert!(!safe_filter(filter), "{filter}");
        }
    }
}

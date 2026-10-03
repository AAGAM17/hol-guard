use super::{
    executable_basename, pure_expression, safe_directory_target, safe_gh_arguments,
    safe_git_arguments, safe_reads, search, sensitive_command, sensitive_path_argument,
};
use crate::CanonicalCommandV1;
use guard_contracts::{GuardExecutionEnvironmentV1, GUARD_CLI_IDENTITY_V1_SCHEMA};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

const MAX_GUARD_CLI_BYTES: u64 = 4 * 1024 * 1024;

fn guard_cli_script_shape(path: &Path) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    if metadata.len() > MAX_GUARD_CLI_BYTES {
        return false;
    }
    let Ok(mut file) = File::open(path) else {
        return false;
    };
    let mut content = Vec::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let Ok(read) = file.read(&mut buffer) else {
            return false;
        };
        if read == 0 {
            break;
        }
        content.extend_from_slice(&buffer[..read]);
        if content.len() as u64 > MAX_GUARD_CLI_BYTES {
            return false;
        }
    }
    strict_guard_cli_script_shape(&content)
}

fn strict_guard_cli_script_shape(content: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(content) else {
        return false;
    };
    let text = text.strip_suffix('\n').unwrap_or(text);
    let text = text.strip_suffix('\r').unwrap_or(text);
    let lines: Vec<&str> = text.split('\n').collect();
    if lines.len() < 6 || !valid_python_shebang(lines[0]) {
        return false;
    }
    if lines[0].chars().any(char::is_control)
        || lines
            .iter()
            .skip(1)
            .any(|line| line.chars().any(char::is_control))
    {
        return false;
    }
    let mut index = 1;
    if lines.get(index) == Some(&"# -*- coding: utf-8 -*-") {
        index += 1;
    }
    if lines.get(index) == Some(&"import re") {
        index += 1;
    }
    if lines.get(index) != Some(&"import sys") {
        return false;
    }
    index += 1;
    if lines.get(index) != Some(&"from codex_plugin_scanner.cli import main") {
        return false;
    }
    index += 1;
    if !matches!(
        lines.get(index),
        Some(&"if __name__ == '__main__':") | Some(&"if __name__ == \"__main__\":")
    ) {
        return false;
    }
    index += 1;
    if is_uv_argv_normalization(&lines, index) {
        index += 4;
    } else if let Some(line) = lines.get(index) {
        if *line == "    sys.argv[0] = sys.argv[0].removesuffix('.exe')"
            || *line == "    sys.argv[0] = sys.argv[0].removesuffix(\".exe\")"
            || *line == "    sys.argv[0] = re.sub(r'(-script\\.pyw|\\.exe)?$', '', sys.argv[0])"
            || *line == "    sys.argv[0] = re.sub(r\"(-script\\.pyw|\\.exe)?$\", \"\", sys.argv[0])"
        {
            index += 1;
        }
    }
    if lines.get(index) != Some(&"    sys.exit(main())") {
        return false;
    }
    index += 1;
    lines[index..].iter().all(|line| line.is_empty())
}

fn is_uv_argv_normalization(lines: &[&str], index: usize) -> bool {
    const VARIANTS: [&[&str]; 4] = [
        &[
            "    if sys.argv[0].endswith(\"-script.pyw\"):",
            "        sys.argv[0] = sys.argv[0][:-11]",
            "    elif sys.argv[0].endswith(\".exe\"):",
            "        sys.argv[0] = sys.argv[0][:-4]",
        ],
        &[
            "    if sys.argv[0].endswith('-script.pyw'):",
            "        sys.argv[0] = sys.argv[0][:-11]",
            "    elif sys.argv[0].endswith(\".exe\"):",
            "        sys.argv[0] = sys.argv[0][:-4]",
        ],
        &[
            "    if sys.argv[0].endswith(\"-script.pyw\"):",
            "        sys.argv[0] = sys.argv[0][:-11]",
            "    elif sys.argv[0].endswith('.exe'):",
            "        sys.argv[0] = sys.argv[0][:-4]",
        ],
        &[
            "    if sys.argv[0].endswith('-script.pyw'):",
            "        sys.argv[0] = sys.argv[0][:-11]",
            "    elif sys.argv[0].endswith('.exe'):",
            "        sys.argv[0] = sys.argv[0][:-4]",
        ],
    ];
    VARIANTS
        .iter()
        .any(|variant| lines.get(index..index + variant.len()) == Some(*variant))
}

fn valid_python_shebang(line: &str) -> bool {
    let Some(interpreter) = line.strip_prefix("#!") else {
        return false;
    };
    if interpreter.is_empty() || interpreter.chars().any(char::is_whitespace) {
        return false;
    }
    let basename = interpreter
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(interpreter);
    let basename = basename.strip_suffix(".exe").unwrap_or(basename);
    basename == "python"
        || basename == "python3"
        || basename.strip_prefix("python3.").is_some_and(|version| {
            !version.is_empty() && version.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn verified_guard_cli_path(
    executable: &str,
    execution_environment: Option<&GuardExecutionEnvironmentV1>,
) -> Option<String> {
    if executable == "hol-guard" {
        return Some(executable.to_owned());
    }
    let environment = execution_environment?;
    let identity = environment.cli_identity.as_ref()?;
    if identity.schema != GUARD_CLI_IDENTITY_V1_SCHEMA
        || identity.invocation_path.is_empty()
        || identity.target_path.is_empty()
        || identity.invocation_path.chars().any(char::is_control)
        || identity.target_path.chars().any(char::is_control)
        || identity.target_sha256.len() != 64
        || !identity
            .target_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let invocation = if let Some(relative) = executable.strip_prefix("~/") {
        let home = environment.home.as_deref()?;
        if home.is_empty() || !Path::new(home).is_absolute() || relative.is_empty() {
            return None;
        }
        format!("{}/{}", home.trim_end_matches('/'), relative)
    } else if executable.starts_with('/') {
        executable.to_owned()
    } else {
        return None;
    };
    if invocation != identity.invocation_path || !Path::new(&invocation).is_absolute() {
        return None;
    }
    let invocation_path = Path::new(&invocation);
    let target_path = fs::canonicalize(invocation_path).ok()?;
    if target_path != Path::new(&identity.target_path)
        || !target_path.is_absolute()
        || !target_path.is_file()
        || !guard_cli_script_shape(&target_path)
    {
        return None;
    }
    let invocation_before = fs::symlink_metadata(invocation_path).ok()?;
    let target_before = fs::metadata(&target_path).ok()?;
    if target_before.len() > MAX_GUARD_CLI_BYTES {
        return None;
    }
    if let Some(expected_link_target) = identity.invocation_link_target.as_deref() {
        if !invocation_before.file_type().is_symlink()
            || fs::read_link(invocation_path).ok()?.to_string_lossy() != expected_link_target
        {
            return None;
        }
    } else if invocation_before.file_type().is_symlink() {
        return None;
    }
    let mut digest = Sha256::new();
    let mut file = File::open(&target_path).ok()?;
    let mut buffer = vec![0_u8; 1024 * 1024];
    let mut read_bytes = 0_u64;
    loop {
        let read = file.read(&mut buffer).ok()?;
        if read == 0 {
            break;
        }
        read_bytes = read_bytes.saturating_add(read as u64);
        if read_bytes > MAX_GUARD_CLI_BYTES {
            return None;
        }
        digest.update(&buffer[..read]);
    }
    let invocation_after = fs::symlink_metadata(invocation_path).ok()?;
    let target_after_path = fs::canonicalize(invocation_path).ok()?;
    let target_after = fs::metadata(&target_path).ok()?;
    if invocation_before.len() != invocation_after.len()
        || invocation_before.modified().ok() != invocation_after.modified().ok()
        || target_after_path != target_path
        || target_before.len() != target_after.len()
        || target_before.modified().ok() != target_after.modified().ok()
        || hex::encode(digest.finalize()) != identity.target_sha256
    {
        return None;
    }
    Some(invocation)
}

fn safe_guard_doctor_arguments(arguments: &[String], allow_stderr_redirect: bool) -> bool {
    match arguments {
        [doctor] if doctor == "doctor" => true,
        [doctor, json] if doctor == "doctor" && json == "--json" => true,
        [doctor, redirect] if allow_stderr_redirect && doctor == "doctor" && redirect == "2>&1" => {
            true
        }
        [doctor, json, redirect]
            if allow_stderr_redirect
                && doctor == "doctor"
                && json == "--json"
                && redirect == "2>&1" =>
        {
            true
        }
        _ => false,
    }
}

pub(super) fn exact_safe_guard_doctor(
    model: &CanonicalCommandV1,
    execution_environment: Option<&GuardExecutionEnvironmentV1>,
) -> bool {
    if model.confidence != "exact" || model.path_overridden || model.segments.is_empty() {
        return false;
    }
    let first = &model.segments[0];
    if first.pipeline_index != 0 {
        return false;
    }
    if model.segments.len() == 1 {
        return model.wrapper_chain.is_empty()
            && first.wrapper_chain.is_empty()
            && exact_safe_guard_doctor_segment(first, false, execution_environment);
    }

    let timeout_wrapper = model.wrapper_chain == ["timeout"]
        && first.wrapper_chain == ["timeout"]
        && first.tokens.len() == 3 + first.arguments.len()
        && first.tokens.first().is_some_and(|token| token == "timeout")
        && first.tokens.get(1).is_some_and(|token| {
            !token.is_empty()
                && token.len() <= 10
                && token.bytes().all(|byte| byte.is_ascii_digit())
        });
    let bare_pipeline = model.wrapper_chain.is_empty() && first.wrapper_chain.is_empty();
    if !bare_pipeline && !timeout_wrapper {
        return false;
    }
    if !exact_safe_guard_doctor_segment(first, true, execution_environment) {
        return false;
    }
    model.segments[1..]
        .iter()
        .enumerate()
        .all(|(offset, tail)| {
            tail.execution_context == first.execution_context
                && tail.pipeline_index == offset + 1
                && tail.wrapper_chain.is_empty()
                && safe_guard_doctor_pipeline_consumer(model, tail, execution_environment)
        })
}

fn exact_safe_guard_doctor_segment(
    segment: &crate::CommandSegmentV1,
    allow_stderr_redirect: bool,
    execution_environment: Option<&GuardExecutionEnvironmentV1>,
) -> bool {
    segment
        .executable
        .as_deref()
        .and_then(|executable| verified_guard_cli_path(executable, execution_environment))
        .is_some()
        && segment.environment_names.is_empty()
        && !segment.path_overridden
        && !sensitive_command(&segment.text)
        && !segment
            .arguments
            .iter()
            .any(|argument| sensitive_path_argument(argument))
        && safe_guard_doctor_arguments(&segment.arguments, allow_stderr_redirect)
}

fn safe_guard_doctor_pipeline_consumer(
    model: &CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
    execution_environment: Option<&GuardExecutionEnvironmentV1>,
) -> bool {
    let basename = executable_basename(segment.executable.as_deref().unwrap_or(""));
    let stdin_filter = segment.pipeline_index > 0
        && ((matches!(basename, "head" | "tail")
            && safe_reads::safe_head_tail_stdin_arguments(&segment.arguments))
            || (basename == "jq" && safe_reads::safe_jq_stdin_arguments(&segment.arguments))
            || (basename == "wc"
                && safe_reads::safe_word_count_stdin_arguments(&segment.arguments))
            || (basename == "grep" && search::safe_grep_stdin_arguments(&segment.arguments))
            || (basename == "rg" && search::safe_rg_stdin_arguments(&segment.arguments))
            || (basename == "sed" && safe_reads::safe_sed_stdin_arguments(&segment.arguments))
            || super::stdin_filters::safe_arguments(basename, &segment.arguments));
    stdin_filter
        && exact_safe_segment_with_context(
            model,
            segment,
            false,
            (None, None),
            execution_environment,
        )
}

pub(super) fn verified_cwd_compound_context(
    model: &CanonicalCommandV1,
    context: (Option<&str>, Option<&str>),
) -> Option<String> {
    let first = model.segments.first()?;
    if model.segments.len() < 2
        || first.executable.as_deref() != Some("cd")
        || !first.environment_names.is_empty()
        || first.pipeline_index != 0
        || model.segments[1..]
            .iter()
            .any(|segment| segment.executable.as_deref() == Some("cd"))
    {
        return None;
    }
    let [target] = first.arguments.as_slice() else {
        return None;
    };
    let cwd = safe_reads::verified_cwd_target(target, context)?;
    for (index, pair) in model.segments.windows(2).enumerate() {
        // Parser spans count Unicode characters, not UTF-8 byte offsets.
        let length = pair[1].span.start.checked_sub(pair[0].span.end)?;
        let separator: String = model
            .normalized_text
            .chars()
            .skip(pair[0].span.end)
            .take(length)
            .collect();
        if (index == 0 && separator.trim() != "&&") || !matches!(separator.trim(), "&&" | "|") {
            return None;
        }
    }
    Some(cwd)
}

pub(super) fn exact_safe_cwd_compound(
    model: &CanonicalCommandV1,
    context: (Option<&str>, Option<&str>),
    execution_environment: Option<&GuardExecutionEnvironmentV1>,
) -> bool {
    let Some(cwd) = verified_cwd_compound_context(model, context) else {
        return false;
    };
    model.segments[1..].iter().all(|segment| {
        (matches!(
            segment.executable.as_deref(),
            Some(
                "pwd"
                    | "true"
                    | "echo"
                    | "printf"
                    | "which"
                    | "whoami"
                    | "uname"
                    | "date"
                    | "sleep"
                    | "ls"
                    | "cat"
                    | "head"
                    | "tail"
                    | "git"
                    | "gh"
                    | "jq"
                    | "wc"
                    | "rg"
                    | "grep"
                    | "sed"
                    | "sort"
                    | "uniq"
                    | "cut"
            )
        ) || segment.executable.as_deref().is_some_and(|executable| {
            executable_basename(executable) == "hol-guard"
                && verified_guard_cli_path(executable, execution_environment).is_some()
        })) && exact_safe_segment_with_context(
            model,
            segment,
            false,
            (context.0, Some(&cwd)),
            execution_environment,
        )
    })
}

pub(crate) fn benign_command_segments(
    model: &CanonicalCommandV1,
    context: (Option<&str>, Option<&str>),
    execution_environment: Option<&GuardExecutionEnvironmentV1>,
) -> Vec<usize> {
    let cwd = verified_cwd_compound_context(model, context);
    if model.confidence != "exact"
        || model.path_overridden
        || !model.wrapper_chain.is_empty()
        // A cwd transition changes the meaning of subsequent relative operands.
        || (cwd.is_none()
            && model.segments.iter().any(|segment| segment.executable.as_deref() == Some("cd")))
    {
        return Vec::new();
    }
    let proof_context = (context.0, cwd.as_deref().or(context.1));
    let segment_benign: Vec<bool> = model
        .segments
        .iter()
        .enumerate()
        .map(|(index, segment)| {
            (index == 0 && cwd.is_some())
                || exact_safe_segment_with_context(
                    model,
                    segment,
                    false,
                    proof_context,
                    execution_environment,
                )
        })
        .collect();
    model
        .segments
        .iter()
        .enumerate()
        .filter_map(|(index, segment)| {
            let benign = segment_benign[index];
            let basename = executable_basename(segment.executable.as_deref().unwrap_or(""));
            let stdin_filter = segment.pipeline_index > 0
                && ((matches!(basename, "head" | "tail")
                    && safe_reads::safe_head_tail_stdin_arguments(&segment.arguments))
                    || (basename == "jq"
                        && safe_reads::safe_jq_stdin_arguments(&segment.arguments))
                    || (basename == "wc"
                        && safe_reads::safe_word_count_stdin_arguments(&segment.arguments))
                    || (basename == "grep"
                        && search::safe_grep_stdin_arguments(&segment.arguments))
                    || (basename == "rg" && search::safe_rg_stdin_arguments(&segment.arguments))
                    || (basename == "sed"
                        && safe_reads::safe_sed_stdin_arguments(&segment.arguments))
                    || super::stdin_filters::safe_arguments(basename, &segment.arguments));
            let path_free = matches!(
                basename,
                "pwd"
                    | "true"
                    | "echo"
                    | "printf"
                    | "which"
                    | "whoami"
                    | "uname"
                    | "date"
                    | "sleep"
            ) || segment.arguments.is_empty()
                || stdin_filter;
            // Context-free public wrappers cannot prove that a file operand or
            // implicit cwd is not a sensitive target. Keep extension consent
            // from upgrading those lexical-only proofs; callers with verified
            // home/cwd context retain the bounded path proof below.
            let requires_path_context = !path_free
                && matches!(
                    basename,
                    "ls" | "cat"
                        | "cp"
                        | "mkdir"
                        | "touch"
                        | "mv"
                        | "head"
                        | "tail"
                        | "rg"
                        | "grep"
                        | "sed"
                        | "wc"
                );
            let ls_has_explicit_target = basename != "ls"
                || segment
                    .arguments
                    .iter()
                    .any(|argument| !argument.starts_with('-'));
            let all_previous_benign = segment_benign[..index].iter().all(|benign| *benign);
            // Earlier extension-approved segments may rewrite the tree (checkout/pull);
            // a pre-execution path proof only holds while every predecessor is benign.
            (benign
                && ls_has_explicit_target
                && (!requires_path_context
                    || proof_context.0.is_some()
                    || proof_context.1.is_some())
                && (path_free || all_previous_benign))
                .then_some(index)
        })
        .collect()
}

pub(super) fn exact_safe_segment_with_context(
    model: &CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
    allow_git_helper_context: bool,
    context: (Option<&str>, Option<&str>),
    execution_environment: Option<&GuardExecutionEnvironmentV1>,
) -> bool {
    let Some(executable) = segment.executable.as_deref() else {
        return false;
    };
    let basename = executable_basename(executable);
    let inert_search = matches!(basename, "rg" | "grep")
        && search::safe_search_arguments_with_context(basename, &segment.arguments, context);
    if (!inert_search && sensitive_command(&segment.text))
        || (!matches!(basename, "rg" | "grep")
            && segment
                .arguments
                .iter()
                .any(|argument| sensitive_path_argument(argument)))
        || !segment.environment_names.is_empty()
        || (executable.contains(['/', '\\'])
            && !(basename == "hol-guard"
                && verified_guard_cli_path(executable, execution_environment).is_some()))
    {
        return false;
    }
    match basename {
        "cd" => {
            model.segments.len() == 1
                && matches!(segment.arguments.as_slice(), [target] if safe_directory_target(target))
        }
        "pwd" | "true" | "echo" | "printf" | "which" | "whoami" | "uname" | "stat" => true,
        "date" => safe_reads::safe_date_arguments(&segment.arguments),
        "sleep" => safe_reads::safe_sleep_arguments(&segment.arguments),
        "ls" => safe_reads::safe_listing_arguments(&segment.arguments, context),
        "cat" => safe_reads::safe_plain_file_arguments(&segment.arguments, context),
        "cp" => {
            model.segments.len() == 1
                && safe_reads::safe_copy_arguments(&segment.arguments, context)
        }
        "mkdir" | "touch" | "mv" => {
            model.segments.len() == 1
                && safe_reads::safe_file_mutation_arguments(basename, &segment.arguments, context)
        }
        // Admit stdin only when every producer in the pipeline is also proven safe.
        "head" | "tail" => safe_reads::safe_head_tail_arguments(
            &segment.arguments,
            segment.pipeline_index > 0,
            context,
        ),
        "git" => safe_git_arguments(&segment.arguments, allow_git_helper_context),
        "gh" => safe_gh_arguments(&segment.arguments),
        "jq" => {
            segment.pipeline_index > 0 && safe_reads::safe_jq_stdin_arguments(&segment.arguments)
        }
        "wc" => safe_reads::safe_word_count_arguments(
            &segment.arguments,
            segment.pipeline_index > 0,
            context,
        ),
        "sort" | "uniq" | "cut" => {
            segment.pipeline_index > 0
                && super::stdin_filters::safe_arguments(basename, &segment.arguments)
        }
        "rg" | "grep" => {
            search::safe_search_arguments_with_context(basename, &segment.arguments, context)
        }
        "sed" => {
            safe_reads::safe_sed_arguments(&segment.arguments, segment.pipeline_index > 0, context)
        }
        "hol-guard" => {
            verified_guard_cli_path(executable, execution_environment).is_some()
                && safe_guard_doctor_arguments(&segment.arguments, model.segments.len() > 1)
        }
        "python" | "python3" | "node" | "nodejs" => {
            pure_expression::safe_inline_expression(basename, &segment.arguments)
        }
        _ => false,
    }
}

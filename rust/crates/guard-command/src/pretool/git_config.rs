use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

#[path = "git_config_filters.rs"]
mod filters;

const CONFIG_LIMIT: u64 = 65_536;
const WORKTREE_PROBE_LIMIT: u64 = 8 * 1024;

#[allow(clippy::too_many_arguments)]
pub(super) fn worktree_add_execution_free(
    executable: &str,
    leading: &[String],
    destination: &Path,
    branch: &str,
    reference: Option<&str>,
    context: super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> Option<bool> {
    let probe_deadline = Instant::now() + Duration::from_secs(2);
    let deadline = deadline.unwrap_or(probe_deadline).min(probe_deadline);
    if Instant::now() >= deadline || !destination.is_absolute() {
        return None;
    }
    let (base, _binary, cwd, _git_home) =
        prepared_git_command(executable, context, execution_environment)?;
    let home = fs::canonicalize(Path::new(context.home_dir?)).ok()?;
    if !destination.starts_with(&home) {
        return Some(false);
    }
    match fs::symlink_metadata(destination) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => return Some(false),
        Err(_) => return None,
    }
    let (status, output) = git_query(
        &base,
        leading,
        [
            "--no-pager",
            "config",
            "--includes",
            "--null",
            "--get-regexp",
            "^.*$",
        ],
        deadline,
        CONFIG_LIMIT,
    )?;
    if !(status.success() || status.code() == Some(1) && output.is_empty()) {
        return None;
    }
    if !safe_worktree_config(&output)? {
        return Some(false);
    }
    let git_dir = git_path(
        &base,
        leading,
        &["rev-parse", "--absolute-git-dir"],
        &cwd,
        deadline,
    )?;
    let common_dir = git_path(
        &base,
        leading,
        &["rev-parse", "--git-common-dir"],
        &cwd,
        deadline,
    )?;
    if !hooks_are_inert(&git_dir.join("hooks")) || !hooks_are_inert(&common_dir.join("hooks")) {
        return Some(false);
    }
    let branch_ref = format!("refs/heads/{branch}");
    let (status, output) = git_query_with_args(
        &base,
        leading,
        &["show-ref", "--verify", "--quiet", &branch_ref],
        deadline,
        WORKTREE_PROBE_LIMIT,
    )?;
    if status.success() {
        return Some(false);
    }
    if status.code() != Some(1) || !output.is_empty() {
        return None;
    }
    let reference = reference.unwrap_or("HEAD");
    let commit_ref = format!("{reference}^{{commit}}");
    let (status, output) = git_query_with_args(
        &base,
        leading,
        &["rev-parse", "--verify", "--quiet", &commit_ref],
        deadline,
        WORKTREE_PROBE_LIMIT,
    )?;
    Some(status.success() && !output.is_empty())
}

pub(super) fn execution_free(
    executable: &str,
    arguments: &[String],
    context: super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> Option<bool> {
    let remaining = crate::command_compatibility::git_inspection_arguments(arguments, context)?;
    let operation = remaining.first()?.as_str();
    if !matches!(operation, "status" | "diff" | "log" | "show") {
        return None;
    }
    Some(
        probe(
            executable,
            arguments,
            remaining,
            operation,
            context,
            deadline,
            execution_environment,
        )
        .unwrap_or(false),
    )
}

pub(super) fn trusted_pipeline_command(
    executable: &str,
    context: super::PathContext<'_>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    let Some(declared_home) = context.home_dir.map(Path::new) else {
        return false;
    };
    let Some(declared_cwd) = context.cwd.map(Path::new) else {
        return false;
    };
    let (Ok(home), Ok(cwd)) = (
        fs::canonicalize(declared_home),
        fs::canonicalize(declared_cwd),
    ) else {
        return false;
    };
    let Some(environment) = execution_environment else {
        return false;
    };
    if !home.is_dir()
        || !cwd.is_dir()
        || !environment.git_config_no_system
        || environment.xdg_config_home.is_some()
        || !clean_environment(Some(environment))
        || environment
            .home
            .as_deref()
            .and_then(|path| fs::canonicalize(path).ok())
            != Some(home.clone())
    {
        return false;
    }
    trusted_command(executable, &home, &cwd, Some(environment)).is_some()
}

fn prepared_git_command(
    executable: &str,
    context: super::PathContext<'_>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> Option<(Command, PathBuf, PathBuf, PathBuf)> {
    let declared_home = Path::new(context.home_dir?);
    let declared_cwd = Path::new(context.cwd?);
    if !declared_home.is_absolute() || !declared_cwd.is_absolute() {
        return None;
    }
    let home = fs::canonicalize(declared_home).ok()?;
    let cwd = fs::canonicalize(declared_cwd).ok()?;
    let environment = execution_environment?;
    if !environment.git_config_no_system
        || environment.xdg_config_home.is_some()
        || !home.is_dir()
        || !cwd.is_dir()
        || !clean_environment(Some(environment))
    {
        return None;
    }
    let binary = trusted_command(executable, &home, &cwd, execution_environment)?;
    let mut command = Command::new(&binary);
    command.env_clear();
    #[cfg(windows)]
    for key in ["SYSTEMROOT", "WINDIR"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    let git_home = Path::new(environment.home.as_deref()?).to_path_buf();
    if !git_home.is_absolute() || fs::canonicalize(&git_home).ok()? != home {
        return None;
    }
    command
        .current_dir(&cwd)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("HOME", &git_home)
        .env("USERPROFILE", &git_home);
    Some((command, binary, cwd, git_home))
}

fn git_query<const N: usize>(
    base: &Command,
    leading: &[String],
    arguments: [&str; N],
    deadline: Instant,
    limit: u64,
) -> Option<(std::process::ExitStatus, Vec<u8>)> {
    let mut command = super::git_probe::copy_command(base)?;
    command.args(leading).args(arguments);
    super::git_probe::output(&mut command, deadline, limit)
}

fn git_query_with_args(
    base: &Command,
    leading: &[String],
    arguments: &[&str],
    deadline: Instant,
    limit: u64,
) -> Option<(std::process::ExitStatus, Vec<u8>)> {
    let mut command = super::git_probe::copy_command(base)?;
    command.args(leading).args(arguments);
    super::git_probe::output(&mut command, deadline, limit)
}

fn git_path(
    base: &Command,
    leading: &[String],
    arguments: &[&str],
    cwd: &Path,
    deadline: Instant,
) -> Option<PathBuf> {
    let (status, output) = git_query_with_args(base, leading, arguments, deadline, 4096)?;
    if !status.success() {
        return None;
    }
    let rendered = std::str::from_utf8(&output).ok()?.trim();
    if rendered.is_empty() || rendered.contains(['\0', '\n', '\r']) {
        return None;
    }
    let path = Path::new(rendered);
    fs::canonicalize(if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    })
    .ok()
}

fn safe_worktree_config(output: &[u8]) -> Option<bool> {
    let output = std::str::from_utf8(output).ok()?;
    for record in output.split('\0').filter(|record| !record.is_empty()) {
        let (key, value) = record.split_once('\n')?;
        let key = key.to_ascii_lowercase();
        if key == "core.bare" && enabled_boolean(value) {
            return Some(false);
        }
        // `worktree add` and each probe below use built-in commands, local
        // refs, and no diff/editor/credential operation. Those unrelated
        // settings are inert for this bounded operation; execution-capable
        // checkout and transport settings remain denied below.
        if key == "core.hookspath"
            || key == "core.worktree"
            || key == "core.fsmonitor"
            || key == "core.sshcommand"
            || key == "core.gitproxy"
            || key == "core.askpass"
            || key == "core.pager"
            || key.starts_with("pager.")
            || key.starts_with("filter.")
            || key.starts_with("include")
            || key.starts_with("extensions.")
            || key.starts_with("submodule.")
            || key.ends_with(".promisor")
            || key.ends_with(".partialclonefilter")
            || key.ends_with(".uploadpack")
            || key.ends_with(".receivepack")
        {
            return Some(false);
        }
    }
    Some(true)
}

fn hooks_are_inert(path: &Path) -> bool {
    const EXECUTABLE_HOOKS: &[&str] = &[
        "post-checkout",
        "post-index-change",
        "reference-transaction",
    ];
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return true,
        Err(_) => return false,
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return false;
    }
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(_) => return false,
    };
    for (count, entry) in entries.enumerate() {
        if count >= 256 {
            return false;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => return false,
        };
        let metadata = match fs::symlink_metadata(entry.path()) {
            Ok(metadata) => metadata,
            Err(_) => return false,
        };
        if metadata.file_type().is_symlink() {
            return false;
        }
        if EXECUTABLE_HOOKS.contains(&entry.file_name().to_string_lossy().as_ref())
            && metadata.is_file()
            && hook_is_executable(&metadata)
        {
            return false;
        }
    }
    true
}

#[cfg(unix)]
fn hook_is_executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn hook_is_executable(metadata: &fs::Metadata) -> bool {
    metadata.is_file()
}

fn probe(
    executable: &str,
    arguments: &[String],
    remaining: &[String],
    operation: &str,
    context: super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> Option<bool> {
    // Configuration plus root, path and attribute inspection share this budget.
    // The caller's overall deadline remains the upper bound.
    let inspection_deadline = Instant::now() + Duration::from_secs(2);
    let deadline = deadline
        .unwrap_or(inspection_deadline)
        .min(inspection_deadline);
    if Instant::now() >= deadline {
        return None;
    }
    let declared_home = Path::new(context.home_dir?);
    let declared_cwd = Path::new(context.cwd?);
    if !declared_home.is_absolute() || !declared_cwd.is_absolute() {
        return None;
    }
    let home = fs::canonicalize(declared_home).ok()?;
    let cwd = fs::canonicalize(declared_cwd).ok()?;
    let leading = &arguments[..arguments.len().checked_sub(remaining.len())?];
    if !home.is_dir() || !cwd.is_dir() || !clean_environment(execution_environment) {
        return None;
    }
    let binary = trusted_command(executable, &home, &cwd, execution_environment)?;
    let mut command = Command::new(&binary);
    command.env_clear();
    #[cfg(windows)]
    for key in ["SYSTEMROOT", "WINDIR"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    if let Some(directory) =
        execution_environment.and_then(|context| context.xdg_config_home.as_deref())
    {
        command.env("XDG_CONFIG_HOME", directory);
    } else if execution_environment.is_none() {
        if let Some(directory) = std::env::var_os("XDG_CONFIG_HOME") {
            command.env("XDG_CONFIG_HOME", directory);
        }
    }
    if execution_environment.is_some_and(|context| context.git_config_no_system) {
        command.env("GIT_CONFIG_NOSYSTEM", "1");
    }
    let git_home = execution_environment
        .and_then(|context| context.home.as_deref())
        .map(Path::new)
        // Git for Windows must see the original home spelling, not the
        // extended-length prefix produced by std::fs::canonicalize.
        .unwrap_or(declared_home);
    command
        .args(leading)
        .current_dir(&cwd)
        .env("HOME", git_home)
        .env("USERPROFILE", git_home);
    let mut query = super::git_probe::copy_command(&command)?;
    let (status, output) = super::git_probe::output(
        query
        .args([
            "--no-pager",
            "config",
            "--null",
            "--get-regexp",
            "^(core\\.fsmonitor|core\\.pager|pager\\..*|diff\\.external|diff\\..*\\.(command|textconv)|filter\\..*\\.(process|clean|smudge)|log\\.showsignature|gpg\\.program|gpg\\..*\\.program|format\\.pretty|pretty\\..*|extensions\\.partialclone|remote\\..*\\.promisor)$",
        ])
,
        deadline, CONFIG_LIMIT,
    )?;
    if !(status.success() || status.code() == Some(1) && output.is_empty()) {
        return None;
    }
    let output = std::str::from_utf8(&output).ok()?;
    let options = remaining
        .iter()
        .skip(1)
        .take_while(|value| value.as_str() != "--");
    // Deliberately conservative: an explicit signature request always needs
    // review, even if a later --no-show-signature would disable it. We do not
    // claim to prove the complete signature-format/helper option grammar.
    if options.clone().any(|value| {
        value.as_str() == "--show-signature"
            || (matches!(operation, "log" | "show") && value.contains("%G"))
            || value.starts_with("--remerge-diff")
            || value == "--diff-merges=remerge"
            || value == "--submodule=diff"
    }) {
        return Some(false);
    }
    let no_external = options
        .clone()
        .filter_map(|value| match value.as_str() {
            "--no-ext-diff" => Some(true),
            "--ext-diff" => Some(false),
            _ => None,
        })
        .last()
        == Some(true);
    let no_textconv = options
        .clone()
        .filter_map(|value| match value.as_str() {
            "--no-textconv" => Some(true),
            "--textconv" => Some(false),
            _ => None,
        })
        .last()
        == Some(true);
    let mut effective = std::collections::BTreeMap::new();
    for record in output.split('\0').filter(|record| !record.is_empty()) {
        let (key, value) = record.split_once('\n')?;
        effective.insert(key, value);
    }
    let pager_key = format!("pager.{operation}");
    let pager_setting = effective.get(pager_key.as_str()).copied();
    let configured_pager = pager_setting.or_else(|| {
        (operation != "status")
            .then(|| effective.get("core.pager").copied())
            .flatten()
    });
    let environment_pager = environment_pager_disabled(execution_environment);
    let git_pager_disabled = git_pager_disabled(execution_environment);
    let no_pager = leading
        .iter()
        .any(|argument| matches!(argument.as_str(), "-P" | "--no-pager"));
    let configured_paging = !no_pager
        && configured_pager.map_or(operation != "status", |value| !disabled_boolean(value));
    let configured_pager_is_cat = configured_pager.is_some_and(|value| value == "cat");
    let paging = configured_paging
        && !configured_pager_is_cat
        && !environment_pager.is_some_and(|disabled| disabled);
    if paging && environment_pager == Some(false) {
        return Some(false);
    }
    // Attribute and index inspection must not trigger lazy partial-clone fetch.
    if effective.iter().any(|(key, value)| {
        (*key == "extensions.partialclone" && !value.is_empty())
            || (key.starts_with("remote.")
                && key.ends_with(".promisor")
                && !disabled_boolean(value))
    }) {
        return Some(false);
    }
    let has_filters = matches!(operation, "status" | "diff")
        && effective
            .iter()
            .any(|(key, value)| key.starts_with("filter.") && !value.is_empty());
    let filters_unused = !has_filters
        || filters::unused(
            &binary,
            leading,
            &cwd,
            git_home,
            execution_environment,
            deadline,
        )?;
    for (key, value) in effective {
        let disabled = disabled_boolean(value);
        let unsafe_value = match key {
            "extensions.partialclone" => !value.is_empty(),
            key if key.starts_with("remote.") && key.ends_with(".promisor") => !disabled,
            "core.fsmonitor" => matches!(operation, "status" | "diff") && !disabled,
            "core.pager" => {
                configured_paging
                    && !git_pager_disabled
                    && pager_setting.is_none_or(enabled_boolean)
                    && !value.is_empty()
                    && value != "cat"
            }
            key if key.starts_with("pager.") => {
                key == pager_key
                    && !git_pager_disabled
                    && !disabled
                    && !value.is_empty()
                    && value != "cat"
                    && if enabled_boolean(value) {
                        paging
                    } else {
                        configured_paging
                    }
            }
            "diff.external" => !no_external && !value.is_empty(),
            key if key.starts_with("diff.") && key.ends_with(".command") => {
                !no_external && !value.is_empty()
            }
            key if key.starts_with("diff.") && key.ends_with(".textconv") => {
                !no_textconv && !value.is_empty()
            }
            key if key.starts_with("filter.") => {
                matches!(operation, "status" | "diff") && !value.is_empty() && !filters_unused
            }
            "format.pretty" => matches!(operation, "log" | "show") && value.contains("%G"),
            key if key.starts_with("pretty.") => {
                matches!(operation, "log" | "show") && value.contains("%G")
            }
            "log.showsignature" => matches!(operation, "log" | "show") && !disabled,
            // Deliberately conservative for custom verification programs:
            // log/show pretty-format aliases may also invoke a GPG helper.
            key if key.starts_with("gpg.") => {
                matches!(operation, "log" | "show") && !value.is_empty()
            }
            _ => return None,
        };
        if unsafe_value {
            return Some(false);
        }
    }
    if matches!(operation, "status" | "diff")
        && !super::git_probe::submodules_are_inert(&command, remaining, deadline)?
    {
        return Some(false);
    }
    Some(true)
}

fn disabled_boolean(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "0" | "false" | "no" | "off"
    )
}

fn enabled_boolean(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "true" | "yes" | "on" | "1"
    )
}

fn environment_pager_disabled(
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> Option<bool> {
    match execution_environment {
        Some(context) => {
            if context
                .environment_names
                .iter()
                .any(|name| name.eq_ignore_ascii_case("GIT_PAGER"))
            {
                Some(context.git_pager_disabled)
            } else if context
                .environment_names
                .iter()
                .any(|name| name.eq_ignore_ascii_case("PAGER"))
            {
                Some(context.pager_disabled)
            } else {
                None
            }
        }
        None => std::env::var_os("GIT_PAGER")
            .map(|value| value.is_empty() || value.to_string_lossy() == "cat")
            .or_else(|| {
                std::env::var_os("PAGER")
                    .map(|value| value.is_empty() || value.to_string_lossy() == "cat")
            }),
    }
}

fn git_pager_disabled(
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    match execution_environment {
        Some(context) => {
            context
                .environment_names
                .iter()
                .any(|name| name.eq_ignore_ascii_case("GIT_PAGER"))
                && context.git_pager_disabled
        }
        None => std::env::var_os("GIT_PAGER")
            .is_some_and(|value| value.is_empty() || value.to_string_lossy() == "cat"),
    }
}

fn clean_environment(
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    let names = match execution_environment {
        Some(context) => {
            let declares_xdg = context
                .environment_names
                .iter()
                .any(|name| name.eq_ignore_ascii_case("XDG_CONFIG_HOME"));
            if declares_xdg != context.xdg_config_home.is_some() {
                return false;
            }
            let declares_no_system = context
                .environment_names
                .iter()
                .any(|name| name.eq_ignore_ascii_case("GIT_CONFIG_NOSYSTEM"));
            if declares_no_system != context.git_config_no_system {
                return false;
            }
            if !context.has_valid_shape() {
                return false;
            }
            context.environment_names.clone()
        }
        None => std::env::vars_os()
            .filter(|(_, value)| !value.is_empty())
            .map(|(name, _)| name.to_string_lossy().into_owned())
            .collect(),
    };
    !names.iter().any(|key| {
        let key = key.to_ascii_uppercase();
        key.starts_with("GIT_TRACE")
            || key.starts_with("DYLD_")
            || key.starts_with("LD_")
            || (key.starts_with("GIT_CONFIG")
                && !(key == "GIT_CONFIG_NOSYSTEM"
                    && execution_environment.is_some_and(|context| context.git_config_no_system)))
            || matches!(
                key.as_str(),
                "GIT_DIR"
                    | "GIT_EXTERNAL_DIFF"
                    | "GIT_COMMON_DIR"
                    | "GIT_INDEX_FILE"
                    | "GIT_OBJECT_DIRECTORY"
                    | "GIT_ALTERNATE_OBJECT_DIRECTORIES"
                    | "GIT_NAMESPACE"
                    | "GIT_REPLACE_REF_BASE"
                    | "GIT_SHALLOW_FILE"
                    | "GIT_WORK_TREE"
                    | "GIT_EXEC_PATH"
                    | "GIT_DISCOVERY_ACROSS_FILESYSTEM"
                    | "LD_PRELOAD"
                    | "LD_LIBRARY_PATH"
                    | "DYLD_INSERT_LIBRARIES"
                    | "DYLD_LIBRARY_PATH"
            )
    })
}

fn trusted_command(
    executable: &str,
    home: &Path,
    cwd: &Path,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> Option<PathBuf> {
    let supplied = Path::new(executable);
    let path = if supplied.components().count() > 1 {
        fs::canonicalize(if supplied.is_absolute() {
            supplied.to_path_buf()
        } else {
            cwd.join(supplied)
        })
        .ok()?
    } else {
        let mut found = None;
        let path = execution_environment
            .map(|context| std::ffi::OsString::from(&context.path))
            .or_else(|| std::env::var_os("PATH"))?;
        for directory in std::env::split_paths(&path) {
            let directory = if directory.is_absolute() {
                directory
            } else {
                cwd.join(directory)
            };
            let command_name = if cfg!(windows) && supplied.extension().is_none() {
                format!("{executable}.exe")
            } else {
                executable.to_owned()
            };
            let candidate = directory.join(command_name);
            if candidate.is_file() {
                found = Some(fs::canonicalize(candidate).ok()?);
                break;
            }
        }
        found?
    };
    let canonical_temp = fs::canonicalize(std::env::temp_dir()).ok();
    if path.starts_with(home)
        || path.starts_with(cwd)
        || path.starts_with(std::env::temp_dir())
        || canonical_temp
            .as_deref()
            .is_some_and(|directory| path.starts_with(directory))
        || path.starts_with("/tmp")
        || path.starts_with("/private/tmp")
    {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let home_metadata = fs::metadata(home).ok()?;
        let owner = home_metadata.uid();
        for ancestor in std::iter::once(path.as_path()).chain(path.ancestors().skip(1)) {
            let metadata = fs::metadata(ancestor).ok()?;
            if metadata.mode() & 0o002 != 0
                || (metadata.mode() & 0o020 != 0
                    && metadata.uid() != owner
                    && metadata.gid() != home_metadata.gid())
                || !matches!(metadata.uid(), uid if uid == 0 || uid == owner)
            {
                return None;
            }
        }
    }
    #[cfg(windows)]
    {
        if !["ProgramFiles", "ProgramFiles(x86)", "SystemRoot"]
            .iter()
            .filter_map(std::env::var_os)
            .filter_map(|root| fs::canonicalize(root).ok())
            .any(|root| path.starts_with(root))
        {
            return None;
        }
    }
    Some(path)
}

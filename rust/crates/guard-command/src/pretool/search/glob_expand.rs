//! Shell glob expansion for read operands, done here component by component.
//!
//! A relative glob expands below the cwd. An absolute or `~/` glob expands
//! below its literal prefix only when that prefix is a directory inside a git
//! working tree below home, the same layout `git -C` and `rg` sibling routes
//! accept. The literal prefix must then be plain: no hidden or `..`
//! components, and no links between the repository root and any match.
use super::{
    home_relative, real_allowed_directory, ReadContext, HAZARDS, MAX_GLOB_ENTRIES,
    MAX_GLOB_MATCHES, MAX_WALK_DEPTH, SECRET_EXTENSIONS,
};
use crate::pretool::search::glob_matches;
use std::path::{Path, PathBuf};

const GLOB_CHARACTERS: [char; 3] = ['*', '?', '['];

/// Expand a glob. `None` when any step is ambiguous: dot components, `..`,
/// links to directories, an absolute or `~` prefix outside a repository below
/// home, or too many matches. A pattern matching nothing is an empty list, so
/// a caller can tell it apart from an unsafe match.
///
/// A component made only of `*` (such as `**`) is expanded as the union of
/// what shells do with it: zero or more nested directories with `globstar`,
/// and a single `*` without it. A wildcard before the last component only
/// descends into directories, as the shell does.
pub(super) fn expand_glob_matches(value: &str, context: ReadContext<'_>) -> Option<Vec<PathBuf>> {
    if value.is_empty()
        || value.len() > 4096
        || value.contains(HAZARDS)
        || value.contains(['{', '}', '#', '^', '(', ')'])
        || value.starts_with('-')
        || !crate::pretool::safe_reads::verified_path_context(context.home_dir, context.cwd)
    {
        return None;
    }
    let (base, root, pattern) = if value.starts_with(['/', '~']) {
        repository_glob_base(value, context)?
    } else {
        let cwd = home_relative(context.cwd?, context.home_dir)?;
        (real_allowed_directory(&cwd, context)?, cwd, value)
    };
    let components: Vec<&str> = pattern
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect();
    let mut current = vec![base];
    let mut inspected = 0_usize;
    for (index, component) in components.iter().enumerate() {
        if *component == ".." || component.starts_with('.') {
            return None;
        }
        let last = index + 1 == components.len();
        let is_pattern = component.contains(GLOB_CHARACTERS);
        let mut next = Vec::new();
        for directory in &current {
            if !is_pattern {
                // The shell keeps only literal continuations that exist.
                let path = directory.join(component);
                let exists = std::fs::symlink_metadata(&path).is_ok();
                if (last && exists) || traversable(&path)? {
                    next.push(path);
                }
                continue;
            }
            if !last && component.len() > 1 && component.bytes().all(|byte| byte == b'*') {
                nested_directories(directory, &mut next, &mut inspected)?;
                continue;
            }
            for entry in std::fs::read_dir(directory).ok()? {
                inspected += 1;
                if inspected > MAX_GLOB_ENTRIES {
                    return None;
                }
                let name = entry.ok()?.file_name();
                let name = name.to_str()?;
                if name.starts_with('.') || !glob_matches(component.as_bytes(), name.as_bytes()) {
                    continue;
                }
                let path = directory.join(name);
                if last || traversable(&path)? {
                    next.push(path);
                }
            }
        }
        if next.len() > MAX_GLOB_MATCHES {
            return None;
        }
        current = next;
    }
    let mut matches = Vec::new();
    for path in current {
        if !screened_match(&path, &root, context)? {
            return None;
        }
        matches.push(path);
    }
    Some(matches)
}

/// Every match is a regular file or a real directory reached through real
/// directories, and clears the sensitive-path and credential-name screens.
/// Credential names are judged below `root`, so the screen covers the literal
/// prefix of a repository glob as well as the expanded part.
fn screened_match(path: &Path, root: &Path, context: ReadContext<'_>) -> Option<bool> {
    let metadata = std::fs::symlink_metadata(path).ok()?;
    if !(metadata.is_dir() || metadata.is_file()) {
        return None;
    }
    // Each intermediate component must be a real directory, never a link.
    let mut ancestor = path.parent();
    while let Some(parent) = ancestor.filter(|parent| parent.starts_with(root) && *parent != root) {
        if !std::fs::symlink_metadata(parent).ok()?.is_dir() {
            return None;
        }
        ancestor = parent.parent();
    }
    let relative = path.strip_prefix(root).ok()?;
    let secret_extension = metadata.is_file()
        && path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| {
                SECRET_EXTENSIONS.contains(&extension.to_ascii_lowercase().as_str())
            });
    Some(
        guard_secure_fs::sensitive_path_family(path).is_none()
            && !guard_secure_fs::credential_named_path(relative)
            && !secret_extension
            && crate::pretool::read_paths::resolved_path_allowed(
                &std::fs::canonicalize(path).ok()?,
                context.home_dir,
                context.cwd,
            ),
    )
}

/// `(base, repository root, pattern)` for an absolute or `~/` glob whose
/// literal prefix is a real directory inside a git working tree below home.
/// Paths outside such a repository, such as home itself or the directory
/// holding several checkouts, are not expanded.
fn repository_glob_base<'a>(
    value: &'a str,
    context: ReadContext<'_>,
) -> Option<(PathBuf, PathBuf, &'a str)> {
    if value.starts_with('~') && !value.starts_with("~/") {
        return None;
    }
    let first_pattern = value.find(GLOB_CHARACTERS)?;
    let prefix_end = value[..first_pattern].rfind('/')?;
    let (prefix, pattern) = (&value[..prefix_end], &value[prefix_end + 1..]);
    // `/*` leaves an empty prefix, which would otherwise resolve to the cwd.
    if !(prefix.starts_with('/') || prefix == "~" || prefix.starts_with("~/"))
        || prefix
            .split('/')
            .skip(1)
            .any(|part| part == ".." || part.starts_with('.'))
    {
        return None;
    }
    let base = super::expanded_operand(prefix, context)?;
    let base = real_allowed_directory(&base, context)?;
    let canonical = std::fs::canonicalize(&base).ok()?;
    if !crate::pretool::git_routes::repository_below_home(&canonical, context)
        || super::inside_agent_state(&base, context)
    {
        return None;
    }
    let root = base
        .ancestors()
        .find(|path| std::fs::symlink_metadata(path.join(".git")).is_ok())?
        .to_path_buf();
    Some((base, root, pattern))
}

/// Whether the shell continues below this path: `Some(true)` for a real
/// directory, `Some(false)` for anything it skips, `None` for a link to a
/// directory, which a shell without `globstar` would follow.
fn traversable(path: &Path) -> Option<bool> {
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return Some(false);
    };
    if metadata.file_type().is_symlink() {
        return std::fs::metadata(path)
            .map_or(Some(false), |target| (!target.is_dir()).then_some(false));
    }
    Some(metadata.is_dir())
}

/// `directory` and every non-hidden real directory below it.
fn nested_directories(
    directory: &Path,
    found: &mut Vec<PathBuf>,
    inspected: &mut usize,
) -> Option<()> {
    let mut pending = vec![(directory.to_path_buf(), 0_usize)];
    while let Some((path, depth)) = pending.pop() {
        if depth > MAX_WALK_DEPTH || found.len() >= MAX_GLOB_MATCHES {
            return None;
        }
        for entry in std::fs::read_dir(&path).ok()? {
            *inspected += 1;
            if *inspected > MAX_GLOB_ENTRIES {
                return None;
            }
            let entry = entry.ok()?;
            let name = entry.file_name();
            if name.to_str()?.starts_with('.') {
                continue;
            }
            let child = entry.path();
            if traversable(&child)? {
                pending.push((child, depth + 1));
            }
        }
        found.push(path);
    }
    Some(())
}

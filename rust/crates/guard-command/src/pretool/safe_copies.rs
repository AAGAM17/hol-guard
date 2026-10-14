//! Plain `cp` operands: one or more readable files copied to a bounded write
//! target. `cp a b dir/` and `cp a dir/` place each file at `dir/<name>`, so
//! every source and every resulting path gets the same screens a single
//! file-to-file copy gets. Flags, recursive copies and directory sources are
//! proven elsewhere or stay reviewed.

use super::super::chain_temporary::absent_temporary_read_target;
use super::super::read_paths::{bounded_file_read_target, expand_home_read_path};
use super::super::PathContext;
use super::{
    bounded_native_file_write_target, bounded_temporary_copy_target, single_link_write_target,
};
use std::path::{Path, PathBuf};

/// More sources than this is not an ordinary hand-written copy.
const MAX_SOURCES: usize = 16;

pub(in crate::pretool) fn safe_copy_arguments(
    arguments: &[String],
    context: PathContext<'_>,
) -> bool {
    let operands = match arguments {
        [separator, rest @ ..] if separator == "--" => rest,
        _ => arguments,
    };
    let Some((destination, sources)) = operands.split_last() else {
        return false;
    };
    if sources.is_empty() || sources.len() > MAX_SOURCES || destination.starts_with('-') {
        return false;
    }
    let expanded =
        expand_home_read_path(destination, context.home_dir).unwrap_or_else(|| destination.clone());
    let Some(resolved) = joined_destination(&expanded, context) else {
        return false;
    };
    // cp places every source inside the destination when it names a
    // directory. With several sources, or a trailing slash, it never writes
    // the destination path itself.
    let into_directory = sources.len() > 1 || expanded.ends_with('/') || resolved.is_dir();
    let absolute = Path::new(&expanded).is_absolute();
    sources.iter().all(|source| {
        let target = if into_directory {
            match Path::new(source).file_name() {
                Some(name) => resolved.join(name),
                None => return false,
            }
        } else {
            resolved.clone()
        };
        source_allowed(source, context) && target_allowed(&target, absolute, context)
    })
}

fn joined_destination(expanded: &str, context: PathContext<'_>) -> Option<PathBuf> {
    let destination = Path::new(expanded);
    if destination.is_absolute() {
        return Some(destination.to_path_buf());
    }
    let cwd = context.cwd?;
    let cwd = expand_home_read_path(cwd, context.home_dir).unwrap_or_else(|| cwd.to_owned());
    Some(Path::new(&cwd).join(destination))
}

fn source_allowed(source: &str, context: PathContext<'_>) -> bool {
    !source.starts_with('-')
        && source.trim() == source
        && (bounded_file_read_target(source, context.home_dir, context.cwd)
            || absent_temporary_read_target(source, context.home_dir, context.cwd))
}

/// cp follows a destination link, so the resulting path must not be one and
/// must not alias a protected inode through a hard link.
fn target_allowed(target: &Path, absolute: bool, context: PathContext<'_>) -> bool {
    let Some(text) = target.to_str() else {
        return false;
    };
    !target
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
        && single_link_write_target(target)
        && (bounded_native_file_write_target(text, context.home_dir, context.cwd)
            // The temporary carve-out is only for destinations the user
            // spelled absolutely. A relative destination joined onto a /tmp
            // workspace must not sidestep the workspace boundary check above.
            || (absolute && bounded_temporary_copy_target(text, context)))
}

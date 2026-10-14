//! A copy into a directory created earlier in the same chain:
//! `mkdir -p src/lib/notes && cp /tmp/checkout/README.md src/lib/notes/`.
//!
//! Each `cp` segment is still proven on its own against the files on disk, so
//! the only thing an earlier `mkdir` can change is whether a destination is a
//! directory. With several sources or a trailing slash, cp never writes the
//! destination path itself, and the proof already checked `<dir>/<name>`. A
//! single source without a trailing slash is only accepted when every `mkdir`
//! target in the chain is the destination's parent or one of its ancestors,
//! byte for byte. Matching names instead would miss case-insensitive or
//! normalization-insensitive volumes, where `mkdir -p src/Sub` makes
//! `src/sub` a directory and the copy lands on a name the proof never saw.
//! Every directory such a chain creates sits strictly above the destination,
//! so none of them can be the destination itself. `mkdir` creates real
//! directories, never links, so the resolved location of every later target
//! stays the one the proof saw. Only plain peers may share the chain: nothing
//! changes directory, renames, links or removes files.

use crate::{CanonicalCommandV1, CommandSegmentV1};
use std::path::{Path, PathBuf};

/// Two or more segments, at least one `mkdir`, and every other segment a
/// plain chain peer.
pub(in crate::pretool) fn mkdir_chain(model: &CanonicalCommandV1) -> bool {
    model.segments.len() > 1
        && super::plain_chain(model, &["mkdir"])
        && model
            .segments
            .iter()
            .any(|segment| segment.executable.as_deref() == Some("mkdir"))
}

/// A `cp` segment in a [`mkdir_chain`] whose destination no `mkdir` in the
/// chain can turn into a directory the proof did not see, however the volume
/// compares names.
pub(super) fn copies_beside_mkdir(
    model: &CanonicalCommandV1,
    segment: &CommandSegmentV1,
    context: super::super::PathContext<'_>,
) -> bool {
    mkdir_chain(model) && destination_settled(model, segment, context)
}

fn destination_settled(
    model: &CanonicalCommandV1,
    segment: &CommandSegmentV1,
    context: super::super::PathContext<'_>,
) -> bool {
    let operands = match segment.arguments.as_slice() {
        [separator, rest @ ..] if separator == "--" => rest,
        operands => operands,
    };
    // Flagged copies (recursive, archive, link-making) stay out of the chain.
    if operands.iter().any(|operand| operand.starts_with('-')) {
        return false;
    }
    let Some((destination, sources)) = operands.split_last() else {
        return false;
    };
    if sources.len() > 1 || destination.ends_with('/') {
        return true;
    }
    let Some(destination) = resolved(destination, context) else {
        return false;
    };
    let Some(parent) = destination.parent() else {
        return false;
    };
    model
        .segments
        .iter()
        .filter(|peer| peer.executable.as_deref() == Some("mkdir"))
        .flat_map(|peer| peer.arguments.iter())
        .filter(|argument| !argument.starts_with('-'))
        .all(|target| resolved(target, context).is_some_and(|target| parent.starts_with(target)))
}

/// The absolute location a path names once missing parts are created: the
/// canonical deepest existing ancestor plus the missing parts. `..` parts and
/// dangling links are refused, so every missing part is a plain name.
fn resolved(value: &str, context: super::super::PathContext<'_>) -> Option<PathBuf> {
    if value.split(['/', '\\']).any(|part| part == "..") {
        return None;
    }
    let expanded = super::super::read_paths::expand_home_read_path(value, context.home_dir)
        .unwrap_or_else(|| value.to_owned());
    let path = Path::new(&expanded);
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        let cwd = context.cwd?;
        let cwd = super::super::read_paths::expand_home_read_path(cwd, context.home_dir)
            .unwrap_or_else(|| cwd.to_owned());
        Path::new(&cwd).join(path)
    };
    let mut missing = Vec::new();
    let mut existing = absolute.as_path();
    while existing.symlink_metadata().is_err() {
        let name = existing.file_name()?;
        missing.push(name.to_owned());
        existing = existing.parent()?;
    }
    let mut canonical = existing.canonicalize().ok()?;
    for name in missing.iter().rev() {
        canonical.push(name);
    }
    Some(canonical)
}

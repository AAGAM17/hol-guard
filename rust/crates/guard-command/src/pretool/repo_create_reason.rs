//! `gh repo create` with public or internal visibility, or with `--push`,
//! stays at review: publishing a repository discloses the workspace, and gh's
//! own push runs outside the proof that admits a plain `git push`. Agents
//! asked to "put it on GitHub" usually reach for `--public --push` and, given
//! only the generic reason, stop. When the same command made private and
//! without `--push` would run without review, say so.

use crate::github_command_capabilities::private_repo_create;
use crate::{CanonicalCommandV1, CommandSegmentV1};

/// Options the private alternative drops; `--private` replaces the first two.
const DROPPED: &[&str] = &["--public", "--internal", "--push"];

/// Whether `gh` arguments create a private repository in the user's own
/// account. That publishes nothing and pushes nothing: the workspace reaches
/// the new repository only through a separate, separately proven `git push`.
pub(super) fn private_create(arguments: &[String]) -> bool {
    matches!(arguments, [repo, create, rest @ ..]
        if repo == "repo" && create == "create" && private_repo_create(rest))
}

/// A review reason naming the private alternative, or `None` when it does not
/// apply. In a chain, the other steps are named as separate commands, since
/// repeating the whole chain with `--private` would still go to review.
pub(super) fn private_alternative_reason(model: &CanonicalCommandV1) -> Option<String> {
    if model.confidence != "exact" || model.path_overridden || !model.wrapper_chain.is_empty() {
        return None;
    }
    let reason_tail = |push: &str| {
        format!(
            "Creating it private runs without review: repeat that `gh repo create` with `--private` in place of `--public`, `--internal` or `--push`{push}. If the user wants it public, tell them they can change its visibility."
        )
    };
    if let [segment] = model.segments.as_slice() {
        let push = private_alternative(segment)?;
        return Some(format!(
            "HOL Guard requires review because this `gh repo create` publishes the repository or pushes with gh itself. {}",
            reason_tail(push)
        ));
    }
    // Split into separate commands, steps after a `cd` would run elsewhere.
    if model
        .segments
        .iter()
        .any(|segment| matches!(segment.executable.as_deref(), Some("cd" | "pushd")))
    {
        return None;
    }
    let mut creates = model
        .segments
        .iter()
        .enumerate()
        .filter_map(|(index, segment)| private_alternative(segment).map(|push| (index, push)));
    let (index, push) = creates.next()?;
    if creates.next().is_some() {
        return None;
    }
    Some(format!(
        "HOL Guard requires review because step {} of this command runs a `gh repo create` that publishes the repository or pushes with gh itself. Run the other steps as separate commands. {}",
        index + 1,
        reason_tail(push)
    ))
}

/// The push hint for a public, internal or pushing `gh repo create` segment
/// whose private form would run without review, or `None`.
fn private_alternative(segment: &CommandSegmentV1) -> Option<&'static str> {
    let executable = segment.executable.as_deref()?;
    let [repo, create, tail @ ..] = segment.arguments.as_slice() else {
        return None;
    };
    if repo != "repo"
        || create != "create"
        || !segment.environment_names.is_empty()
        || super::executable_basename(executable) != "gh"
    {
        return None;
    }
    // Already private and not pushing: there is nothing different to suggest.
    if tail.iter().any(|argument| argument == "--private")
        && !tail
            .iter()
            .any(|argument| DROPPED.contains(&argument.as_str()))
    {
        return None;
    }
    let mut alternative: Vec<String> = tail
        .iter()
        .filter(|argument| !DROPPED.contains(&argument.as_str()))
        .cloned()
        .collect();
    if !alternative.iter().any(|argument| argument == "--private") {
        alternative.push("--private".to_owned());
    }
    if !private_repo_create(&alternative) {
        return None;
    }
    Some(if tail.iter().any(|argument| argument == "--push") {
        ", then push with `git push -u origin <branch>`"
    } else {
        ""
    })
}

#[cfg(test)]
#[path = "repo_create_reason_tests.rs"]
mod tests;

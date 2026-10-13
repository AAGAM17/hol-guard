//! Local Git writes that keep every change reachable: `git add`, a non-forced
//! `git rm`, `git commit -m`, a new branch at `HEAD`, a non-forced branch
//! rename and a plain stash push.
//! The workspace sandbox runs them in a main checkout, but a linked worktree
//! keeps its index, refs and objects in the shared Git directory the sandbox
//! cannot write, and some hosts have no sandbox, so they would stop at review.
//! Here the session's own Git is proven to start no program: no filter other
//! than the user's Git LFS install, no fsmonitor, signing, diff program,
//! lazy fetch, submodule recursion or configured hook, and none of the hook
//! files the command runs. `git rm` without `-f` refuses a file that differs
//! from `HEAD`, and a commit, branch or stash only adds history. `git commit
//! --amend` replaces the local tip, but the reflog still reaches the old
//! commit, and rewriting what a remote holds still needs a reviewed forced
//! push. `git add -f` stays reviewed: it is how an ignored secret file gets
//! staged. `git branch -M` stays reviewed: it overwrites an existing branch.

use super::git_remote_config::GitConfig;
use super::git_session_probe::Probe;
use crate::{CanonicalCommandV1, CommandSegmentV1};
use guard_contracts::{GuardExecutionEnvironmentV1, PreToolActionTypeV1, PreToolResultV1};
use std::time::Instant;

pub(crate) const REASON: &str = "native_exact_safe_git_local_write";

/// The declarative review rules these forms may settle.
const RULES: &[&str] = &[
    "command.git.add",
    "command.git.rm",
    "command.git.commit",
    "command.git.branch",
    "command.git.switch",
    "command.git.checkout",
    "command.git.stash",
];

/// Read rules the packaged catalog ships disabled, so they never raise a
/// review of their own.
const READ_RULES: &[&str] = &[
    "command.git.status",
    "command.git.log",
    "command.git.diff",
    "command.git.show",
    "command.git.ls-files",
];

const INDEX_HOOKS: &[&str] = &["post-index-change"];
const COMMIT_HOOKS: &[&str] = &[
    "pre-commit",
    "prepare-commit-msg",
    "commit-msg",
    "post-commit",
    "post-rewrite",
    "post-index-change",
    "reference-transaction",
    "pre-auto-gc",
];
const BRANCH_HOOKS: &[&str] = &["reference-transaction"];
const CHECKOUT_HOOKS: &[&str] = &[
    "post-checkout",
    "post-index-change",
    "reference-transaction",
];

/// Turn a generic review whose only matched rules are the ones above into an
/// allow when every write segment is proven and every other segment is
/// benign on its own.
pub(super) fn settle(
    result: &mut PreToolResultV1,
    pre_floor: &(String, String),
    model: Option<&CanonicalCommandV1>,
    context: super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&GuardExecutionEnvironmentV1>,
) {
    let reviewable = |reason: &str| {
        matches!(
            reason,
            "native_command_review_required" | "native_command_extension_review"
        )
    };
    let generic = reviewable(&result.reason_code) && result.minimum_action == "review";
    // The Git floor stands for helpers the configuration could start; the
    // probe below proves that none can.
    let git_floor = result.reason_code == "native_git_execution_context_review"
        && pre_floor.1 == "review"
        && (reviewable(&pre_floor.0) || pre_floor.0 == "native_git_helper_context_review");
    if !(generic || git_floor)
        || result.action.action_type != PreToolActionTypeV1::Command
        || result.action.sensitive_target
    {
        return;
    }
    let Some(model) = model else {
        return;
    };
    if !proven(result, model, context, deadline, execution_environment) {
        return;
    }
    result.minimum_action = "allow".into();
    result.policy_action = "allow".into();
    result.decision = "allow".into();
    result.explicitly_benign = true;
    result.reason_code = REASON.into();
    result.reason = concat!(
        "The Rust command authority proved this Git command only updates the local ",
        "repository, keeps every change reachable, and starts no configured program or hook.",
    )
    .into();
}

fn proven(
    result: &PreToolResultV1,
    model: &CanonicalCommandV1,
    context: super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&GuardExecutionEnvironmentV1>,
) -> bool {
    let Some(extensions) = result.command_extensions.as_ref() else {
        return false;
    };
    if model.confidence != "exact"
        || model.path_overridden
        || !model.wrapper_chain.is_empty()
        || extensions.binding.uncertainty_count != 0
        || extensions.evaluation_error.is_some()
        || !extensions.permission_observations.is_empty()
    {
        return false;
    }
    let cwd_proof = model
        .segments
        .iter()
        .position(|segment| segment.executable.as_deref() == Some("cd"))
        .and_then(|cd_index| {
            super::worktree_add::verified_worktree_cwd_context(model, cd_index, context)
        });
    let context = super::PathContext {
        cwd: cwd_proof
            .as_ref()
            .map(|proof| proof.cwd.as_str())
            .or(context.cwd),
        ..context
    };
    let mut writes: Vec<(usize, &'static [&'static str])> = Vec::new();
    let mut safe = Vec::new();
    for (index, segment) in model.segments.iter().enumerate() {
        if segment.executable.as_deref() == Some("cd") {
            if cwd_proof
                .as_ref()
                .is_none_or(|proof| proof.cd_index != index)
            {
                return false;
            }
            continue;
        }
        if let Some(hooks) = write_hooks(segment) {
            writes.push((index, hooks));
            continue;
        }
        if !super::segment_proof::exact_safe_segment_with_context(model, segment, false, context) {
            return false;
        }
        safe.push(index);
    }
    let written = |index: &usize| writes.iter().any(|(write, _)| write == index);
    // Off-by-default read rules (`command.git.status`) still record what they
    // matched; on a segment proven above they add nothing to review.
    let inert_match = |observation: &guard_contracts::NativeCommandObservationV1| {
        READ_RULES.contains(&observation.rule_id.as_str())
            && !observation.effective_segment_indexes.is_empty()
            && observation
                .matcher_evidence
                .iter()
                .map(|evidence| evidence.segment_index)
                .chain(observation.effective_segment_indexes.iter().copied())
                .all(|index| safe.contains(&index))
    };
    if writes.is_empty()
        || !extensions.observations.iter().all(|observation| {
            if observation.uncertainty_reasons.is_empty() && inert_match(observation) {
                return true;
            }
            let mut indexes = observation
                .matcher_evidence
                .iter()
                .map(|evidence| evidence.segment_index)
                .chain(observation.effective_segment_indexes.iter().copied())
                .peekable();
            observation.uncertainty_reasons.is_empty()
                && RULES.contains(&observation.rule_id.as_str())
                && indexes.peek().is_some()
                && indexes.all(|index| written(&index))
        })
    {
        return false;
    }
    let Some(probe) = Probe::new("git", &[], context, deadline, execution_environment) else {
        return false;
    };
    let Some((effective, repository)) = probe.config() else {
        return false;
    };
    inert(&effective, &repository) && writes.iter().all(|(_, hooks)| probe.hooks_inert(hooks))
}

/// The hooks a proven write form runs, or `None` when `original` is not one.
/// Leading Git options such as `-c` or `-C` are refused: they can point the
/// command at another repository or configuration.
fn write_hooks(original: &CommandSegmentV1) -> Option<&'static [&'static str]> {
    let stripped = super::segment_proof::without_stderr_merge(original);
    let segment = stripped.as_ref().unwrap_or(original);
    if segment.executable.as_deref() != Some("git")
        || segment.pipeline_index != 0
        || segment.path_overridden
        || !segment.wrapper_chain.is_empty()
        || !segment.environment_names.is_empty()
        || segment.text.contains(['>', '<', '$', '`', '\n', '\r'])
    {
        return None;
    }
    let words: Vec<&str> = segment.arguments.iter().map(String::as_str).collect();
    match words.split_first()? {
        (&"add", rest) => add(rest).then_some(INDEX_HOOKS),
        (&"rm", rest) => rm(rest).then_some(INDEX_HOOKS),
        (&"commit", rest) => commit(rest).then_some(COMMIT_HOOKS),
        (&"branch", rest) => branch_rename(rest).then_some(BRANCH_HOOKS),
        _ => super::workspace_contained::keeping_arguments(&segment.arguments)
            .then_some(CHECKOUT_HOOKS),
    }
}

/// Options `allowed` accepts, then pathspecs, with `--` ending the options.
fn pathspecs(rest: &[&str], allowed: impl Fn(&str) -> bool) -> bool {
    let mut options = true;
    rest.iter().all(|word| {
        if options && *word == "--" {
            options = false;
            true
        } else if options && word.starts_with('-') {
            allowed(word)
        } else {
            !word.is_empty()
        }
    })
}

fn add(rest: &[&str]) -> bool {
    pathspecs(rest, |option| {
        matches!(
            option,
            "-A" | "--all"
                | "-u"
                | "--update"
                | "-v"
                | "--verbose"
                | "-n"
                | "--dry-run"
                | "-N"
                | "--intent-to-add"
                | "--ignore-errors"
        )
    })
}

fn rm(rest: &[&str]) -> bool {
    pathspecs(rest, |option| {
        matches!(
            option,
            "-q" | "--quiet" | "-r" | "--cached" | "-n" | "--dry-run" | "--ignore-unmatch"
        )
    })
}

/// A commit whose message is on the command line, so no editor starts.
fn commit(rest: &[&str]) -> bool {
    let (mut message, mut amend, mut no_edit) = (false, false, false);
    let mut options = true;
    let mut words = rest.iter();
    while let Some(word) = words.next() {
        if !options || !word.starts_with('-') {
            if word.is_empty() {
                return false;
            }
            continue;
        }
        match *word {
            "--" => options = false,
            "-m" | "--message" | "-am" => {
                if words.next().is_none() {
                    return false;
                }
                message = true;
            }
            value if value.starts_with("--message=") => message = true,
            value if value.len() > 2 && value.starts_with("-m") => message = true,
            "-q" | "--quiet" | "-a" | "--all" | "-s" | "--signoff" | "-n" | "--no-verify"
            | "--allow-empty" | "--no-gpg-sign" => {}
            "--amend" => amend = true,
            "--no-edit" => no_edit = true,
            _ => return false,
        }
    }
    message || (amend && no_edit)
}

/// `branch -m NEW` or `branch -m OLD NEW`, options first. A rename moves the
/// ref with its reflog and refuses an existing target, so nothing becomes
/// unreachable. `-M`, `--force`, a copy and every other option are refused.
fn branch_rename(rest: &[&str]) -> bool {
    let mut moved = false;
    let mut names = Vec::new();
    for word in rest {
        match *word {
            "-m" | "--move" if !moved && names.is_empty() => moved = true,
            "-q" | "--quiet" if names.is_empty() => {}
            name if super::worktree_add::valid_branch_name(name) => names.push(name),
            _ => return false,
        }
    }
    moved && matches!(names.len(), 1 | 2)
}

/// Whether the effective configuration lets these writes start no program.
pub(in crate::pretool) fn inert(effective: &GitConfig, repository: &GitConfig) -> bool {
    !super::git_remote_ops::pull::repository_lfs_program(repository)
        && !effective.iter().any(|(key, values)| {
            let enabled = values
                .iter()
                .any(|value| !super::git_remote_ops::pull::disabled(value));
            (key.starts_with("filter.")
                && (!super::git_remote_ops::pull::standard_lfs(key, values)
                    || repository.contains_key(key)))
                || key.starts_with("hook.")
                || key == "core.worktree"
                || key == "core.virtualfilesystem"
                || key == "diff.external"
                || key == "extensions.partialclone"
                || (key.starts_with("diff.")
                    && (key.ends_with(".textconv") || key.ends_with(".command")))
                || (key.starts_with("trailer.")
                    && (key.ends_with(".command") || key.ends_with(".cmd")))
                || (key.starts_with("remote.") && key.ends_with(".promisor") && enabled)
                || (matches!(
                    key.as_str(),
                    "core.fsmonitor" | "commit.gpgsign" | "submodule.recurse"
                ) && enabled)
        })
}

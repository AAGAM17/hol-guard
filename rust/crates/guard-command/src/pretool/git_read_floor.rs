//! The Git execution-context floor for reads the native proofs allowed.
//!
//! A Git read can run a configured pager, diff driver or textconv helper. The
//! configuration probe proves a single read helper-free; a read later in a
//! compound command keeps that proof only when nothing before it could have
//! changed the configuration it reads.
use crate::CanonicalCommandV1;
use std::time::Instant;

/// Whether a Git read in the command needs review before it runs.
pub(super) fn requires_review(
    model: &CanonicalCommandV1,
    context: super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    // A proven read prefix holds no Git segment and changes nothing a later
    // read depends on, so the floor judges the command from its `cd` onward.
    if let Some(rest) = super::segment_proof::after_read_prefix(model, context) {
        return requires_review(&rest, context, deadline, execution_environment);
    }
    let destination = super::segment_proof::verified_cwd_compound_context(model, context);
    let read_context = super::PathContext {
        cwd: destination.as_deref().or(context.cwd),
        ..context
    };
    let benign = super::segment_proof::benign_command_segments(model, context);
    // `git merge-base ... | xargs git log` runs its Git read as the child, so
    // that stage is judged as the Git command it runs.
    let children: Vec<Option<crate::CommandSegmentV1>> = (0..model.segments.len())
        .map(|index| super::fanout_reads::git_xargs_child(model, index))
        .collect();
    let segments: Vec<&crate::CommandSegmentV1> = model
        .segments
        .iter()
        .zip(&children)
        .map(|(segment, child)| child.as_ref().unwrap_or(segment))
        .collect();
    // A trailing `2>&1` is a redirect, not a Git argument.
    let arguments: Vec<Vec<String>> = segments
        .iter()
        .map(|segment| {
            super::segment_proof::without_stderr_merge(segment)
                .map_or_else(|| segment.arguments.clone(), |stripped| stripped.arguments)
        })
        .collect();
    let inspections: Vec<Option<bool>> = segments
        .iter()
        .enumerate()
        .map(|(index, segment)| {
            segment
                .executable
                .as_deref()
                .filter(|executable| super::executable_basename(executable) == "git")
                .and_then(|executable| {
                    super::git_config::execution_free(
                        executable,
                        &arguments[index],
                        read_context,
                        deadline,
                        execution_environment,
                        super::git_helper_context::stdout_piped(model, index),
                    )
                })
        })
        .collect();
    // Exact models carry no file redirects, and a proof admits a file writer
    // only as the whole command, so a proven segment before a read wrote
    // nothing. Its own read may still lack the path proof that `benign`
    // needs (a bare `ls`); that is decided separately.
    let write_free = |segment: &crate::CommandSegmentV1| {
        model.confidence == "exact"
            && !model.path_overridden
            && model.wrapper_chain.is_empty()
            && !segment.path_overridden
            && segment.wrapper_chain.is_empty()
            && super::segment_proof::exact_safe_segment_with_context(
                model,
                segment,
                false,
                read_context,
            )
    };
    // A proven Git read or `origin` fetch writes no configuration, so it
    // cannot change what a later read in the same command would run.
    let settled = |prior: usize| {
        let segment = segments[prior];
        benign.contains(&prior)
            || write_free(segment)
            || super::git_remote_ops::verified_fetch(segment, read_context)
            || super::git_remote_ops::verified_fetch(segment, context)
            || (inspections[prior] == Some(true)
                && segment.environment_names.is_empty()
                && (super::git_reads::safe_git_arguments(&arguments[prior], true, read_context)
                    || super::git_reads::inspection_writes_nothing(
                        &arguments[prior],
                        read_context,
                    )))
    };
    segments.iter().enumerate().any(|(index, segment)| {
        segment.executable.as_deref().is_some_and(|executable| {
            if super::executable_basename(executable) != "git" {
                return false;
            }
            let inspection = inspections[index];
            // Inert names (`CI`, `LANG`, ...) change no Git behavior, so the
            // segment keeps its own permission decision.
            segment
                .environment_names
                .iter()
                .any(|name| !crate::command_compatibility::inert_environment_name(name))
                || !super::directory_targets::drive_targets_quoted(segment)
                || inspection == Some(false)
                // Only inspection operations have a configuration proof to
                // invalidate. Other Git operations retain their own native
                // review/permission floors, not this read floor.
                || (inspection.is_some() && index > 0 && (0..index).any(|prior| !settled(prior)))
        })
    })
}

//! The argument forms of the local Git writes `git_local_writes` proves:
//! `add`, a non-forced `rm`, `commit` with its message on the command line
//! and a non-forced `branch` rename.

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

pub(super) fn add(rest: &[&str]) -> bool {
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

pub(super) fn rm(rest: &[&str]) -> bool {
    pathspecs(rest, |option| {
        matches!(
            option,
            "-q" | "--quiet" | "-r" | "--cached" | "-n" | "--dry-run" | "--ignore-unmatch"
        )
    })
}

/// A commit whose message is on the command line, so no editor starts.
pub(super) fn commit(rest: &[&str]) -> bool {
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
pub(super) fn branch_rename(rest: &[&str]) -> bool {
    let mut moved = false;
    let mut names = Vec::new();
    for word in rest {
        match *word {
            "-m" | "--move" if !moved && names.is_empty() => moved = true,
            "-q" | "--quiet" if names.is_empty() => {}
            name if super::super::worktree_add::valid_branch_name(name) => names.push(name),
            _ => return false,
        }
    }
    moved && matches!(names.len(), 1 | 2)
}

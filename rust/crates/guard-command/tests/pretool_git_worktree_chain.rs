#![cfg(unix)]

use crate::git_helper_fixture as fixture;
use fixture::{evaluate_pre_tool_envelope_with_context, FixtureCleanup};
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

fn evaluate(home: &Path, cwd: &Path, command: &str) -> guard_contracts::PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name":"bash", "tool_input":{"command":command}}),
        Some(&fixture::github_controls("enabled")),
        None,
        home.to_str(),
        cwd.to_str(),
    )
}

fn directory(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn git(home: &Path, repository: &Path, arguments: &[&str]) {
    assert!(std::process::Command::new("git")
        .arg("-C")
        .arg(repository)
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_COMMON_DIR")
        .args(arguments)
        .status()
        .unwrap()
        .success());
}

/// `org/app` below a fresh home, with a remote-tracking `origin/main`, a
/// sibling repository and a symlink beside it that leads out of `org`.
fn repository(name: &str) -> (FixtureCleanup, PathBuf, PathBuf) {
    let unique = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let root = std::fs::canonicalize("/tmp")
        .unwrap()
        .join(format!("guard-worktree-{name}-{unique}"));
    let cleanup = FixtureCleanup(root.clone());
    let home = root.join("home");
    let organization = home.join("org");
    let repository = organization.join("app");
    for path in [&root, &home, &organization, &repository] {
        directory(path);
    }
    git(
        &home,
        &repository,
        &["init", "--quiet", "--initial-branch=main"],
    );
    git(
        &home,
        &repository,
        &["config", "user.name", "Guard Fixture"],
    );
    git(
        &home,
        &repository,
        &["config", "user.email", "guard-fixture@example.invalid"],
    );
    std::fs::write(repository.join("tracked.txt"), "fixture\n").unwrap();
    git(&home, &repository, &["add", "tracked.txt"]);
    git(&home, &repository, &["commit", "--quiet", "-m", "fixture"]);
    git(
        &home,
        &repository,
        &["update-ref", "refs/remotes/origin/main", "HEAD"],
    );
    let sibling = organization.join("service");
    directory(&sibling);
    git(&home, &sibling, &["init", "--quiet"]);
    directory(&root.join("elsewhere"));
    std::os::unix::fs::symlink(root.join("elsewhere"), organization.join("link")).unwrap();
    (cleanup, home, repository)
}

fn assert_allowed(home: &Path, cwd: &Path, command: &str) {
    let result = evaluate(home, cwd, command);
    assert_eq!(
        result.minimum_action, "allow",
        "{command}: {}",
        result.reason_code
    );
}

fn assert_reviewed(home: &Path, cwd: &Path, command: &str) {
    let result = evaluate(home, cwd, command);
    assert_ne!(result.minimum_action, "allow", "{command}");
}

/// Without `-b` Git checks the reference out detached and creates no branch.
#[test]
fn detached_worktree_add_needs_a_reference() {
    let (_cleanup, home, repository) = repository("detached");
    for command in [
        "git worktree add ../app-review origin/main",
        "git worktree add ../app-review refs/heads/main",
        "git worktree add --detach ../app-review origin/main",
    ] {
        assert_allowed(&home, &repository, command);
    }
    for command in [
        // Git names a new branch after the directory.
        "git worktree add ../app-review",
        "git worktree add -b review --detach ../app-review origin/main",
        "git worktree add ../service origin/main",
        "git worktree add ../link/review origin/main",
        "git worktree add ../app-review origin/main~1",
    ] {
        assert_reviewed(&home, &repository, command);
    }
}

/// Reads in the checkout the command itself creates share the repository's
/// proven configuration.
#[test]
fn reads_in_the_new_worktree_are_allowed() {
    let (_cleanup, home, repository) = repository("chain");
    for command in [
        "git worktree add -b flat ../app-flat origin/main && cd ../app-flat && git log --oneline -3 && git status",
        "git worktree add ../app-flat origin/main && cd ../app-flat && git status --short",
        "git worktree add -b flat ../app-flat origin/main && cd ../app-flat && git log --oneline | head -5",
        "git worktree add -b flat ../app-flat origin/main && cd ../app-flat; git diff --stat",
    ] {
        assert_allowed(&home, &repository, command);
    }
}

/// Writes, pushes, other directories and paths outside the checkout keep
/// their review.
#[test]
fn other_work_in_the_new_worktree_stays_reviewed() {
    let (_cleanup, home, repository) = repository("chain-reviewed");
    let add = "git worktree add -b flat ../app-flat origin/main";
    for tail in [
        "cd ../app-flat && git commit --allow-empty -m wip",
        "cd ../app-flat && git push origin flat",
        "cd ../app-flat && git config core.hooksPath hooks",
        "cd ../app-flat && git -c core.fsmonitor=true status",
        "cd ../app-flat && git -C ../service status",
        "cd ../app-flat && git log -- ../service",
        "cd ../app-flat && git diff --no-index tracked.txt other.txt",
        "cd ../app-flat && ls",
        "cd ../app-flat && git status || git push origin flat",
        "cd ../app-flat && git status & git status",
        "cd ../service && git status && git commit --allow-empty -m wip",
        "cd .. && git status",
        "cd ../app-flat/.. && git status",
    ] {
        assert_reviewed(&home, &repository, &format!("{add} && {tail}"));
    }
    for command in [
        "git worktree add -b flat ../service origin/main && cd ../service && git status",
        "git worktree add -b flat ../link/flat origin/main && cd ../link/flat && git status",
        "git worktree add -b flat ../app-flat origin/main; cd ../app-flat && git status",
        "git worktree add -b flat ../app-flat origin/main && git status && cd ../app-flat",
        "rm -rf ../app-flat && git worktree add -b flat ../app-flat origin/main && cd ../app-flat && git status",
    ] {
        assert_reviewed(&home, &repository, command);
    }
}

/// With `git -C`, a failed `cd` leaves the shell in a directory the proof
/// never read, so a read after `;` stays reviewed.
#[test]
fn fallback_reads_after_a_routed_add_stay_reviewed() {
    let (_cleanup, home, repository) = repository("chain-routed");
    let organization = repository.parent().unwrap();
    let destination = organization.join("app-flat");
    let (repository_text, destination) = (repository.display(), destination.display());
    assert_reviewed(
        &home,
        organization,
        &format!(
            "git -C {repository_text} worktree add -b flat {destination} origin/main && cd {destination}; git log --oneline -3"
        ),
    );
}

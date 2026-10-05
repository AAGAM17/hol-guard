#!/usr/bin/env bash
# Build coverage-instrumented native evaluators for Python-driven integration shards.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root/rust"
toolchain="$(python -c 'import tomllib; print(tomllib.load(open("rust-toolchain.toml", "rb"))["toolchain"]["channel"])')"
coverage_version="0.6.21"

rustup component add --toolchain "$toolchain" llvm-tools-preview
if [[ "$(cargo +"$toolchain" llvm-cov --version 2>/dev/null || true)" != "cargo-llvm-cov $coverage_version" ]]; then
    cargo +"$toolchain" install cargo-llvm-cov --version "=$coverage_version" --locked --force
fi

export CARGO_TARGET_DIR="$repo_root/rust/target/native-coverage"
# cargo-llvm-cov documents show-env for external tests that execute cargo-built binaries.
# Use the same instrumentation contract here and in Sonar's final report job.
source <(cargo +"$toolchain" llvm-cov show-env --export-prefix)
cargo +"$toolchain" llvm-cov clean --workspace
cargo +"$toolchain" build --locked --release     -p guard-command -p hol-guard-runtime     --bin guard-command-source --bin hol-guard-runtime

test -x "$CARGO_TARGET_DIR/release/guard-command-source"
test -x "$CARGO_TARGET_DIR/release/hol-guard-runtime"

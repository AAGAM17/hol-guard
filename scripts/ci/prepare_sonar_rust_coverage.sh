#!/usr/bin/env bash
# Generate Rust coverage from this checkout plus Python-driven native executions.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
coverage_data="${1:-$repo_root/coverage-data}"
cd "$repo_root/rust"
toolchain="$(python -c 'import tomllib; print(tomllib.load(open("rust-toolchain.toml", "rb"))["toolchain"]["channel"])')"
coverage_version="0.6.21"
rustup component add --toolchain "$toolchain" llvm-tools-preview
if [[ "$(cargo +"$toolchain" llvm-cov --version 2>/dev/null || true)" != "cargo-llvm-cov $coverage_version" ]]; then
    cargo +"$toolchain" install cargo-llvm-cov --version "=$coverage_version" --locked --force
fi

report="$repo_root/coverage-reports/rust-lcov.info"
mkdir -p "$(dirname "$report")"
rm -f "$report"

# Build the exact release-profile objects used by the coverage shards under the
# instrumentation environment documented by cargo-llvm-cov for external tests.
export CARGO_TARGET_DIR="$repo_root/rust/target/native-coverage"
source <(cargo +"$toolchain" llvm-cov show-env --export-prefix)
cargo +"$toolchain" llvm-cov clean --workspace

# Cargo-run tests provide direct unit/integration coverage.
cargo +"$toolchain" test --locked --release --workspace --all-targets

# Python coverage shards execute these native binaries externally. Rebuild the
# identical instrumented release objects here so their profiles can be merged.
cargo +"$toolchain" build --locked --release     -p guard-command -p hol-guard-runtime     --bin guard-command-source --bin hol-guard-runtime

shopt -s nullglob
external_profiles=("$coverage_data"/pytest-coverage-*/rust-profraw/*.profraw)
echo "Merging ${#external_profiles[@]} external native coverage profiles"
test "${#external_profiles[@]}" -gt 0

profile_dir="$(dirname "$LLVM_PROFILE_FILE")"
mkdir -p "$profile_dir"
for source_profile in "${external_profiles[@]}"; do
    destination="$profile_dir/external-$(basename "$source_profile")"
    test ! -e "$destination"
    cp "$source_profile" "$destination"
done

cargo +"$toolchain" llvm-cov report --release --lcov --output-path "$report"
test -s "$report"
grep -q '^SF:.*\.rs$' "$report"
grep -q '^DA:' "$report"

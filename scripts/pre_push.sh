#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
export LC_ALL=C

cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings

mkdir -p target
test_log=$(mktemp ./target/pre-push-tests.XXXXXX)
trap 'rm -f -- "$test_log"' EXIT
cargo test --workspace | tee "$test_log"
if ! awk '
    /^test result:/ {
        summaries++
        if ($0 !~ /; 0 failed; 0 ignored;/) failed = 1
    }
    END { exit (failed || !summaries) }
' "$test_log"; then
    echo "Workspace tests must report zero failed and zero ignored tests." >&2
    exit 1
fi

cargo audit --deny warnings
bash -n scripts/test_e2e.sh

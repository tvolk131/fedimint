#!/usr/bin/env bash
# Reproduce the watchdog/backoff restart loop with all four guardians online.
# Run in the Nix development shell. The default fast regression is expected to
# fail on affected code, after proving the stall and long-timeout recovery.
# --expect-watchdog-stall: pass only when the diagnostic reproduces the loop.
# --natural-backoff: use a 25-minute outage and the normal exponential schedule
# instead of the test-only delay floor. Production defaults are unchanged.
# Both modes grow backoff under a long watchdog before testing short-watchdog
# recovery; they do not establish reachability with an unchanged watchdog.

set -euo pipefail
export RUST_LOG="${RUST_LOG:-info},fm::devimint=info"

source scripts/_common.sh
build_workspace
add_target_dir_to_path
make_fm_test_marker

devimint consensus-recovery-test "$@"

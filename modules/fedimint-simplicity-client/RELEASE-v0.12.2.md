# Simplicity on Fedimint v0.12.2

The `simplicity-v0.12.2` branch starts at official tag `v0.12.2`, commit
`53be4684015cf25cd784b5d3f473c911f8bc551a`. It ports the Simplicity changes from
`17336264b340f01b1cd786a2a46bb14b5da132af` relative to that development branch's
upstream base, `487948934b8`. It does not merge the intervening upstream master
changes. The development branch remains available independently.

## Compatibility boundaries

The port preserves the module's wire formats, consensus rules, fees, contract
templates, funding reservations and authenticated session-history recovery.
Release-specific changes use v0.12.2's existing `anyhow` error boundaries and
fallible client/connector constructors instead of importing the later client
error refactor. No external backup file or deprecated backup endpoint is needed
for recovery with the same wallet software, mnemonic and retained federation
history; see [REQ-simplicity-recovery](../../specs/REQ-simplicity-recovery.md).

Two upstream liveness fixes are prerequisites: the database notification race
fix already carried by the development branch, and PR #9085's overlapping watch
borrow fix for the guardian status endpoint. Both retain regression coverage.
The shared transaction context, preflight/finalization hooks and mint-v2 durable
reservations remain the small integration surface described in the module docs.

The compiler and VM remain pinned to the development branch's tested versions.
SimplicityHL's Elements dependency requires Rust Bitcoin 0.32.102, so the release
lockfile's Bitcoin 0.32.8 and its companion crates must advance. The necessary
`cc` and secp256k1-zkp versions match the development branch. Other dependencies
retain the release's lockfile versions. This dependency change is why the checks
include shared encoding/signing and client tests as well as the module tests.

The ordinary `fedimintd` build does not enable the module; use the explicit
`experimental-simplicity` feature or `fedimintd-simplicity` Nix package. Record the
Git revision and lockfile hash: the package version alone still says `0.12.2`
and does not identify this extension. All guardians must use the same reviewed
candidate and module configuration. This is not a rolling mixed-version upgrade
promise or a migration from every undeployed prototype. The separate Markets
app, its SDK pin, and the existing regtest federation are not changed by this port.

## Focused release checks

`.github/workflows/simplicity-consensus.yml` runs on every push to this branch
and supports manual dispatch. It covers:

- Native Linux x86-64 and ARM64 common-module tests, independent reference
  fixtures, 100,000 seeded mutations, and byte-for-byte observation comparison.
- Linux ASan and leak checking, with intentional Rust/C failures verifying
  that instrumentation is active.
- Common/server/client tests and affected core, client, mint-v2 and server tests;
  four-guardian process tests for submission, conflicts, restart and recovery;
  example compilation; module Clippy; ordinary and enabled guardian builds.
- The release's repository formatting and lint checks through its Nix shell.

Reproduce the focused release job using Rust 1.93.0 and the native dependencies
Clang/libclang, CMake, pkg-config and protoc:

```sh
scripts/tests/simplicity-release-checks.sh tests
scripts/tests/simplicity-release-checks.sh network
scripts/tests/simplicity-release-checks.sh clippy
scripts/tests/simplicity-release-checks.sh guardian
nix develop .#lint --command env NO_STASH=true bash misc/git-hooks/pre-commit
```

The network fixtures use four real guardian processes with TLS, WebSocket,
Aleph and RocksDB, but simulated Bitcoin RPC/funding. Their loopback ports need
to be available. Hosted artifacts contain synthetic reports, environment details
and logs, never guardian databases or wallet secrets. They expire after 14 days;
retain the chosen candidate's evidence separately.

Validation of this port is in progress. The earlier October 6/7 evidence files
identify development-branch revisions and do not certify this branch. Passing
these focused checks does not replace the remaining [beta checklist](BETA-CHECKLIST.md):
new-candidate hardware/storage observations, baseline upgrade fixtures, and a
small private signet pilot with real deposits and withdrawals remain separate.

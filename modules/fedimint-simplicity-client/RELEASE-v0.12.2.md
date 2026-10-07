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

## Candidate validation: October 7, 2026

The tested code revision is `13c53a4f79c6a0cb9b8fb35f0aa83b05eb56efb9`, with
Cargo.lock SHA-256
`3b1f1db253a1aee9d7ef9465d798286c7f927880be15e62dc84b95f6c0a0599d`.
The [hosted run](https://github.com/tvolk131/fedimint/actions/runs/37668146744)
passed all six jobs: native comparison, ASan/leak checks, repository lint,
module/shared tests, four-guardian tests, example compilation, Clippy and both
daemon builds. The ordinary and enabled Linux release binaries each ran
`--version` successfully. The final commit after this tested revision only
records these results in documentation.

Both hosted Linux x86-64 and the ARM64 Mac passed 322 module/shared tests and all
four network scenarios: submission/settlement/disk recovery, sender-receipt
history recovery, shared-market
conflicts/restarts/resolution, and mnemonic-only recovery with spendability.
The common-module vectors and 100,000 seeded mutations also passed locally.
Mac, Linux x86-64, Linux ARM64 and Linux ASan observations matched byte-for-byte:

| Report | SHA-256 |
| --- | --- |
| Consensus observations | `f2b3440159972ac994d1b213c3399996e0ae1edcfc4227f6472258d5ff872815` |
| Mutation observations | `9c796bf55aaa7c74cd1c64d14c8541ba607a6ca43e17323ce1dbabc4094c7283` |

The mutation seed was `5065796730156482561`; the campaign reached 47,880 decoded
programs, 42,712 successful executions and 100,000 C-frame adapter calls. This is
bounded coverage, not exhaustive consensus or memory-safety verification. Focused
independent review found no outstanding issue in the port or CI changes.
The opt-in Nix package's derivation evaluated on the Mac; a complete Nix package
build was not run. The guardian build checks above use Cargo.

The earlier October 6/7 evidence files identify development-branch revisions and
do not certify this branch. Passing these focused checks does not replace the
remaining [beta checklist](BETA-CHECKLIST.md): new-candidate hardware/storage
observations, deployment-baseline fixtures, and a small private signet pilot
with real deposits and withdrawals remain separate. The application and live
Mac/Pi federation remain on their existing development revisions.

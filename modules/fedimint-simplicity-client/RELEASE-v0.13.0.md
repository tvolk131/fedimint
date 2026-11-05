# Simplicity on Fedimint v0.13.0

The `simplicity-v0.13.0` branch ports the Simplicity patch set onto official
`v0.13.0`, commit `264ebf22b698c158055bcdd80d5b586fdb48d1fc`. The source branch,
`simplicity-v0.12.2`, remains at `d6678118b42eb86f611724bce4db05a45b8e135b`.
The histories diverged before v0.12.2, so this is an explicit replay onto the
release tag, not a merge of either development history. Of the original 38
patches, 36 are replayed. The guardian status watch-borrow fix and database
subscription-registration fix are already included upstream and are not replayed.

This is a compatibility port, not a new beta qualification. Earlier checks in
[the v0.12.2 release notes](RELEASE-v0.12.2.md) remain evidence for their named
revisions only. Record a clean candidate revision, lockfile hash, and fresh test
results before distributing a v0.13.0 artifact.

## Compatibility changes

- The client initialization, recovery, funding-reservation, and transaction
  finalizer APIs use v0.13.0's typed `ClientModuleError` boundaries. Authorization
  failures are explicitly reported as `TransactionSubmitError::Finalization`,
  not misclassified as primary-module or insufficient-funds errors.
- Session consensus items, P2P imports, logging helpers, and the SDK example's
  infallible builder initialization follow the upstream API moves. The server
  database migration now returns `DbMigrationError`.
- Mint-v2 reservation integration retains upstream checked accounting, typed
  balance errors, migration tests, and eager metric initialization.
- CI runs on both release branches. The focused release-check timeout allows
  for rebuilding the new upstream dependency graph.
- The executor and decoded-program cache tests live in standalone module
  files, as required by the new upstream inline-module lint. Test bodies and
  production behavior are unchanged.

Contract source, golden CMRs, consensus fixtures, execution versions, wire
formats, fees, wallet descriptors, and module database schemas are unchanged
from the source branch. Simplicity VM `0.9.0`, `simplicity-sys` `0.8.0`, and
SimplicityHL revision `351eb068e30affc69189993739cd1b30b02b269d` remain pinned.
The lockfile starts with the official release graph and adds the module's
dependencies. As on the previous Simplicity branch, the compiler requires
Bitcoin `0.32.102` and its companion crates rather than upstream's `0.32.8`.
The port therefore needs shared encoding, signing, client, and server tests,
not just Simplicity-specific checks.

## Upgrade boundaries

The [runbook](RUNBOOK.md#upgrading-from-beta1) still applies. The existing
version 0-to-1 module database migration initializes the running live-contract
total; beta.1 cannot reopen that migrated database. Back up before starting
the new binary. Market and AMM template changes already present on the source
branch mean beta.1 descriptors are not universally recoverable with current
templates. A successful database migration does not change that limitation.

This port does not qualify a live, mixed-version federation or a rolling core
upgrade. Use matching guardian and client revisions and test funds. Rehearse
the full intended deployment and recovery procedure separately. Ordinary
`fedimintd` still excludes the module; build with `experimental-simplicity` or
the `fedimintd-simplicity` Nix package. The package version `0.13.0` alone does
not identify the extension.

## Validation

Run the reproducible focused checks in the development environment:

```sh
just format
bash scripts/tests/simplicity-release-checks.sh tests
bash scripts/tests/simplicity-release-checks.sh network
bash scripts/tests/simplicity-release-checks.sh guardian
bash scripts/tests/simplicity-release-checks.sh clippy
```

The native consensus workflow also compares the implementation's observations
on Linux x86-64 and ARM64, runs seeded mutations, and exercises the instrumented
Rust/C adapters. Local Mac results do not replace those candidate-specific jobs.

An opt-in regression opens a private retained guardian checkpoint only after
copying its files to a temporary database. Supply the module ID from that
checkpoint's consensus configuration, not a guessed default:

```sh
FM_SIMPLICITY_CHECKPOINT=/path/to/immutable/db_checkpoints/SESSION \
FM_SIMPLICITY_INSTANCE_ID=2 \
cargo +1.93.0 test --release --locked -p fedimint-simplicity-server --lib \
  tests::audit::retained_checkpoint_migrates_without_changing_contracts -- \
  --ignored --exact
```

This checks nonempty contract preservation, the migrated liability total,
module audit, restart, and migration idempotence. The original checkpoint is
never opened or written. It is not full guardian startup, consensus replay,
live-peer interoperability, or mnemonic/template-recovery qualification. Keep
private checkpoint contents out of public release evidence.

## Local port checks

The implementation working tree passed the following on macOS ARM64 with Rust
`1.93.0`. Its lockfile SHA-256 is
`0c3c462e1e71106042568c2ba96cab300d67ba7fb6812f3a7b848e9bd9f118d5`.
These are local port checks, not qualification of a clean release artifact.

- The focused `tests` script passed 493 tests across the module, shared
  framework, mint-v2 migration snapshots, resource workloads, and SDK examples.
- The `network` script passed all five harness tests, including the four real
  guardian-process scenarios for market settlement, history/asset recovery,
  sender receipts, and shared-intent races, restarts, and funding limits.
- Ordinary and `experimental-simplicity` Cargo guardian builds both passed and
  reported `fedimintd 0.13.0`.
- All-target Clippy with warnings denied passed for the three Simplicity crates,
  `fedimint-client-module`, `fedimint-client`, and `fedimint-mintv2-client`.
- The 100,000-round seeded native campaign passed, including 41,920 decoded
  programs, 30,673 executions, and 100,000 frame-adapter calls. The observation
  report test and independent Python reference check also passed.
- The copied-checkpoint regression passed against two nonempty retained signet
  pilot checkpoints, including migration, audit, reopen, and idempotence.
- Repository formatting and lint hooks passed after extracting the two test
  modules. A separate read-only integration review found no semantic regressions.

The common-module source and fixtures, contract templates, template-CMR fixture,
and wallet database definitions match the source branch. Implementation
consensus observations also match the frozen pre-port executable's report
byte-for-byte. That executable was not independently rebuilt at the original
branch tip, so this is a bounded runtime comparison, not exact-tip binary
qualification or a consensus-equivalence proof.

The lockfile retains the previous Simplicity branch's added dependency versions,
including `secp256k1-zkp 0.11.0`, rather than accepting an unrelated resolver bump.
Upstream release dependencies otherwise retain the new release baseline except
for the Bitcoin/compiler requirements described above.

Candidate-specific Linux x86-64/ARM64 comparison, Linux sanitizer/leak runs, a
Nix artifact build, full workspace `final-check`, and live coordinated upgrade
qualification were not performed locally. Run the corresponding CI and
operational checks before claiming those boundaries are qualified.

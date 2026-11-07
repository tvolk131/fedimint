# Testing the Simplicity server module

Each layer proves something the faster layers below it cannot. Put a check in the
cheapest layer that can fail for the right reason, and reach for a live scenario
only for behavior that needs real processes, networking or disk.

| Layer | Question it answers | Where it lives now | Cost |
| --- | --- | --- | --- |
| Unit / module policy | Do the module's own hooks, config, API and upgrade logic behave? | `src/tests.rs`, `src/tests/*.rs` | seconds |
| VM | Does a program decode and execute to the expected result, cost and error? | `fedimint-simplicity-common` tests for the VM and jets; here, each fixture's `runtime::decode_program` and `runtime::execute` inside `fixtures::check_all` | seconds |
| Core | Does Fedimint's own transaction processor give the same outcome in submission and consensus modes, with funding and without leaking writes? | `src/tests/assets/{instances,context,resources}.rs`; `tests/resource_workloads.rs` | seconds to minutes |
| Live | Do separate guardian processes, TLS P2P, the WebSocket API, Aleph consensus, RocksDB and real clients still agree? | `src/tests/assets/network.rs` and below | minutes each |

## Resource workloads

`tests/resource_workloads.rs` includes `benches/resources/fixtures.rs`, the same
workloads the opt-in `resources` benchmark measures, and runs its correctness
assertions as ordinary tests. It measures nothing.

- `fixtures::check_all` runs every registered fixture through preflight, decode,
  VM execution, guardian validation and a funded core submission.
- `adversarial::check_all` is the same set as the four family tests, each calling
  `adversarial::check_cases` on one workload family (large and packed programs,
  program shapes, signatures and creations, context access). Each case is checked
  for preflight and for core outcome and dropped writes in submission and
  consensus modes. `every_adversarial_case_belongs_to_one_family` fails when a
  case is added without a family, and an empty family fails its own test.

The benchmark binary still runs both `check_all` functions before measuring
(`cargo bench -p fedimint-simplicity-server --bench resources -- --test`).

## Live scenarios

All live scenarios run four guardians as OS processes. Bitcoin RPC is simulated
through a file in the federation directory; funding is the dummy module, while
wallet scenarios also use real Mint v2 ecash. Client scenarios use
in-memory client databases; guardians use RocksDB. Every scenario has its own
timeout, so a stuck federation fails with the guardian logs rather than hanging.

Guardians are this test executable re-run on `guardian_process_entry`, an
`#[ignore]`d subprocess entry that `Federation::start` selects with
`--ignored --exact`. It is not a scenario and has no required-selection entry.
`guardian_entry_is_a_registered_ignored_test` fails at once if the name in
`GUARDIAN_ENTRY` stops matching, because otherwise every guardian would match
zero tests, exit successfully, and the scenario would fail only at its timeout.

| Scenario (`tests::assets::network::`) | Timeout | What only a live run shows |
| --- | --- | --- |
| `four_guardians_submit_settle_and_recover_assets_from_disk` | 180 s | Asset creation, issuance, transfer and authority destruction reach all guardians. A guardian killed without graceful shutdown rejoins on its own RocksDB and catches up; a spent contract cannot be resurrected. |
| `sessions::creation_sessions_and_expired_policy_replay_match_authenticated_history` | 180 s | Creation sessions and expired-policy replay match authenticated session history across a guardian restart. |
| `status::operator_status_observes_four_guardians_and_a_missing_peer` | 90 s | Operator status over the real guardian endpoints, including one guardian down. |
| `wallet::direct_sender_receipts_restore_history_without_owning_recipient_contracts` | 180 s | Receipt history and recovery for sends funded only by another module. |
| `wallet::mnemonic_only_client_recovery_preserves_assets_history_and_spendability` | 180 s | Wallet recovery from the root secret and federation history alone. |
| `wallet::pruning::funding_sensitive_pruning_and_stale_plans_roll_back_real_ecash` | 180 s | Funding-sensitive pruning and stale intent plans roll back reservations and real Mint v2 ecash before submission. |
| `wallet::receipts::watched_shared_contract_submission_survives_mnemonic_only_recovery` | 180 s | A watched shared contract's submission survives recovery with no owned contracts. |

The release check requires exactly these seven names
(`simplicity_network_tests` in `scripts/tests/simplicity-release-checks.sh`),
and `scripts/tests/simplicity-test-selection.sh` fails when any is missing,
ambiguous or ignored. Changing the set of scenarios means changing that list in
the same commit.

Application policy, oracle, AMM/order, and persisted market-intent race lifecycles
are owned by `tvolk131/fedimint-simplicity` (`tests/ledger`, `tests/live`). The core
retains generic successor, reservation, recovery, and intent-policy checks. Their
relocation is not permission to drop those application assertions.

## Recovery acceptance

[REQ-simplicity-recovery](../../specs/REQ-simplicity-recovery.md) lists the
acceptance conditions. Which layer exercises each one today:

| Condition | Live scenario | In-process |
| --- | --- | --- |
| Whole client database deleted, no backup service; holdings, authority ownership and spendability restored | `mnemonic_only_client_recovery_…` compares contracts and history after recovery, then spends the restored collateral and retires the restored authorities | |
| Wallet that has spent every contract still recovers its confirmed history, with no unspent contract left | `mnemonic_only_client_recovery_…` recovers the drained wallet, and a second wallet independently | |
| Direct sends funded by another module restore sender activity; a receipt does not turn recipient outputs into sender holdings; copied ciphertext creates no history; explicit receipt context survives | `direct_sender_receipts_…` | `fedimint-simplicity-client/src/receipt/tests.rs` |
| A watched shared contract's confirmed submission recovers | `watched_shared_contract_submission_…` | |
| Guardian state survives a hard guardian restart | `four_guardians_…_from_disk`, `creation_sessions_…` | |
| Historical descriptor versions | not live | `fedimint-simplicity-client/src/wallet/tests.rs` (`compatible_wallet_software_restores_historical_template_versions`) |
| Recovery interrupted and resumed without loss or duplicates | not live | `fedimint-simplicity-client/src/wallet/tests.rs` (`pending_prefix_resumes_after_reopening_and_rejects_history_gaps_or_changes`) |
| Foreign or copied records ignored; unsupported owned templates fail atomically | not live | `fedimint-simplicity-client/src/wallet/tests.rs` |

A row marked "not live" has no four-guardian check today. Do not read the live
scenarios as covering it.

## Running

From the repository root. `scripts/tests/simplicity-release-checks.sh` pins the
toolchain and exports `RUSTFLAGS="--cfg tokio_unstable"` and
`FM_TEST_USE_REAL_DAEMONS=0`; export the same before running `cargo` directly,
or Cargo rebuilds the workspace under different compiler flags.

```sh
# Everything except the live scenarios, as the release check runs it.
bash scripts/tests/simplicity-release-checks.sh tests

# Only the resource-workload correctness checks.
cargo test --release --locked -p fedimint-simplicity-server --test resource_workloads

# The seven live scenarios, with the required-selection guard.
bash scripts/tests/simplicity-release-checks.sh network

# One live scenario while developing; --nocapture shows guardian startup.
cargo test --release --locked -p fedimint-simplicity-server --lib -- \
  tests::assets::network::status:: --nocapture --test-threads=1
```

This note describes the harness as it stands. Where scenario code or the owning
crate moves, update the "Where it lives now" column, the scenario table and the
release script together.

## Release qualification

Use the development environment and the exact clean candidate source. Run all
focused phases, not only the module unit tests:

```sh
just format
bash scripts/tests/test-simplicity-test-selection.sh
bash scripts/tests/simplicity-release-checks.sh tests
bash scripts/tests/simplicity-release-checks.sh docs
bash scripts/tests/simplicity-release-checks.sh network
bash scripts/tests/simplicity-release-checks.sh guardian
bash scripts/tests/simplicity-release-checks.sh clippy
nix develop .#lint --command env NO_STASH=true bash misc/git-hooks/pre-commit
```

The driver checks required legacy-mint and network test names with the same
package/feature selections used for execution. Missing, ambiguous or ignored
required tests fail; successful execution must account for every selected runnable
test. Unrelated zero-test harnesses are permitted. Selection inventories, ignored
names, execution totals and failures live in `evidence/test-selections/<selection>/`;
`result.txt` records status and exit code, and a new attempt invalidates an older
success before discovery. These guards cover the filtered selections, not every
broad suite or doctest. Mint v2 snapshot-generation tests matching `db::snapshot_`
are intentionally filtered out; retained migration-snapshot validation still runs.

Preserve manifests, logs and workflow step outcomes together. Neither discovery
nor a manifest establishes passing execution. Guardian builds require clean
source and preserve ordinary and enabled artifacts separately with their source,
lockfile, compiler, feature and checksum identities. A version probe alone does
not establish a functional module deployment.

`.github/workflows/simplicity-consensus.yml` also compares native Linux x86-64
and ARM64 implementation observations, runs seeded mutations, and exercises
instrumented Rust/C sanitizer and leak checks with positive controls. Local Mac
results do not replace these candidate-specific jobs. The focused checks do not
qualify the complete workspace, WASM, live Bitcoin/Lightning backends, target Pi
resources or operational deployment. Keep the
[beta checklist](../fedimint-simplicity-client/BETA-CHECKLIST.md) open until its
separate gates are met; [historical passes](../fedimint-simplicity-client/EVIDENCE.md)
are scoped to their recorded revisions, not this checkout.

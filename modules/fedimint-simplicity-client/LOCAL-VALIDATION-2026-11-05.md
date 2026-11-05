# Local beta follow-up — November 5, 2026

This records the locally addressable audit follow-up on official Fedimint
v0.13.0. The implementation and test fixes are committed through
`c92f71ee106`; the source/lockfile/compiler identities of generated guardian
artifacts belong in their manifests. This is local macOS ARM64 evidence, not
Linux, Raspberry Pi 5, production, or operational release qualification.

## Changes

- **Recovery receipts:** a locally watched input no longer suppresses an
  automatic sender receipt. Suppression requires a mnemonic-decryptable
  descriptor that reproduces the input/output's execution version and CMR.
  Quoting and submission share receipt insertion before fee calculation.
  The four-guardian regression resolves someone else's watched market, loses
  the entire wallet database and recovers the confirmed interaction without
  rewatching or treating the vault as owned. Conservative extra receipts remain
  possible for annotation-free descendants; local watch membership is never
  treated as proof of mnemonic discoverability.
- **Session replay:** the new engine-level regression compares v0/v1 creation
  metadata with threshold-signed inclusion history, rejects forged creation
  clocks and premature/expired spends, and rejoins a guardian from its older
  persisted database after the policy expires. Stored records and spent-output
  removal must agree after replay; a zero or current-tip substitution cannot
  satisfy the test.
- **API cleanup:** `PoolAction` replaces raw pool opcodes while preserving
  their contract bytes. Mint v2 constructors accept a private ordinary/reserved
  funding mode, not arbitrary terminal state-machine states. Persisted state
  discriminants do not change.
- **Market discovery:** lineage traversal uses the existing authenticated
  successor links, checking consuming transaction IDs, policy, authorities,
  missing links and cycles. It no longer scans all retained contracts at each
  hop. This removes the quadratic scan, not the initial history download.
- **Release tooling:** selected shared/default-module tests, behavioral mint
  integrations, doctests and affected-client Clippy join the module checks.
  Guardian builds require clean committed source and embed its exact revision.
  Default and experimental guardians are preserved separately with hashes,
  compiler, lockfile, feature and selected-configuration manifests. Nonstandard
  environment settings are redacted; independent CI phases preserve outcomes
  and logs even when another phase fails.
- **Deployment baseline:** this undeployed candidate starts a fresh matching
  federation. Old prototype migrations are regression fixtures, not a required
  or supported v0.12.2-to-v0.13.0 deployment path. Historical evidence remains
  revision-bound; deployed template recovery must remain versioned thereafter.

## Local checks

Host: Apple M4 Pro, 14 cores, 48 GiB RAM, macOS 26.6.2. Cargo/Rust use `1.93.0`,
locked dependencies, optimized release mode, `--cfg tokio_unstable`, two build
jobs, no incremental compilation and no release debug information.

- The committed release driver completed **551 passing tests**, with three
  explicitly ignored tests: selected module/shared/default-module unit and
  integration checks, all 12 selected Mint v2 behavioral/migration checks,
  three exact-name legacy-mint behavior regressions and SDK example tests.
  The two Mint v2 snapshot-generation tests are intentionally filtered out;
  validation of the retained migration snapshots still runs.
- All **seven four-guardian scenarios passed**, including receipt recovery,
  exact-session replay, quorum progress/rejoin, market settlement, operator
  status, mnemonic recovery and shared-intent races with real Mint v2 funding.
- A repeat exposed a test-only race: the pruning test compared note inventories
  before a previous accepted operation's primary-module change had finished.
  The observed difference was eight credited notes, with no missing original
  notes. Both setup operations now await `Client::await_no_active_states`
  before taking snapshots; the complete network rerun passed. Production
  `await_operation` semantics remain unchanged.
- **Nine doctests passed**, with two intentionally ignored documentation
  examples. These ran earlier in the same implementation worktree, before the
  final test-only settlement fix; they are not a final-artifact qualification.
- All-target **Clippy with warnings denied passed** for common/client/server,
  shared client/module and Mint v2 client crates, including the settlement fix.
- The resource harness smoke check and independent Python vector reference
  completed. [Current worker/cache measurements](../fedimint-simplicity-server/benches/resources/RESULTS-2026-11-05.md)
  retain their own source and workload scope; historical timings do not qualify
  this execution path.
- ShellCheck, Bash/Python syntax, YAML structure, whitespace checks and the
  repository commit hooks passed. Local formatting excludes one unchanged
  upstream line in `fedimint-wasm-tests/src/tests.rs` whose formatting differs
  with the installed formatter; it is not included as an unrelated edit.
- Manifest checks reject dirty guardian builds and mismatched forced revisions,
  verify both lockfile hashes, and confirm that nonstandard settings and local
  user paths are not published in the generated environment manifest.

Raw local logs and generated manifests/binaries live under ignored `evidence/`;
keep that directory if retaining this run. It is not a committed release bundle.
Run `bash scripts/tests/simplicity-release-checks.sh guardian` from a clean source
tree to generate both guardian artifacts and their version probes. Their
manifests identify the build revision without a self-referential documentation
hash. A version probe is not a live deployment rehearsal.

## Coverage decisions and remaining gates

The expanded offline checks exercise the changed shared transaction/client
interfaces, Bitcoin encoding/signing dependencies and real mint client/server
behavior. Fake Bitcoin makes these reproducible without services or test coins.
They do **not** exercise live Bitcoin/Lightning backends, the complete workspace,
WASM, every default-module behavior, mixed core revisions or rolling upgrades.
Selected wallet/Lightning common tests are not substitutes for their complete
daemon integrations. Linux x86-64 release CI, separate native ARM64 consensus
comparison and instrumented Rust/C sanitizer jobs must pass for the chosen
candidate; this local record asserts none of those results.

A targeted static pass of the unchanged guardian executor, preparation/cache,
resource/type guards, asset validation and Rust/C frame widths found no new
confirmed defect. This is not a completed independent security audit or proof
of worst-case resource safety.

Pi 5 latency/memory and adversarial admission/consensus-progress measurements,
storage/endurance and retained-history commitments, exact distributable artifact
qualification, and the private signet operator pilot remain release work. The
fresh deployment must rehearse restart, checkpoint catch-up, mnemonic recovery
and spending contracts created before restart. Preserve its state and template
versions as the baseline for future compatible upgrades. See the
[beta checklist](BETA-CHECKLIST.md); none of its hardware or operational gates
is waived by this local follow-up.

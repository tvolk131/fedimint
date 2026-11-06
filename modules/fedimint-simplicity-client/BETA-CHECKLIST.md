# Simplicity: first v0.13.0 beta checklist

Checkpoint: first-beta preparation on v0.13.0, 2026-11-05. There is no previous
beta on this core release line. The [v0.13.0 port](RELEASE-v0.13.0.md) records
the current release baseline; [v0.12.2 checks](RELEASE-v0.12.2.md) and earlier
evidence remain tied to their original revisions, not qualification of the
current candidate. These workstreams separate bounded code/artifact
qualification from the deployment and pilot work still outstanding. The native market
application exercises the SDK, but does not replace module release checks. Use test
funds throughout. The [runbook](RUNBOOK.md) covers deployment and recovery;
the [module documentation](../fedimint-simplicity-common/README.md) describes
the current protocol and limits.

The v0.13.0 candidate is not deployed. Its initial rollout uses a fresh matching
federation, not a migration of disposable beta.1 prototypes. The historical
completed items below remain revision-bound evidence. Current qualification
must exercise candidate-state restart, checkpoint catch-up, mnemonic recovery
and a valid spend created before restart; preserve those fixtures as the first
deployment baseline. Future deployed releases must preserve that baseline's
historical templates and recovery support.

## Current candidate gates

All boxes in this section start open. Check one only against the chosen
v0.13.0 candidate, recording its owner, exact revision, environment and date,
result, evidence references, exclusions and remaining failures. Reference the
existing source/lockfile/compiler manifest, guardian feature manifests and
binary checksums rather than maintaining a second set of artifact identities.
Retain release evidence outside expiring CI artifacts and build caches; keep
secrets, wallet state and guardian database material private.

- [ ] **Freeze and identify the candidate.** Record a clean source revision,
  the intended guardian and client packages, platforms and feature sets, and
  the resulting artifact manifests and hashes. Qualify the actual intended
  binaries, including a functional Simplicity-module smoke test; a core version
  string alone does not establish module inclusion.
- [ ] **Run exact-candidate automated checks.** Record CI links and evidence
  for native x86-64/ARM64 consensus comparison, sanitizer/leak controls, lint,
  focused behavior/network checks, docs and guardian builds. Required filtered
  regressions must exist and execute. Record ignored/filtered coverage and do
  not claim full-workspace, live-backend, Pi or WASM qualification from the
  focused workflow.
- [ ] **Qualify target resources and storage.** Repeat the
  [resource benchmarks](../fedimint-simplicity-server/benches/resources/README.md)
  on the intended guardian hardware, including cold-cache and mixed admission/
  consensus traffic, ordinary-payment latency, memory and sustained disk growth.
  Record storage, cooling, competing workloads and the observation window. The
  [November 5 local follow-up](LOCAL-VALIDATION-2026-11-05.md) is Mac core-path
  evidence, not Pi 5 or full admission/consensus qualification.
- [ ] **Establish the fresh deployment baseline.** With matching candidate
  guardians and clients, rehearse restart, checkpoint catch-up, interrupted
  mnemonic recovery and spending contracts created before restart. Verify
  expected signed transaction outcomes and contract records after replay, not
  only session counters. Preserve configuration, checkpoints, descriptors,
  pending operations and historical templates for future compatibility tests.
  Disposable prototype migration and rolling mixed-version upgrades are not
  release gates for this fresh deployment.
- [ ] **Rehearse operator backup, restore and halt.** Assign operators and
  validate the [backup/restore and halt procedures](RUNBOOK.md#backup-restoration-and-coordinated-halt)
  on candidate artifacts. Record off-host backup verification, guardian identity
  handling, authenticated-history retention, quorum/failure domains, restoration
  results and who authorizes reopening. Do not mark this complete from written
  instructions alone.
- [ ] **Complete a small private signet pilot before broader beta.** Use
  actual testnet deposits/withdrawals, test funds, monitored candidate guardians
  and clients, and retained recovery history. Before starting, record operators,
  backends, storage, host layout, observation window and stop criteria. Retain
  timestamped monitoring and recovery/restoration evidence. Two guardians per
  host do not provide four independent failure domains. A monitored regtest
  rehearsal or a green CI run does not complete the pilot.

## Historical observations, not current qualification

The earlier Mac/Pi regtest rehearsals exercised real Bitcoin Core funding, market
operations, mnemonic recovery, guardian outages and catch-up, and restoration
from an older guardian checkpoint. These are useful bounded observations, not
completion of the longer campaigns below. Both machines are ARM64, and two
guardians per machine provide only two host failure domains.

The [October 6 evidence](BETA-EVIDENCE-2026-10-06.md) records the completed mutation,
ASan, clock/race/recovery, two-hour load, and checkpoint-restoration campaigns.
Unchecked workstreams below are not a claim that those tests remain unrun:
they retain the outstanding platform, operational, or candidate-specific work.

1. [x] **Native x86-64 / ARM64 consensus comparison.** Hosted Ubuntu 24.04
   runners passed the common-module vectors and 100,000 seeded mutations at
   `76dbcba1b3a`. Observed encodings, commitments, custom jets, execution costs,
   fees, and acceptance/rejection results matched byte-for-byte across native
   Linux x86-64, Linux ARM64, and the local ARM64 Mac. The workflow preserves
   environments and compares implementation results, not just expected fixture
   files. See the [hosted CI evidence](BETA-EVIDENCE-2026-10-07-CI.md).
   The cleaned v0.12.2 candidate also passed this comparison; see its
   [release evidence](RELEASE-v0.12.2.md). This is bounded vector coverage,
   not an exhaustive consensus-equivalence proof.

2. [x] **Bounded execution fuzzing and sanitizers.** Extend the deterministic mutation
   probes into decoding, type inference, witnesses, VM execution, and the
   custom Rust/C frame adapters. Run bounded, instrumented campaigns and keep
   actionable reproducers as regression tests. This needs suitable sanitizer
   toolchains and compute time; it does not require a new protocol design.
   **Completed:** 100,000 seeded native and ASan iterations including C adapters;
   all ordinary common library vectors under ASan. The hosted Linux run also
   passed with leak detection enabled and verified deliberate Rust/C overflow
   and leak controls, resolving the Mac shutdown-scan tooling gap. See the
   [hosted CI evidence](BETA-EVIDENCE-2026-10-07-CI.md). **Remaining:**
   broader/coverage-guided campaigns as ongoing hardening, not an unfinished
   first-beta gate. The v0.12.2 candidate's
   bounded native/ASan/leak checks passed. No memory-safety proof is implied.

3. [x] **Persistent failure and conflict coverage.** Exercise crashes and lost
   responses around funding reservation, transaction submission/acceptance,
   release, retries, and cancellation. Add precise clock/deadline tests,
   including clock votes ordered before a transaction in the same session,
   spend paths closing/reopening, and a rejected attempt later becoming valid.
   Verify safe funding reuse. Complete live shared-market race, invalid-oracle,
   and timeout scenarios beyond the already automated coverage. The existing
   federation can support this work; tests must isolate wallet databases.
   **Completed:** v0/v1 same-session block-vote and close/reopen tests; live
   partial/routed buy/sell races, cancellation/fee conservation, crash/lost-ack,
   opening-block resolution, and three full mnemonic recoveries with late-join
   price history. The v0.12.2 candidate passed the four automated guardian
   scenarios and a fresh real-Bitcoin Mac/Pi rehearsal of lost acknowledgement,
   conflict/funding reuse, operation kill, and mnemonic recovery followed by
   spending. The first-beta `0.1` rehearsal also killed recovery with durable cursor `1`
   and target `3`, then resumed to identical holdings and 22 confirmed history
   entries. This closes the previously outstanding nonzero-cursor case.

4. [ ] **Longer mixed-load and storage runs.** Extend the bounded Pi/Mac runs
   with sustained valid/invalid traffic and growing recovery history. Measure
   latency, memory, disk writes/growth, checkpoint restoration, and recovery;
   include unpaid validation near deadlines and after paths reopen. Record
   competing host workloads. Select suitable storage for sustained deployment:
   idle SD write amplification was reproduced without Simplicity, so fixing
   that upstream behavior is separate from this module's beta checklist.
   **Completed:** 120 mixed-load rounds over two hours, 4,134 adversarial
   transactions, 1,391 concurrent payments, resource samples, application
   recovery after load, and restoration from a session-562 guardian checkpoint.
   The v0.12.2 candidate also passed a 15-minute functional observation with
   all four guardian outage/rejoin cases and populated-checkpoint restoration.
   It retained about 1.2 MiB/s of kernel-accounted writes per Pi guardian,
   including at idle. **Remaining:** deployment storage choice and a longer
   pilot observation window; bounded bursts do not establish saturated
   throughput, storage endurance or DoS immunity.

5. [x] **Compatibility baseline and upgrade foundation.** Preserve guardian
   and client databases, descriptors, pending operations, and template versions
   from the first deployment baseline. Establish fixtures now and freeze them
   against the chosen candidate. Exercise coordinated upgrade/recovery when a
   successor exists; full future-version validation cannot happen beforehand.
   Do not imply support for rolling mixed-version consensus or migrations from
   every undeployed prototype.
   **Completed:** the first-beta `0.1` candidate has a private, checksummed
   71-file guardian/client/template/pending-operation baseline retained outside
   build caches, with all checksums verified. Its four wallet copies loaded
   offline with networking denied;
   the guardian checkpoint restored and caught up live. The upgrade foundation
   adds all-peer readiness, durable ordered activation, fail-stop downgrade
   handling, and client capability discovery. Deterministic tests emulate
   successor `0.2` support. A concrete feature-bearing successor still needs
   its own mixed-binary rehearsal; that is future-release work. Earlier
   prototype fixtures, including those also labeled `0.1`, are not an upgrade
   source for this envelope. The baseline's guardian checkpoint remains one:
   a version 0-to-1 module database migration seeds the stored live contract
   total from its existing contracts. The earlier successor plan required a
   live old-contract upgrade rehearsal. For the undeployed v0.13.0 candidate,
   the fresh-deployment qualification above supersedes that migration-source
   requirement; the retained-checkpoint test remains additional regression
   coverage, not a supported cross-core upgrade. Beta.1 market/AMM client
   fixtures are incompatible with the changed template CMRs; see the
   [historical runbook procedure](RUNBOOK.md#historical-beta1-prototype-transition).

6. [x] **Beta.1 release-candidate checks and packaging.** Release
   `v0.12.2-simplicity-beta.1` tags code candidate `ac5b7094c77` on official
   Fedimint v0.12.2; module config/consensus/API remain `0.1`. Its
   [final qualification record](RELEASE-v0.12.2.md#final-beta-candidate-october-10-2026)
   identifies the source, dependency locks, artifacts, review and checks.
   All six exact-candidate hosted jobs passed, including 361 ordinary/migration/
   CLI tests and five network scenarios. All 303 retained evidence entries and
   both release archives' binary hashes were verified after copying.
   The final artifacts passed a fresh two-Mac/two-Pi rehearsal of real Bitcoin
   funding/withdrawal, mnemonic recovery and spending, operator status, and
   one guardian's outage/rejoin with continued quorum transactions. The earlier
   first-beta qualification retains the broader market/conflict/interruption,
   all-four-outage and populated-checkpoint campaigns, plus compatibility fixtures.
   Packaged Mac Nix and Linux ARM64 binaries are checksummed; the Mac closure and
   private evidence are retained outside build caches. Linux Nix and other
   deployment targets remain unqualified; desktop-app packaging is separate.

Separate upstream follow-up: the v0.12.2 rehearsal observed caught API-handler
panics when concurrent guardian-metadata updates encountered database write
conflicts. The unchanged upstream handler lacks an optimistic-transaction retry;
the guardians continued and passed the qualification.
[The retry fix](https://github.com/fedimint/fedimint/pull/9313) remains an open
upstream PR at this checkpoint and is not included here. See the release evidence.
This and the existing background write-volume concern are not Simplicity
consensus changes.

For each item, record the tested revision, environment, result, limitations, and
remaining failures before marking it complete. Keep reproducible checks and
necessary fixtures in the repository; retain bulky raw logs with the release
evidence rather than committing every run.

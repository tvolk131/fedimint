# Simplicity: remaining beta work

Checkpoint: 2026-10-07. The [v0.12.2 port](RELEASE-v0.12.2.md) records the
release baseline and focused checks; earlier evidence remains tied to its
original development revision. These seven release workstreams include completed bounded
tests and work still requiring a chosen release candidate. The native market
application exercises the SDK, but does not replace module release checks. Use test
funds throughout. The [runbook](RUNBOOK.md) covers deployment and recovery;
the [module documentation](../fedimint-simplicity-common/README.md) describes
the current protocol and limits.

The Mac/Pi regtest rehearsals have exercised real Bitcoin Core funding, market
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

2. [ ] **Execution fuzzing and sanitizers.** Extend the deterministic mutation
   probes into decoding, type inference, witnesses, VM execution, and the
   custom Rust/C frame adapters. Run bounded, instrumented campaigns and keep
   actionable reproducers as regression tests. This needs suitable sanitizer
   toolchains and compute time; it does not require a new protocol design.
   **Completed:** 100,000 seeded native and ASan iterations including C adapters;
   all ordinary common library vectors under ASan. The hosted Linux run also
   passed with leak detection enabled and verified deliberate Rust/C overflow
   and leak controls, resolving the Mac shutdown-scan tooling gap. See the
   [hosted CI evidence](BETA-EVIDENCE-2026-10-07-CI.md). **Remaining:**
   broader/coverage-guided campaigns as warranted. The v0.12.2 candidate's
   bounded native/ASan/leak checks passed. No memory-safety proof is implied.

3. [ ] **Persistent failure and conflict coverage.** Exercise crashes and lost
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
   spending. Recovery was killed before its first scanned page; interruption
   after a nonzero history cursor remains additional coverage.

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

5. [ ] **Compatibility fixtures and coordinated upgrades.** Preserve guardian
   and client databases, descriptors, pending operations, and template versions
   from the first deployment baseline. Establish fixtures now and freeze them
   against the chosen candidate. Exercise coordinated upgrade/recovery when a
   successor exists; full future-version validation cannot happen beforehand.
   Do not imply support for rolling mixed-version consensus or migrations from
   every undeployed prototype.
   **Completed:** private, checksummed guardian/client/template/pending-operation
   baseline under the October 6 evidence directory, plus a new 74-file
   v0.12.2 baseline retained outside build caches. Its four wallet copies loaded
   offline with networking denied, and its guardian checkpoint restored and
   caught up live. A successor version is needed for the actual upgrade rehearsal.

6. [x] **Exact release-candidate checks and packaging.** After fixes, run the
   focused module and affected shared-component checks, repository lint,
   native consensus comparison, sanitizers, and both guardian builds against
   one pinned revision atop the official release. Upstream general release
   qualification is not repeated wholesale. Resolve or explicitly disposition outstanding lint
   failures, verify reproducible deployment including the Pi's 16 KiB pages,
   and obtain focused independent review. Update the runbook and retain the
   artifact identities and validation evidence. Prior rehearsals do not certify
   a later candidate; desktop-app packaging is a separate deliverable.
   The [v0.12.2 candidate evidence](RELEASE-v0.12.2.md#candidate-validation-october-7-2026)
   records this port's exact revision and focused validation. Candidate
   `41100ea9a5e` now has a built/launched macOS Nix package, installed Linux ARM64
   Cargo binaries on the Pi's 16 KiB-page OS, matching native SDK, real Bitcoin
   deposit/withdrawal, and isolated four-guardian recovery/outage/restoration
   evidence. The appended release documentation changes no production code.
   Linux Nix packaging and other deployment targets remain unqualified; use
   the documented, tested artifact paths.

7. [ ] **Small private signet pilot.** Before broader beta, operate the chosen
   candidate with actual testnet deposits/withdrawals, monitoring, retained
   recovery history, restoration, and coordinated upgrade procedures. This
   needs operators, test coins, Bitcoin backends, deployment/storage choices,
   and a pilot observation window. The two-host layout is useful for a private
   rehearsal; independent guardian failure-domain claims need additional hosts.

Separate upstream follow-up: the v0.12.2 rehearsal observed caught API-handler
panics when concurrent guardian-metadata updates encountered database write
conflicts. The unchanged upstream handler lacks an optimistic-transaction retry;
the guardians continued and passed the qualification. See the release evidence.
This and the existing background write-volume concern are not Simplicity
consensus changes.

For each item, record the tested revision, environment, result, limitations, and
remaining failures before marking it complete. Keep reproducible checks and
necessary fixtures in the repository; retain bulky raw logs with the release
evidence rather than committing every run.

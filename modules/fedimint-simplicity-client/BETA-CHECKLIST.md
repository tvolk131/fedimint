# Simplicity: remaining beta work

Checkpoint: 2026-10-06. These seven release workstreams include completed bounded
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

1. [ ] **Native x86-64 / ARM64 consensus comparison.** Run the same pinned
   vectors on native Linux of both architectures and compare commitments,
   custom jets, execution costs, fees, and acceptance/rejection results.
   Preserve revision, toolchain, commands, and results. ARM64 hardware is
   available; this needs an x86-64 runner, such as a Linux droplet or WSL2.

2. [ ] **Execution fuzzing and sanitizers.** Extend the deterministic mutation
   probes into decoding, type inference, witnesses, VM execution, and the
   custom Rust/C frame adapters. Run bounded, instrumented campaigns and keep
   actionable reproducers as regression tests. This needs suitable sanitizer
   toolchains and compute time; it does not require a new protocol design.
   **Completed:** 100,000 seeded native and ASan iterations including C adapters;
   all ordinary common vectors under ASan. **Remaining:** a supported Linux leak
   scan (the Mac runtime hangs at shutdown), broader/coverage-guided campaigns
   as warranted, and the chosen candidate's final checks. No memory-safety proof
   is implied by passing a bounded campaign.

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
   price history. Preserve these reproducible checks and rerun on the candidate.

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
   **Remaining:** deployment storage choice and a longer pilot observation
   window; bounded bursts do not establish saturated throughput or DoS immunity.

5. [ ] **Compatibility fixtures and coordinated upgrades.** Preserve guardian
   and client databases, descriptors, pending operations, and template versions
   from the first deployment baseline. Establish fixtures now and freeze them
   against the chosen candidate. Exercise coordinated upgrade/recovery when a
   successor exists; full future-version validation cannot happen beforehand.
   Do not imply support for rolling mixed-version consensus or migrations from
   every undeployed prototype.
   **Completed:** private, checksummed guardian/client/template/pending-operation
   baseline under the October 6 evidence directory. A successor version and
   chosen release baseline are needed for the actual upgrade rehearsal.

6. [ ] **Exact release-candidate checks and packaging.** After fixes, run the
   full repository Nix/CI checks and focused module/shared-client tests against
   one pinned revision. Resolve or explicitly disposition outstanding lint
   failures, verify reproducible deployment including the Pi's 16 KiB pages,
   and obtain focused independent review. Update the runbook and retain the
   artifact identities and validation evidence. Prior rehearsals do not certify
   a later candidate; desktop-app packaging is a separate deliverable.

7. [ ] **Small private signet pilot.** Before broader beta, operate the chosen
   candidate with actual testnet deposits/withdrawals, monitoring, retained
   recovery history, restoration, and coordinated upgrade procedures. This
   needs operators, test coins, Bitcoin backends, deployment/storage choices,
   and a pilot observation window. The two-host layout is useful for a private
   rehearsal; independent guardian failure-domain claims need additional hosts.

For each item, record the tested revision, environment, result, limitations, and
remaining failures before marking it complete. Keep reproducible checks and
necessary fixtures in the repository; retain bulky raw logs with the release
evidence rather than committing every run.

# Simplicity: first v0.13.0 beta checklist

This checklist governs the fresh execution-version-1 candidate on Fedimint
v0.13.0. There is no deployed prototype state to migrate and no public
real-money release. Use test funds throughout. The [runbook](RUNBOOK.md)
covers deployment and recovery; the
[module documentation](../fedimint-simplicity-common/README.md) describes the
protocol and limits. The [evidence index](EVIDENCE.md) preserves earlier
release-line, Mac/Pi, CI and resource observations at their original revisions.
Those results do not qualify this candidate or complete any box below.

The initial rollout uses a fresh matching federation. Qualification must
exercise candidate-state restart, checkpoint catch-up, interrupted mnemonic
recovery and a valid spend of a contract created before restart. Preserve that
state as the first deployment baseline. Future deployed releases must retain
its historical execution semantics, templates and recovery support; disposable
prototype resets do not authorize dropping them.

## External consumer qualification

The separate `tvolk131/fedimint-simplicity` reference consumer exercises the
public SDK; it is not an officially supported application kit or a substitute
for module release checks.

- [ ] Record an exact clean core/application revision pair and locked dependencies.
- [ ] Run public-API create, spend, conflict, database-loss recovery, and post-recovery
  spend scenarios for explicitly registered application templates and handlers.
- [ ] Preserve historical application descriptor meaning and template vectors.

Local path-overridden builds are development checks, not evidence for a published
revision pair. Core release checks do not promise official application support.

## Current candidate gates

All boxes start open. Check one only against the chosen candidate, recording
its owner, exact revision, environment and date, result, evidence references,
exclusions and remaining failures. Reference the existing source/lockfile/compiler
manifest, guardian feature manifests and binary checksums rather than maintaining
a second set of artifact identities. Retain release evidence outside expiring CI
artifacts and build caches; keep secrets, wallet state and guardian database
material private.

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
  [focused workflow](../fedimint-simplicity-server/TESTING.md#release-qualification).
- [ ] **Qualify target resources and storage.** Repeat the
  [resource benchmarks](../fedimint-simplicity-server/benches/resources/README.md)
  on the intended guardian hardware, including cold-cache and mixed admission/
  consensus traffic. Run sustained valid/invalid submissions with growing
  recovery history, including unpaid validation near policy deadlines and after
  spend paths reopen. Measure ordinary-payment latency, memory, disk writes/growth,
  checkpoint restoration and recovery. Record storage, cooling, competing
  workloads and the observation window.
  [Earlier Mac measurements](EVIDENCE.md#resource-measurements) are not Pi 5,
  storage-endurance or full admission/consensus qualification. Select suitable
  deployment storage and a longer pilot window; bounded bursts do not establish
  saturated throughput or DoS immunity.
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
  Bitcoin backends, storage, retention and backup commitments, the observation
  window and halt criteria. Retain timestamped consensus/latency/memory/disk
  observations and recovery outcomes. Two guardians on each of a Mac and a Pi
  host do not provide four independent failure domains. A monitored regtest
  rehearsal or a green CI run does not complete the pilot.

Broader coverage-guided fuzzing and longer campaigns remain ongoing hardening;
historical bounded native/ASan passes are not memory-safety or consensus proofs.
Keep reproducible checks and necessary fixtures in the repository. Add new
revision-bound evidence through the index rather than copying historical completed
checkboxes or maintaining another release narrative.

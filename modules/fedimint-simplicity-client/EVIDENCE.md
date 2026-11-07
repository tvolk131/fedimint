# Simplicity evidence index

## Current guidance

- [Module protocol and limits](../fedimint-simplicity-common/README.md).
- [Guardian and native SDK runbook](RUNBOOK.md): builds, fresh deployment,
  recovery, backup/restoration and operational diagnostics.
- [Beta checklist](BETA-CHECKLIST.md): open gates for the chosen candidate.
- [Test layers and release checks](../fedimint-simplicity-server/TESTING.md).
- [Resource harness methodology](../fedimint-simplicity-server/benches/resources/README.md).

The current candidate is a fresh execution-version-1 deployment on Fedimint
v0.13.0, not a migration from disposable prototypes. It has not been publicly
released for real-money use. Use test funds; historical passes do not close
current candidate gates.

## Historical record boundary

This index consolidates documentation present at
`d23491069dff57d78eecf6ab334c1f756bc46eaf` (November 7, 2026). That revision is
the **document lookup snapshot**, not the tested source revision of every
record and not a newly qualified artifact. The links below use that immutable
snapshot rather than branch tips. Full narratives, measurements, hashes, CI
links, exclusions and evidence locations remain in Git, without maintaining
parallel release stories or old command sequences in the working tree.

Each record qualifies only its named source, lockfiles, platform, workload and
artifact, if identified. A working-tree check is not a clean-revision build;
an implementation-through revision is not the identity of every generated
binary. Some older follow-ups do not identify a single clean measured revision;
the snapshot must not be substituted for that missing identity. Historical
commands and prototype transition instructions are for their original checkouts,
not instructions for the current candidate.

For offline access, from the repository root:

```sh
git show d23491069dff57d78eecf6ab334c1f756bc46eaf:modules/fedimint-simplicity-client/RELEASE-v0.12.2.md
git show d23491069dff57d78eecf6ab334c1f756bc46eaf:modules/fedimint-simplicity-server/benches/resources/RESULTS-2026-11-05.md
```

Keep the lookup snapshot and the original evidence revisions reachable when
rewriting history. The old filenames below are paths in that snapshot, not
files to restore alongside current guidance.

## Beta and release history

| Record | Source qualification and scope |
| --- | --- |
| [October 6 Mac/Pi campaign][october-campaign] | Guardians at `598b012f5e5b5d5b89c860b538ee9dc4520cdf35`; SDK `dd91a935a71`, application `7ee0cc5`, and separately identified test/mutation revisions. Bounded regtest load, recovery and checkpoint restoration on two ARM64 hosts, not four failure domains or beta certification. |
| [October 7 native comparison and sanitizers][october-ci] | Tested `76dbcba1b3a2289239ffdeb231401c6e70a96e2c`. Linux x86-64/ARM64 observations and instrumented Rust/C checks, including positive controls and leak detection; focused common-module coverage, not hardware or whole-repository qualification. |
| [v0.12.2 release-line record][release-012] | Multiple separately qualified candidates, lockfiles, report/artifact hashes and private evidence inventories. The sections below distinguish them; no pass carries forward to v0.13.0 or the execution-v1-only candidate. |
| [v0.13.0 port and local checks][port-013] | Replay onto official `264ebf22b698c158055bcdd80d5b586fdb48d1fc` from source branch tip `d6678118b42eb86f611724bce4db05a45b8e135b`. Local Mac implementation-working-tree checks, not clean distributable qualification. The frozen executable comparison was not an independently rebuilt exact-tip comparison. |
| [November 5 local follow-up][november-validation] | Implementation/test fixes committed through `c92f71ee106ce7c09840f4855eca1ab03f41b960`; local macOS ARM64 checks. The record distinguishes earlier doctests, final test-only changes and artifact-manifest identities. It does not certify Linux, Pi, operational deployment or the later application/core separation. |

Navigate the v0.12.2 record by qualification rather than its reused package or
module version:

- [October 7 port and history cleanup][release-012-oct7]: original
  `13c53a4f79c6a0cb9b8fb35f0aa83b05eb56efb9`, then corrected candidate
  `0107a0fa0e509856431fddd79acb5e144965347d`; intermediate history/tag and
  per-commit checks are recorded separately.
- [Packaged Mac/Pi rehearsal][release-012-packaged]:
  `41100ea9a5ea7b5014789bc1a28d7006da568a34`.
- [October 8 maximal-pruning qualification][release-012-pruning]:
  `928747c0538e8ee037b23172c471399c3bba325a`.
- [October 9 upgrade-activation qualification][release-012-activation]:
  `62f13634bcc233c92f1af41bbcc7744895c9c0e5`; an earlier prototype baseline,
  not a supported migration source for today's deployment.
- [October 9 first-beta qualification][release-012-first-beta]:
  `d64925adb96b9705507cefd0786ef22ce44044ea`.
- [October 10 final beta candidate][release-012-final]:
  `ac5b7094c77e201d31b624182b20e6fae6439016`, labeled
  `v0.12.2-simplicity-beta.1`. Its narrower final-artifact rehearsal does not
  repeat all earlier market/interruption/checkpoint campaigns.

The [predeployment transition narrative][prototype-transition] is preserved for
audit only. No prototype database or market/AMM descriptor migration is supported
by the fresh deployment. Future compatible releases must retain the first
deployment's execution semantics, historical templates and recovery support.

## Resource measurements

- [October results and follow-ups][october-resources] retain the original
  stage definitions, comparison scopes, source-revision table, storage fees at
  measurement time, recovery/download experiments and limitations. They predate
  the worker pools, admission limit and shared decoded-program cache; the
  record's "latest" and "now" describe that historical path only.
- [Original raw baseline and six detailed reports][resource-archive] are
  preserved at `39102ef2040d3c4dd6b0027132a5ddb4ba46c553`, also named by tag
  `codex/simplicity-benchmarks-2026-10-03`. Keep that commit/tag: it retains
  original measured history that rebased release commits do not identify.
- [November 5 worker/cache measurements][november-resources] identify clean
  harness source `19bb641f45acb23c94813c6d9fdf351070faa614`, lockfile,
  executable and fixture-manifest hashes. These are warm, closed-loop Mac
  core-path observations with writes dropped, not cold-cache, hostile API,
  consensus-progress, sustained-storage or Pi qualification. The later generic
  corpus retired application market cases, so whole-corpus counts and timings
  must not be presented as current or directly comparable.

Retrieve the original archive without relying on a moving branch:

```sh
git fetch origin tag codex/simplicity-benchmarks-2026-10-03
git show 39102ef2040d3c4dd6b0027132a5ddb4ba46c553:modules/fedimint-simplicity-server/benches/resources/2026-10-02-m4-pro/metadata.json
```

No historical measurement is a worst-case bound, Pi sizing result, production
throughput guarantee, or justification by itself for changing fees or limits.

## Evidence retention

The frozen records name private release/compatibility bundles, ignored
`target/` and `evidence/` locations, and hosted workflow artifacts. Git preserves
the written records, **not** all those raw files. Historical CI artifacts had
14-day retention; a CI link is not a promise that its downloads still exist.
This consolidation does not claim to have retrieved or reverified private
bundles or expired artifacts.

For new qualification, use the current checklist and release driver. Retain the
exact source/lockfile/compiler and feature manifests, artifact checksums,
workflow outcomes, test-selection inventories/results and exclusions outside
build caches and expiring CI storage. Add a revision-bound record here rather
than updating a historical result to sound current. Preserve guardian identities,
databases, mnemonics, wallet material and credentials privately; public evidence
must contain only safe reports and metadata.

[october-campaign]: https://github.com/tvolk131/fedimint/blob/d23491069dff57d78eecf6ab334c1f756bc46eaf/modules/fedimint-simplicity-client/BETA-EVIDENCE-2026-10-06.md
[october-ci]: https://github.com/tvolk131/fedimint/blob/d23491069dff57d78eecf6ab334c1f756bc46eaf/modules/fedimint-simplicity-client/BETA-EVIDENCE-2026-10-07-CI.md
[release-012]: https://github.com/tvolk131/fedimint/blob/d23491069dff57d78eecf6ab334c1f756bc46eaf/modules/fedimint-simplicity-client/RELEASE-v0.12.2.md
[release-012-oct7]: https://github.com/tvolk131/fedimint/blob/d23491069dff57d78eecf6ab334c1f756bc46eaf/modules/fedimint-simplicity-client/RELEASE-v0.12.2.md#candidate-validation-october-7-2026
[release-012-packaged]: https://github.com/tvolk131/fedimint/blob/d23491069dff57d78eecf6ab334c1f756bc46eaf/modules/fedimint-simplicity-client/RELEASE-v0.12.2.md#packaged-candidate-and-isolated-macpi-rehearsal
[release-012-pruning]: https://github.com/tvolk131/fedimint/blob/d23491069dff57d78eecf6ab334c1f756bc46eaf/modules/fedimint-simplicity-client/RELEASE-v0.12.2.md#maximal-pruning-qualification-october-8-2026
[release-012-activation]: https://github.com/tvolk131/fedimint/blob/d23491069dff57d78eecf6ab334c1f756bc46eaf/modules/fedimint-simplicity-client/RELEASE-v0.12.2.md#upgrade-activation-qualification-october-9-2026
[release-012-first-beta]: https://github.com/tvolk131/fedimint/blob/d23491069dff57d78eecf6ab334c1f756bc46eaf/modules/fedimint-simplicity-client/RELEASE-v0.12.2.md#first-beta-01-qualification-october-9-2026
[release-012-final]: https://github.com/tvolk131/fedimint/blob/d23491069dff57d78eecf6ab334c1f756bc46eaf/modules/fedimint-simplicity-client/RELEASE-v0.12.2.md#final-beta-candidate-october-10-2026
[port-013]: https://github.com/tvolk131/fedimint/blob/d23491069dff57d78eecf6ab334c1f756bc46eaf/modules/fedimint-simplicity-client/RELEASE-v0.13.0.md
[november-validation]: https://github.com/tvolk131/fedimint/blob/d23491069dff57d78eecf6ab334c1f756bc46eaf/modules/fedimint-simplicity-client/LOCAL-VALIDATION-2026-11-05.md
[prototype-transition]: https://github.com/tvolk131/fedimint/blob/d23491069dff57d78eecf6ab334c1f756bc46eaf/modules/fedimint-simplicity-client/RUNBOOK.md#historical-beta1-prototype-transition
[october-resources]: https://github.com/tvolk131/fedimint/blob/d23491069dff57d78eecf6ab334c1f756bc46eaf/modules/fedimint-simplicity-server/benches/resources/RESULTS.md
[resource-archive]: https://github.com/tvolk131/fedimint/tree/39102ef2040d3c4dd6b0027132a5ddb4ba46c553/modules/fedimint-simplicity-server/benches/resources
[november-resources]: https://github.com/tvolk131/fedimint/blob/d23491069dff57d78eecf6ab334c1f756bc46eaf/modules/fedimint-simplicity-server/benches/resources/RESULTS-2026-11-05.md

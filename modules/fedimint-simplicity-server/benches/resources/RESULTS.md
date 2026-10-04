# Simplicity resource results — 2026-10-02/03

These measurements motivated transaction-wide caps, shared context, early
rejection and decoded-program reuse. The latest measured core path takes about
17 ms for packed constants and 21 ms for constants plus 33 signature checks on
an M4 Pro. These are observed workloads, not worst-case bounds or Pi 5 sizing.

## Context-access follow-up

Nine `context_*` workloads perform 512 accesses per program against 32-entry
asset/authority/action lists. Two 100-sample runs on the same machine measured
0.743–0.750 ms for scalar reads, 1.248–1.258 ms for outpoint hashing,
1.707–1.902 ms for asset searches, and 1.559–1.625 ms for authority/action searches.
A final invalid index rejected in 1.139–1.157 ms. These are full warm in-memory
core checks, not isolated jet costs; differences also include argument
construction. The tested cases do not justify changing the current 1,000
milliweight context-jet charge, but do not establish its worst-case adequacy.
All nine cases run in normal regression tests with both processing modes and
dropped-write checks. A separate allocation test covers a sub-256-byte program
whose one-bit sum witness would expand its unselected branch to tens of MiB;
the existing type guard rejects it before any 128 KiB allocation request, while
smaller encodings decode successfully. No consensus limit or fee changed.

## Concurrent follow-up

Two fresh-process passes per workload/backend/concurrency cell ran 80 iterations
per caller at 1/2/4/8/16 callers. This includes warm RocksDB and a real Mint v2
control but drops all writes. Selected RocksDB results:

| Workload | 1 caller p95 | 16 callers p95 | Throughput, 1 → 16 callers |
| --- | ---: | ---: | ---: |
| Packed constants | 18.4–19.8 ms | 48.5–49.1 ms | 53–56 → 485–515/s |
| Two deep decoder chains | 15.1–16.9 ms | 42.7–43.5 ms | 62–68 → 517–520/s |
| Mixed workload failing its last signature | 21.6–22.5 ms | 50.5–58.4 ms | 46–47 → 410–450/s |
| Repeated missing asset lookup | 1.71 ms | 4.91–5.44 ms | 635–637 → 4,581–5,421/s |
| Mint v2 alone | 1.80–1.85 ms | 8.58–9.18 ms | 585–590 → 5,091–5,248/s |
| Mint v2 within the alternating mixed workload | 1.86–1.87 ms | 7.99–10.55 ms | — |

Four-caller packed/late-failure p95 stayed around 19.6–22.6 ms. At sixteen,
packed/late-failure runs consumed roughly 9.6–11 process CPU seconds per elapsed
second: bounded attempts still saturate this machine. These runs do not establish
queue fairness or consensus liveness; even the Mint-only control saturates.
Packed/late-failure process peaks were about 15–17 MiB with MemDatabase and
81–83 MiB with RocksDB, including setup/cache memory. The baseline differs by
backend; these are not incremental allocation or production guardian RSS limits.
The decoder-heavy chain workload does accumulate substantially more memory:
MemDatabase lifetime peaks rose from 19.6–19.9 MiB at one caller to 57–64 MiB at
sixteen; RocksDB rose from 85–86 MiB to 122–127 MiB. A per-attempt retention
budget is not a bound on concurrent guardian memory.

## Persistent storage follow-up

Fresh RocksDB runs at 1,000 and 10,000 operations confirmed linear logical growth
in six workloads. The table gives decimal MB at 10,000 operations, per guardian;
fees are the Simplicity fees at measurement time, excluding real funding fees.
These runs used the former 10-sat asset-creation surcharge; the agreed schedule
below reduces that surcharge without changing the other rates.
Churn has two transactions per operation. Signed history uses 100 transactions
per session. These are fixture measurements, not universal disk estimates.

| Operation | Logical database MB | Flushed checkpoint MB | Fee, sats |
| --- | ---: | ---: | ---: |
| Bare zero-value contract | 3.75 | 2.08 | 0.104 |
| Live contract with 1 KiB annotation | 24.35 | 24.51 | 1.128 |
| 1 KiB receipt, no UTXO | 13.00 | 13.03 | 1.129 |
| Create and spend annotated contract | 16.24 | 13.99 | 1.230 |
| Namespace with one asset | 8.21 | 5.25 | 10.340 |
| Namespace with 32 assets | 79.92 | 61.04 | 321.365 |

Bare/annotated live module records occupy 108/1,134 logical bytes each. Receipts
and churn leave no live contract records, but their signed history alone is
12.26/14.79 MB at 10,000 operations. Deleting live records therefore cannot bound
permanent growth while preserving the agreed recovery contract. Namespace markers
use 33 bytes and asset origins 164 bytes each, excluding module prefixes. Those
records remain permanent by design even after authority destruction; authority
destruction itself is covered by existing ledger tests, not this sizing probe.

Full database totals include accepted indexes and synthetic funding bookkeeping;
the checkpoint includes compression, metadata and uncompacted effects. Real
funding, session occupancy, heterogeneous contracts, replication, backups and
compaction change physical cost. Shared fixture policies compress particularly
well in the bare/asset cases; unique annotations do not. No recovery scan latency
or history download cost was measured.

**Agreed prototype fees:** retain the 100-msat input/output bases, one-msat
byte/weight charges, and reduce the asset-creation surcharge to 100 msat per ID.
The same one/32-asset operations now cost 0.440/4.565 sats; all other rows' fees
remain unchanged. Against the historical logical sizes, those asset workloads
charge about 0.54–0.57 msat per byte, versus 0.28 for bare contracts. This supports
a lower surcharge without making these measured asset workloads cheaper per byte
than bare contracts. It does not establish a minimum attack cost: real funding,
batching and different record contents change both fees and stored sizes.
The fee change also changes transaction hashes and funding encodings; the table
preserves historical measurements rather than claiming identical physical sizes.

These coefficients are a policy starting point, not a demonstrated lifetime-cost
price or a storage-DoS guarantee. Accepted transactions still grow history without
a global bound, and rejected transactions still pay no fee. Large-state database
and wallet-recovery measurements remain necessary to assess record-count costs.
No rent, expiry, pruning or refunds are introduced. Coefficients are deterministic
and must agree across guardians.

## Evidence and method

The published tag `codex/simplicity-benchmarks-2026-10-03` preserves the original
source history, six detailed reports and first baseline's raw results at
`39102ef2040d3c4dd6b0027132a5ddb4ba46c553`.
[Browse the archive][archive]; retrieval commands are in [README.md](README.md).
Later comparisons retained selected results rather than committing every raw run.
The revisions below are the original measured revisions, retained by that tag;
rebasing the feature branch does not change this experimental provenance.

| Phase | Source revision | Measured scope |
| --- | --- | --- |
| Initial baseline | `d748fb05f03` + harness in `48d3fd7ebbe` | Isolated module validation; no aggregate cap |
| Shared context | `48d3fd7ebbe` → `10fe62152db` | Same 28 fixtures and module scope |
| Aggregate caps | `ce3d2562895` | Adds unsigned preflight and funded core submission; 35 fixtures |
| Adversarial corpus | `0eb6c7f8cfb` | Adds 34 cap-fitting workloads/faults and a mutation probe |
| Structural rejection | `0eb6c7f8cfb` → `3580e4ab851` | Same core cases; signed preflight scope changes |
| State preparation/reuse | `3580e4ab851` → `39102ef2040` | Same core cases; module preparation and retained-decode stage added |

All runs used Apple M4 Pro (14 cores, 48 GiB), macOS 26.6.2 (25G83), Rust 1.98.1,
native ARM64, the default optimized bench profile with thin LTO, Divan 0.1.21,
and no target-CPU/compiler-flag overrides. Timings used the System allocator,
two passes of 100 samples with one iteration each; the last two comparisons
alternated before/after executables. Timer precision was 41 ns. No builds/tests
ran concurrently; there was no CPU pinning, thermal control or load isolation.
Ranges below span run medians, not confidence intervals. Different measurement
sessions are not interchangeable baselines; compare within each table.

Allocation profiling used separate `bench-alloc` executables, normally with
100 samples and with ten for preparation/retention. Their timings are excluded.
Peak values use the median-time column of Divan's `max alloc`, in decimal units:
additional live Rust allocation requests on the measured thread. They exclude
existing fixtures/state, stack, allocator overhead, direct C allocation and other
threads; they are neither RSS nor the maximum across all samples. Cumulative
`alloc` bytes exclude separately reported growth events.

Setup, compilation, signing, state seeding and fixture assertions are outside
timing. Module-only measurements omit core verification, funding and processing.
Core measurements include fresh warm MemDatabase transactions, signatures,
funding checks, processing hooks and dropping writes, using dummy funding.
They exclude wire decoding, database commits/RocksDB, real mint funding,
network admission, consensus and concurrent requests. Module fixtures alone may
lack collateral/fee sponsorship and must not be interpreted as accepted payments.
Do not subtract stage medians to derive unmeasured costs. Full commands, stage
definitions and case descriptions remain in [README.md](README.md).

## Why both caps matter

The initial 32-input signature stress case contained 6,144 BIP340 checks, cost
318,679,936 milliweight in aggregate, and took 807–810 ms of module validation
despite encoding to only 8,783 bytes. Each input fit the old 10,000,000 ceiling.
Shared context alone left this workload at 813–818 ms.

The subsequent 2,000,000 milliweight aggregate cap rejects that case in
0.147–0.151 ms through core. It also charges each asset creation signature
100,000 milliweight. The 16 KiB aggregate redemption-byte cap independently
limits decoding work; these caps sum across Simplicity instances. Fees were not
changed by the cap or optimization commits.

Selected core measurements immediately after introducing caps:

| Case | Outcome | Median | Peak Rust heap |
| --- | --- | ---: | ---: |
| Owner signature | Accept | 0.317–0.332 ms | 15.53 KB |
| Market issuance | Accept | 2.412–2.439 ms | 318.3 KB |
| Market resolution | Accept | 2.510–2.602 ms | 317.6 KB |
| Three 4 KiB constants | Accept | 25.29–26.63 ms | 31.86 KB |
| Four 4 KiB constants | Byte limit | 0.584–0.625 µs | 1.896 KB |
| 19 creations + minimal spend | Accept | 0.413–0.485 ms | 32.12 KB |
| 20 creations + minimal spend | Weight limit | 2.21–2.37 µs | 2.988 KB |

Three constants cost only 197,508 milliweight but use 12,300 redemption bytes;
decoding alone consumed 12.42–12.80 ms and was then repeated during execution.
The original market issuance likewise spent about 1.1 ms decoding versus 47 µs
in its cached VM. Near the old per-program ceiling, signature jets took over
50 times as long as cheap combinators. Static cost is a bound, not a precise
latency model; calibration must include decoding, context and expensive jet mixes.

## Shared context

Caching each version's intent hash once per instance/validation call and sharing
immutable context through `Arc` preserved every field of the initial manifest.
The isolated environment-clone stage changed ownership model; the module stage
continued to build its own context. Selected module-only comparisons:

| Case | Before | After | Peak before → after |
| --- | ---: | ---: | ---: |
| 32 simple inputs | 0.265–0.281 ms | 0.0857–0.0871 ms | — |
| 32 successors | 0.568–0.622 ms | 0.1109–0.1109 ms | 53.74 → 40.21 KB |
| Recovery-heavy context | 2.831–2.970 ms | 0.3085–0.3174 ms | 218.6 → 166.6 KB |
| Asset-heavy context | 3.304–3.597 ms | 0.4536–0.4590 ms | 259.8 → 200.4 KB |

Cumulative allocation traffic fell from 4.664 MB to 408.9 KB for recovery-heavy
context and from 5.502 MB to 469 KB for assets. Single-input market/signature
workloads remained essentially unchanged. The tiny unit case moved from
3.749–3.832 µs to 3.916–4.040 µs: sharing adds some fixed bookkeeping.

## Adversarial findings and structural rejection

Before the ordering improvements, packed constants used exactly 16,384 redemption
bytes and 264,740 milliweight yet took 34.06–34.31 ms through core. Mixing constants
with 33 signatures took 38.06–39.62 ms at 16,295 bytes and 1,971,725 milliweight.
A mixed workload failing its last signature jet still took 37.29–38.73 ms.
Its changed program sharing required fewer constants to stay within the caps;
it was not an identical-work comparison with the accepted case.

668 deterministic program-bit mutations produced 358 successful preflights and
310 `Program` errors without panic. Slowest observed rejected/successful probes
were about 7.1/15.9 ms. Each had one timing sample and no VM execution: passing
preflight did not establish authorization or a worst-case bound.

Moving duplicate, output/action and signature-envelope checks before decoding
produced the following paired core measurements:

| Fault | Before | After |
| --- | ---: | ---: |
| Duplicate reference | 14.95–15.02 ms | 0.667–0.791 µs |
| Unsupported output version | 14.93–15.08 ms | 0.708–0.833 µs |
| Missing outer signature | 30.39–30.53 ms | 0.708–0.833 µs |
| Invalid nineteenth creation destination | 289.2–293.9 µs | 3.332–3.374 µs |

Accepted workloads, correctly shaped bad signatures and missing UTXOs were controls
with no meaningful improvement in that pass. Sub-microsecond results are sensitive
to timer granularity. Transaction hashes, sizes, bounds and core outcomes were
unchanged; signed preflight expectations changed with its new rejection order.

## Latest measured path: state preparation and decoded-program reuse

The guardian now resolves all consumed contracts before decoding and checks all
commitments/versions and shared static cost before any Simplicity VM runs.
Programs may be retained within an 8 MiB conservative logical budget per attempt;
otherwise they are decoded again for execution. Capacity affects performance,
not validity, fees or errors. See [validation architecture][architecture].

| Core case | Before preparation | After preparation |
| --- | ---: | ---: |
| Accepted packed constants | 34.15–34.21 ms | 17.44–17.45 ms |
| Accepted constants + 33 signatures | 38.00–38.10 ms | 21.44–21.49 ms |
| Accepted two deep chains | 27.76–28.34 ms | 14.44–14.51 ms |
| Accepted 38 signature checks | 5.074–5.234 ms | 4.947–5.195 ms |
| Unknown first contract | 16.82–16.94 ms | 34.56–36.18 µs |
| Unknown last contract | 16.83–16.86 ms | 43.43–45.33 µs |
| Wrong first CMR | 20.96–20.97 ms | 4.235–4.236 ms |
| Wrong last CMR | 33.49–33.53 ms | 16.49–16.54 ms |
| Invalid outer signature, correct count | 34.02–34.06 ms | 17.38–17.40 ms |
| Mixed workload failing its last signature jet | 37.23–37.40 ms | 20.76–20.82 ms |

Decoder-heavy accepted workloads roughly halve their time. Signature-heavy
controls do not show a meaningful change. A late commitment failure still needs
preceding decoding but no earlier VM execution. Outer authorization remains late.

Retaining all graphs in an initial isolated probe peaked at 2.21 MB for two deep
chains and 29.71 KB for packed constants. This justified exploration, not a bound.
Production charges nodes/data, jets, padded values and pointer-distinct types,
including value-owned types, with conservative bookkeeping allowances. Retention
uses outer input identity within the immutable transaction, not just its CMR.
Preparations never cross attempts and are dropped before core processing.

| Core workload | Before peak Rust heap | After peak Rust heap |
| --- | ---: | ---: |
| Packed constants | 41.81 KB | 69.77 KB |
| Two deep chains | 1.499 MB | 2.229 MB |
| Two balanced graphs | 1.402 MB | 2.133 MB |
| Constants + 33 signatures | 38.50 KB | 64.82 KB |

The largest observed peak rose about 0.73 MB. The retention budget is not an exact
allocator/RSS ceiling: decoder/accounting scratch, snapshot records, an uncached
current program and VM require additional memory. The corpus proves no maximum.
The allocation baseline manifest matched the timing baseline except for its
profiler flag.

The comparison preserved transaction bytes/hashes, static bounds and core outcomes.
Two malformed-witness probes now pass cheap structure and fail preparation.
The isolated guardian benchmark now includes all preparation hooks, so its nine
historical over-budget cases reject; its scope changed. Only the unchanged core
scope supports the timing comparison above. Unsigned client preflight still
decodes; signed guardian structural preflight no longer does.

## Validation and remaining work

The preparation change was covered by 131 tests across common/client/server and
core/server-core, including targeted reruns after fixture adjustments, and 265
benchmark smoke cases. Regressions cover cross-instance state/cost barriers,
commitment/version rejection before VM failures, exact cost boundaries, stale
state, and equal outcomes/fees across zero/partial/full retention, including
same-policy inputs with different witnesses. The archived reports retain the
earlier checks and scoped lint exceptions; these counts describe those revisions.

Production calibration still needs Raspberry Pi 5 measurements with recorded
RAM, storage, cooling, clocks and throttling; full admission/consensus costs,
cold/large databases, real funding/storage workloads, and broader decoder/type/VM
shapes. The module-local concurrency and storage probes above do not measure
production queueing or recovery scans/downloads. The agreed fees above have not
been calibrated for lifetime operating cost. Rejected transactions pay no accepted-transaction
fee, and per-transaction caps do not bound repeated or simultaneous submissions.
Earlier outer authorization/funding checks, bounded admission and duplicate-work
coalescing remain separate work. Valid claim-key signatures alone cannot prove
that a contract's policy will succeed.

[archive]: https://github.com/tvolk131/fedimint/tree/39102ef2040d3c4dd6b0027132a5ddb4ba46c553/modules/fedimint-simplicity-server/benches/resources
[architecture]: ../../../../specs/ARCH-simplicity.md#module-and-transaction-boundaries

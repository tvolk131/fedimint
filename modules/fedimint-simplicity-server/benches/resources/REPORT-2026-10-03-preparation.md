# Resolve state and reuse decoded programs — 2026-10-03

Guardian validation now rejects unknown contracts before Simplicity decoding and
checks every execution version, commitment and the shared static-cost budget
before any Simplicity VM runs. Sequential decoding retains programs for reuse
within one validation attempt. A conservative 8 MiB logical retention budget
across all instances falls back to re-decoding when a candidate does not fit.
Cache capacity never changes validity, fees or error ordering.

## Method

Before: `3580e4ab851`, using its preserved normal benchmark executable. After:
that revision plus this commit. Hardware/software match the preceding reports:
Apple M4 Pro, 14 cores, 48 GiB RAM, macOS 26.6.2 (25G83), Rust 1.98.1, native
ARM64, optimized bench profile with thin LTO and no compiler/target-CPU overrides.
Two alternating before/after passes use the System allocator, 100 samples of
one iteration per `adversarial_core` case. No concurrent builds/tests run during
these passes. Timer precision is 41 ns; there is no CPU pinning, thermal control
or load isolation. Ranges below span run medians, not confidence intervals.

Both manifests have identical transactions, sizes, static bounds and core
outcomes. The two malformed-witness probes now pass the cheap structural phase
and still reject during preparation. The isolated guardian stage now includes
all preparation hooks, so its historical over-budget fixtures reject before VM
execution. Its scope has changed; only the unchanged core-processing scope is
used for the timing comparison here.

Run the preserved executables with `--bench adversarial_core --sample-count 100
--sample-size 1 --color never`; Cargo build commands are in [README.md](README.md).
Setup, compilation, signing, state seeding and fixture assertions are outside
measurement. Core processing includes fresh warm MemDatabase transactions and
dropping writes. It excludes wire decoding, network admission, RocksDB/commits,
consensus, real mint funding and concurrent requests. Results are comparisons on
this M4, not Raspberry Pi 5 latency bounds or a throughput guarantee.

## Core processing results

| Case | Before median | After median |
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

Decoder-heavy accepted workloads roughly halve their processing time. Missing
contracts avoid decoding entirely; commitment failures still require decoding
through the failing input, but no prior Simplicity VM executes. Outer signature
verification remains late and benefits only from eliminating repeated decoding.
The signature-heavy control has little decoding work to remove, and these runs
do not establish a meaningful change for it.

## Memory decision

Before implementing reuse, `retained_decode` measured retaining all decoded
graphs until the end of each adversarial baseline workload. The largest observed
peak was 2.21 MB for `chain_768x2`; packed constants used 29.71 KB. This justified
exploring retention but did not establish an adversarial upper bound.

The production cache therefore charges nodes, node data, jets, padded values and
pointer-distinct type graphs, including value-owned types, with conservative
allowances for headers and bookkeeping. Accounting stops when a candidate exceeds
the remaining budget. Uncached candidates still pass all preparation checks and
are decoded again during execution. Cache lookup uses the exact outer input index,
including module instance and witness identity through the immutable transaction;
it does not key reuse by policy commitment. Preparations are dropped before core
input/output processing and never shared across submissions or consensus attempts.

The budget is not an exact allocator/RSS ceiling. The current decoder, accounting
scratch storage, snapshot records, an uncached current program and the VM require
additional memory. Existing per-program decoder/type/cell/frame bounds still apply.
The allocation probe uses a separate `bench-alloc` executable with ten samples of
one iteration; its timings are not used. Peak values count additional live Rust
allocation requests on the measured thread, excluding existing fixtures/state,
stack, allocator overhead, direct C allocation and other threads.

| Core workload | Before peak Rust heap | After peak Rust heap |
| --- | ---: | ---: |
| Packed constants | 41.81 KB | 69.77 KB |
| Two deep chains | 1.499 MB | 2.229 MB |
| Two balanced graphs | 1.402 MB | 2.133 MB |
| Constants + 33 signatures | 38.50 KB | 64.82 KB |

Units are decimal and values come from the allocation profiler's median-time
`max alloc` column. The preserved allocation baseline's manifest matches the
timing baseline except for its allocation-profiler flag. The largest observed core
peak increases by about 0.73 MB, while avoiding the second decode roughly halves
the chain workload's CPU time. This corpus is not a proof of maximum
retained/transient memory.

## Validation

The common/client/server and core/server-core tests cover 131 tests, including the
four-guardian market, recovery and competing-intent scenarios. Targeted reruns
after fixture/test adjustments pass. Five new preparation tests cover all-instance
state resolution before decoding, late commitment/version rejection before VM
failure, cross-instance aggregate cost, stale state on a subsequent attempt,
retention accounting boundaries, and equal outcomes/fees under zero, partial and
full retention. Same-policy inputs with different witnesses are covered both
across cache capacities and through submission/consensus in both instance orders.
The existing exact-cost-boundary test now uses a known, matching-commitment input
for its over-budget case; missing-state rejection is tested separately.

All 265 benchmark smoke checks pass. Scoped all-target Clippy passes with the
pre-existing `duration_suboptimal_units` finding in `iroh_api.rs:31` forced to a
warning; that unrelated source is unchanged. Repository formatting and independent
review pass. Accepted transaction rules, fees and wire formats are unchanged;
multiply-invalid transactions can return different first errors.

Earlier outer signature/funding checks, bounded admission, duplicate-work
coalescing and concurrent/Pi 5 calibration remain separate work. A bounded cache
does not bound aggregate load from many simultaneous or repeated submissions.

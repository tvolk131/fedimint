# Aggregate transaction caps — 2026-10-02

The module now limits an outer transaction to **2,000,000 milliweight** and
**16,384 combined redemption program/witness bytes**, summed across all
Simplicity instances. Each asset-creation signature adds 100,000 milliweight to
the same budget. Fees and existing per-program/type/cell/frame safeguards remain
unchanged.

Core calls the new stateless verification hook once per participating module
kind, before per-input verification or stateful validation. Simplicity checks
bytes/counts first, then sequentially decodes programs and accumulates their
static costs, dropping each decoded program before the next. Rejection occurs
before contract execution and creation-signature verification. The client runs
the same checks before committing submission/funding state.

## Method

Measured `10fe62152db` plus this commit's aggregate-cap changes on Apple M4 Pro,
14 cores, 48 GiB RAM, macOS 26.6.2 (25G83), Rust 1.98.1, native ARM64, default
optimized bench profile with thin LTO. Same Cargo.lock and Divan 0.1.21; no
target-CPU or compiler-flag overrides. Two timing runs use the System allocator
and 100 samples of one iteration each; a separate `bench-alloc` run measures
allocations. Timer precision is 41 ns. No concurrent builds/tests, CPU pinning,
thermal controls or load isolation during measurements.

Use the `transaction_preflight|core_submission` filter in
[the methodology](README.md), with the allocation feature for the separate
profiling run. The schema-2 manifest preserves all historical fields of the
original 28 fixtures exactly and adds seven fixtures plus funded transaction
hashes, sizes and preflight outcomes. All 35 fixtures and 163 stage/case smoke
checks pass. Routine raw reruns are not committed.

The new **core submission** stage includes a fresh warm MemDatabase transaction,
stateless preflight, module validation/execution, outer signatures, funding
checks and processing hooks. It uses a dummy funding input and rolls back each
iteration. It excludes wire decoding, database commits, RocksDB, mint funding,
network admission and ordered consensus. Earlier reports timed only the isolated
module validation hook; their latency figures are not directly comparable.

## Results

Ranges span the two run medians, not confidence intervals. Decimal allocation
units match Divan. Peak is additional live Rust allocation requested on the
measured thread, excluding pre-existing state, stack, allocator overhead and
direct C/other-thread allocations; it is not RSS. The table uses the profiler's
median-time column, not a maximum across all samples.

| Core submission case | Outcome | Median (ms) | Peak |
| --- | --- | ---: | ---: |
| Owner signature | Accept | 0.317–0.332 | 15.53 KB |
| Market issuance | Accept | 2.412–2.439 | 318.3 KB |
| Market resolution | Accept | 2.510–2.602 | 317.6 KB |
| 32 simple inputs | Accept | 0.964–1.033 | 40.53 KB |
| 32 recovery-heavy inputs/outputs | Accept | 6.049–6.321 | 173.8 KB |
| 32 asset-heavy inputs/outputs | Accept | 6.955–7.416 | 207.7 KB |
| 32 signature checks in one input | Accept | 4.521–4.713 | 11.79 KB |
| 32 signature checks in four inputs | Accept | 5.396–5.699 | 13.12 KB |
| Three 4 KiB constants | Accept | 25.29–26.63 | 31.86 KB |
| Four 4 KiB constants | Byte limit | 0.000584–0.000625 | 1.896 KB |
| 19 creations plus a minimal spend | Accept | 0.413–0.485 | 32.12 KB |
| 20 creations plus a minimal spend | Weight limit | 0.00221–0.00237 | 2.988 KB |
| Old 6,144-signature stress case | Weight limit | 0.147–0.151 | 9.824 KB |
| 32 owner spends, last signature invalid | Program failure | 8.263–8.305 | 60.15 KB |

The old signature stress transaction is now rejected after decoding its first
program, without executing any signature jets. Its previously measured roughly
0.8 seconds of module execution is no longer reachable through core processing.
This is an early rejection, not a speedup for executing the same accepted work.

The three-constant fixture is a useful counterexample to treating static VM cost
as a latency estimate: it uses only 197,508 milliweight, but 12,300 encoded bytes.
Preflight alone takes 12.42–12.80 ms; execution validation decodes again. Four
copies total 16,400 bytes and are rejected before any program decoding. The byte
cap matters independently of the execution-weight cap. Accepted repeated
signatures total about 1.66 million milliweight; spreading them across inputs
adds decoding, context and outer-signature work.

## Correctness and remaining calibration

All 70 common/client/server tests pass, including allocation guards and federation
network tests. New cases cover exact/over weight boundaries, mixed versions and
instances, output-only creation transactions, early byte rejection before large
allocation, malformed encodings, client finalization, admission/consensus parity
and unchanged database snapshots after rejection. WASM client checking passes.
Scoped Clippy passes with the two existing Rust 1.98 lint categories
`map_unwrap_or` and `unused_async_trait_impl` retained as warnings; unrelated
existing WASM warnings remain. Independent implementation and benchmark review
found no issues.

**Raspberry Pi 5 remains the minimum target, not measured hardware.** These caps
bound individual transactions but do not establish a Pi latency ceiling or
protect against an unlimited stream of valid or invalid submissions. Further
work is Pi measurement, concurrent admission/load testing and a broader search
for expensive decoder/type/VM shapes within the caps. The late-invalid-signature
case also demonstrates that rejected transactions can still consume substantial
bounded work without paying an accepted-transaction fee. No new admission rate
policy or fee calibration is introduced by this change.

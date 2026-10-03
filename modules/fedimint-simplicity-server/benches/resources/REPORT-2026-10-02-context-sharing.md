# Sharing transaction context — 2026-10-02

Reusing transaction-wide work substantially reduces multi-input validation time.
On the same M4 Pro, the recovery-heavy fixture is about 9 times faster and the
asset-heavy fixture about 7–8 times faster. Single-input market validation and
the signature-heavy stress case remain essentially unchanged. No consensus
rules, fees, encodings or limits changed.

## Change and method

Within each module validation call, lazily compute each version's intent hash
once, including reuse for asset-creation signatures. V0 and v1 have separate
entries. Reuse the outer transaction ID for asset origins and the final result.
Hashing still occurs at its original validation step to preserve rejection order.
Nothing is cached across transactions, module instances or validation calls.

Share resolved inputs, proposed outputs and asset actions through `Arc`; retain
each input's own current contract, index and creation clocks. The benchmark's
isolated environment helper now shares those same fields. Its clone stage
therefore measures the new ownership model; the guardian stage still constructs
its own context through production code.

Compare the [first baseline](REPORT-2026-10-02.md), committed in
`48d3fd7ebbebd8fb12101c1f659428367887c61c`, with that revision plus this commit's
context-sharing change. Same Apple M4 Pro, 14 cores, 48 GiB RAM, macOS 26.6.2
(25G83), Rust 1.98.1, native ARM64, default optimized bench profile with thin LTO.
Same Cargo.lock and Divan 0.1.21; no compiler-flag or target-CPU overrides.
Two timing runs use the System allocator, 100 samples of one iteration each.
A separate `bench-alloc` build measures allocations; its timings are excluded.
Timer precision is 41 ns. No concurrent builds or tests, CPU pinning, thermal
controls or load isolation during measurement. Use the commands in
[the methodology](README.md) to reproduce the matrix.

The new manifest is exactly equal to the committed baseline: all 28 transactions,
hashes, encoded sizes, static bounds, fees and expected outcomes are unchanged.
All 92 stage/case smoke checks pass. This report retains selected comparisons;
routine raw reruns are not added to the repository.

## Guardian validation

Ranges below span the two run medians; they are not confidence intervals.
These measure the module hook with a warm MemDatabase, excluding core's initial
parallel decoding, outer signatures, funding checks, processing, commits and
network consensus. They are not complete-transaction throughput measurements.

| Case | Before (ms) | After (ms) |
| --- | ---: | ---: |
| `inputs_32` | 0.265–0.281 | 0.0857–0.0871 |
| `context_32` | 0.568–0.622 | 0.1109–0.1109 |
| `recovery_32` | 2.831–2.970 | 0.3085–0.3174 |
| `assets_32` | 3.304–3.597 | 0.4536–0.4590 |
| `foreign_outputs_128` | 0.584–0.613 | 0.1190–0.1226 |
| `market_issue` | 1.205–1.310 | 1.253–1.273 |
| `market_resolve` | 1.344–1.440 | 1.378–1.405 |
| `cost_32` | 14.34–16.56 | 14.87–15.44 |
| `signature_cost_32` | 807.2–809.9 | 812.7–818.0 |
| `late_bad_signature` | 6.732–7.148 | 6.393–6.599 |

The tiny `unit_v1` case moves from 3.749–3.832 µs to 3.916–4.040 µs.
Sharing adds some fixed bookkeeping; this is a small absolute trade-off, not a
universal speedup. Owner authorization remains about 0.20 ms. Early asset
conservation failure remains about 0.13–0.15 ms. Small differences should not be
treated as established improvements or regressions on this uncontrolled host.

Market decoding remains about 1.1–1.2 ms, while its cached issuance VM takes about
47 µs. Context sharing does not address decoding or the cost of thousands of
signature checks. In particular, the 6,144-signature transaction still consumes
about 0.8 seconds of module validation.

## Allocations

Decimal units match Divan. Peak means additional live Rust allocation requests
on the measured thread, not RSS; it excludes pre-existing state, stack, allocator
overhead and direct C allocations. The `alloc` column is cumulative bytes from
Divan's allocation events, excluding its separately reported growth events.

| Case | Peak before → after | `alloc` bytes before → after |
| --- | ---: | ---: |
| `context_32` | 53.74 → 40.21 KB | 1.354 MB → 212.2 KB |
| `recovery_32` | 218.6 → 166.6 KB | 4.664 MB → 408.9 KB |
| `assets_32` | 259.8 → 200.4 KB | 5.502 MB → 469 KB |

For the recovery and asset fixtures, peak additional heap falls about 23–24%,
while cumulative allocation traffic falls much more. One isolated environment
clone now allocates only the current contract's payload: 1.024 KB or 1.28 KB,
instead of 80.38 KB or 97.02 KB respectively. Its timing reaches approximately
the timer's precision, so no precise clone-speed multiplier is claimed.

## Validation and next calibration

All 60 common, client and server tests pass, including decoder allocation guards,
consensus vectors, multiple module instances and federation network tests. The
new regression uses mixed v0/v1 spends in both orders, two creation signatures,
distinct current states and creation clocks, wrong-version signatures, a changed
nonce, rollback checks and immutable asset-origin outpoints. The WASM client
build and scoped Clippy check pass; the independent code review found no issues.

**Raspberry Pi 5 is the minimum guardian performance target.** These Mac results
establish the optimization's effect, not safe Pi limits. Measure on that hardware
with recorded RAM, storage, cooling, clocks and throttling, then include the full
admission/consensus path, invalid submissions and concurrency. Transaction-wide
work budgets, decoder costs, creation-signature workloads and fee calibration
remain separate decisions. This optimization does not complete that broader
production-hardening work.

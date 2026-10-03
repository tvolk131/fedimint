# Expensive transactions within the caps — 2026-10-03

The slowest accepted workload found in this targeted search takes **38–40 ms**
through core's in-memory submission path on the M4 Pro. A similar workload that
fails its last signature jet takes **37–39 ms**. Both fit the 2,000,000
milliweight and 16 KiB redemption limits. No panic or admission/consensus outcome
disagreement surfaced in this corpus. These are observed workloads, not proven
worst cases or Pi 5 latency bounds.

This commit adds benchmark fixtures and documentation only. Production guardian
behavior, fees, limits and consensus rules are unchanged. The findings support
reordering some checks; the recommendations below are not implemented changes.

## Scope and reproducibility

Source: `ce3d2562895` plus this commit's benchmark additions. Same Apple M4 Pro,
14 cores, 48 GiB RAM, macOS 26.6.2 (25G83), Rust 1.98.1, native ARM64, optimized
bench profile with thin LTO, Cargo.lock and Divan 0.1.21 as the previous report.
No target-CPU or compiler-flag overrides. Two timing passes, each with 100 samples
of one iteration, use the System allocator. Separate `bench-alloc` passes measure
allocations. Timer precision is 41 ns; ranges below span run medians rather than
confidence intervals. No CPU pinning, thermal controls or load isolation.

Thirty cases were measured first, then four follow-ups combining workloads.
Follow-up timing runs were repeated after dependency restoration finished to
avoid that interference. Reported runs have no concurrent builds/tests.
Use the `adversarial_` filter and mutation command in [README.md](README.md).
Routine raw reruns are not committed. The manifest's `adversarial` array pins
transaction hashes, encoded sizes, per-input bounds and expected results. All
historical fields of the previous 35 fixtures are unchanged.

There are 34 new cases and 231 total stage/case smoke checks. Each new case
asserts both its unmutated workload's aggregate bounds and its submitted outcome
in submission and ordered-consensus modes. Full database snapshots match after
dropping every transaction. Scoped benchmark Clippy and formatting pass; no new
CI job is added. The production test suite is unchanged and was not rerun for
these benchmark-only additions.

Both measured stages receive an already decoded Fedimint transaction. Preflight
is the real stateless resource checker. Core measurement includes warm
MemDatabase transaction creation, module validation, outer signatures, native
funding checks, processing hooks, error construction and dropping writes. It
uses dummy funding and excludes wire decoding, network admission, commits,
RocksDB, real mint funding, and concurrent requests. Setup, compilation, signing,
state seeding and fixture assertions are outside measurement.

## Accepted workloads

| Case | Redemption bytes | Static milliweight | Core median (ms) | Peak Rust heap |
| --- | ---: | ---: | ---: | ---: |
| `constants_packed` | 16,384 | 264,740 | 34.06–34.31 | 41.81 KB |
| `constants_1024x15` | 15,420 | 250,260 | 32.30–32.71 | 40.24 KB |
| `chain_768` | 6,922 | 356,252 | 13.93–14.00 | 1.491 MB |
| `chain_768x2` | 13,844 | 712,504 | 27.87–29.36 | 1.499 MB |
| `balanced_768x2` | 14,294 | 712,504 | 28.48–29.97 | 1.402 MB |
| `wide_2048` | 14 | 1,122,404 | 1.642–1.652 | 76.05 KB |
| `hash_blocks_64` | 4,201 | 1,010,644 | 1.814–1.823 | 67.19 KB |
| `signatures_38` | 141 | 1,970,922 | 5.702–5.782 | 11.98 KB |
| `mixed_33` | 16,295 | 1,971,725 | 38.06–39.62 | 38.5 KB |

Heap uses the allocation run's median-time column of `max alloc`: additional live
Rust allocation requests on the measured thread, in decimal units. It excludes
existing fixtures/state, stack, allocator overhead and direct C/other-thread
allocations; it is not RSS or a maximum across all samples.

The dense constants dominate CPU time despite low execution weight. Their
preflight alone takes 16.38–16.67 ms. Core later calls `execute`, which calls
`decode_program` again. The balanced/chain probes use distinct constants to
prevent canonical sharing from collapsing the graph; their memory demand is
much larger despite fewer encoded bytes. Two chain programs do not double peak
heap because decoding and execution are sequential. This matters when considering
retaining decoded programs between stages.

## Rejected workloads

Most cases below start from the exact-byte-limit constant workload. Each failure
has valid outer authorization unless outer authorization is the tested fault.

| Fault | Core rejection median (ms) | Where rejection occurs |
| --- | ---: | --- |
| Unknown first / last contract | 17.43–17.49 | State lookup after full preflight |
| Duplicate contract reference | 16.76–16.76 | Module input collection after full preflight |
| Unsupported output version | 16.71–16.73 | Output validation after full preflight |
| Wrong first CMR | 20.88–20.96 | First execution validation, after decoding again |
| Wrong last CMR | 33.48–33.68 | After earlier programs execute |
| Invalid first outer signature | 33.96–34.23 | Core signature check after module execution |
| Missing outer signature | 35.27–35.67 | Core signature-count check after module execution |
| Uncovered native fees | 35.95–36.91 | Final core funding check |
| Trailing witness in first / last program | 4.28–4.29 / 17.24–17.48 | Redemption decoding during preflight |
| Wrong first / last of 38 signature jets | 0.828–0.843 / 5.894–5.995 | Program execution |
| Mixed constants + wrong last signature jet | 37.29–38.73 | Final input's program execution |

Malformed-witness cases remove a small constant to make room within the byte cap;
their malformed encodings have no valid static cost. Their baselines fit both
caps. The mixed rejected case uses 16,165 bytes and 1,967,329 milliweight; the bad
message breaks some program sharing, requiring slightly less constant data than
the accepted mixed case. It is not an identical-work comparison.

Creation probes also demonstrate ordering: a wrong first creation signature
rejects in 0.047–0.048 ms, while a wrong nineteenth signature or a signed invalid
nineteenth destination takes about 0.314–0.316 ms. These consume 1,900,100
milliweight including the minimal contract spend. The destination could be
rejected structurally before cryptographic verification.

## Mutation probe

668 deterministic program-bit flips across constants, deep/balanced graphs,
hashing and signature workloads produced 358 successful preflights and 310
`Program` errors, with no panic. Success here does not imply valid commitments,
signatures, or transaction acceptance: the probe only runs preflight and does
not execute mutated programs. The slowest rejected probe was about 7.1 ms in a
balanced graph; the slowest successful probe about 15.9 ms in the constant case.
Each has only one timing sample. No novel slower family emerged from this
limited probe; it does not establish an exhaustive decoder bound.

## Suggested check ordering

1. **Put cheap structural rejection before redemption decoding.** Keep global
   bytes/counts first, then check duplicate `(instance, outpoint)` references,
   output versions/shapes and signature scheme/count. These faults currently
   survive 17–36 ms in this corpus. Most module checks can be shared with the
   existing common preflight without another database hook. Signature-envelope
   validation must follow core's format rules and preserve scope across modules.
2. **Resolve inputs before expensive decoding where practical.** Missing UTXOs
   need no VM/type analysis to reject. This requires separating cheap stateless
   bounds from the later decode phase, or an admission-only state precheck. Keep
   byte/count safeguards ahead of database work, use one consistent snapshot,
   and retain authoritative consensus validation. An attacker can target existing
   UTXOs, so existence checking alone cannot eliminate expensive invalid work.
3. **Avoid repeated decoding, and check all commitments before executing any
   program.** Reusing a transaction-local decoded result could reduce the largest
   repeated CPU component and prevent earlier VM work before a later CMR failure.
   Do not assume an exact speedup by subtracting stage medians. Measure retained
   memory before choosing this design: the current checker deliberately drops
   each decoded graph, and a single deep fixture already peaks near 1.5 MB.
   Avoid an unbounded cross-request cache.
4. **Consider outer-signature/funding checks before VM execution as a larger
   core refactor.** Core currently obtains keys, amounts and fees through module
   processing after module validation has executed contracts. Reordering needs
   a clean separation of read-only metadata from policy execution/mutation,
   with rollback and cross-module behavior preserved. Verifying a supplied
   claim key's signature is not proof of contract ownership: an attacker can
   sign with their own claim key and still fail the contract policy later.

These are implementation opportunities, not measured optimized results.
Reordering may change the first error for multiply-invalid transactions even
when the accepted set stays identical. Pin the intended rejection ordering and
test all guardians/consensus paths consistently when implementing a change.
The prototype's undeployed status permits coordinated changes, but a core-wide
change must also account for already deployed module behavior.

The recommended first follow-up is the cheap structural pass, followed by a
measured design for decode reuse. Concurrent admission/backpressure testing and
Pi 5 measurements remain separate work. Rejected transactions pay no accepted
transaction fee, and per-transaction caps do not limit the number of requests.

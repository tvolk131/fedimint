# Structural rejection before decoding — 2026-10-03

This change moves cheap structural rejection ahead of Simplicity program decoding
in the guardian's stateless preflight. It checks duplicate contract references,
output/action shape, creation keys/destinations, and the outer signature scheme
and count. Existing count, byte and creation-cost limits run first. Clients share
the structural checks, but their finalizers run before outer signatures exist.

Full cryptographic signature verification, database lookups, commitment checks,
asset accounting and native funding checks remain in their existing stages.
Limits and fees are unchanged. Invalid transactions can return a different first
error; output structural faults now use the module preflight input-error envelope.

## Scope and reproducibility

Before: `0eb6c7f8cfb`, using its preserved optimized benchmark executable.
After: that revision plus this commit's structural-preflight changes. Both use
the ordinary System allocator, optimized bench profile with thin LTO, native
ARM64 and no target-CPU/compiler-flag overrides. The machine is the same Apple
M4 Pro (14 cores, 48 GiB) as the preceding reports, running macOS 26.6.2 (25G83)
and Rust 1.98.1. There is no CPU pinning, thermal control or load isolation.

Two timing passes per version, alternating before/after, measure all 34
`adversarial_core` cases with 100 samples of one iteration. No builds or tests
run alongside them. Ranges span the two run medians, not confidence intervals.
The timer reports 41 ns precision. Both manifests have identical transaction
hashes, sizes, static bounds and core outcomes for every fixture. Only adversarial
preflight expectations/format change. The benchmark now uses the guardian's
signed preflight for that stage; unsigned client preflight remains a separate
stage. The comparison below uses core processing throughout.

To repeat a preserved binary's measurements, pass `--bench` explicitly:

```sh
/path/to/resources --bench adversarial_core \
  --sample-count 100 --sample-size 1 --color never
```

For a fresh build, use the Cargo commands in [README.md](README.md). Setup,
compilation, signing, database seeding and fixture assertions are outside timing.
Core processing includes a fresh warm MemDatabase transaction and dropping writes;
it excludes wire decoding, network admission, RocksDB/commits, consensus, real
mint funding and concurrent submissions. These are M4 comparisons, not Pi 5
latency bounds or a throughput guarantee.

## Core processing results

| Case | Before median | After median |
| --- | ---: | ---: |
| Duplicate contract reference | 14.95–15.02 ms | 0.667–0.791 µs |
| Unsupported output version | 14.93–15.08 ms | 0.708–0.833 µs |
| Missing outer signature | 30.39–30.53 ms | 0.708–0.833 µs |
| Invalid nineteenth creation destination | 289.2–293.9 µs | 3.332–3.374 µs |
| Accepted packed constants | 30.52–30.79 ms | 30.63–30.89 ms |
| Accepted constants + 33 signatures | 34.19–34.46 ms | 34.32–34.36 ms |
| Invalid outer signature, correct count | 30.46–30.52 ms | 30.70–31.16 ms |
| Unknown last contract | 14.92–14.92 ms | 14.91–15.05 ms |

The first four faults now reject without decoding any program. The remaining
rows are controls: valid workloads retain their work, a signature with the right
shape still requires cryptographic verification later, and unknown contracts
still require database lookup after preflight. The comparison does not establish
a meaningful change in those control workloads. Sub-microsecond values are
especially sensitive to timer granularity and setup/cache conditions.

## Validation and remaining work

All 76 tests across common, client and server pass, including the four-guardian
market/recovery/conflict tests. New regression cases cover structural errors
before malformed-program decoding in submission and consensus, per-instance
scoping, shared authority destinations, unsigned finalization and error
precedence. An allocation regression verifies duplicate references, invalid
output versions and missing signatures reject before allocating a large constant
that the valid decoder control does allocate. The older rollback test now
asserts the earlier error envelope. An artificial client receipt fixture now
uses valid bundle destinations instead of targeting action outputs.

All 231 benchmark smoke checks pass, along with scoped all-target Clippy and
repository formatting. Independent code review found no issues. This is the
first validation-ordering step only: database-dependent early rejection, reuse
of decoded programs, earlier full authorization/funding checks, bounded public
admission and concurrent-load/Pi 5 measurements remain separate work.

# Consensus reference vectors

`consensus.json` is a fixed compatibility fixture. Tests must not regenerate it
from the implementation under test. A changed expectation requires review of the
consensus change, including its execution-version implications.

`examples/consensus_reference.rs` derives the fixture without calling or importing
Fedimint, rust-simplicity or the compiler. It spells out BigSize framing,
enum/dynamic-output framing, the v1 signing preimage, namespace/asset derivation,
and all 36 custom jet identities and type widths. It derives tagged midstates and
program CMRs from the Bitcoin SHA-256 primitive, independently of the Simplicity
commitment implementation; only that `bitcoin_hashes` primitive is shared with
the module, and a padded-block assertion checks the reference's use of
compression. JSON object keys are explicitly sorted so Cargo feature unification
cannot change the fixture. The three execution vectors use literal DAG encodings
and independently calculated static bounds and fees.

To inspect the reference without changing the fixture:

```sh
cargo run --release --locked -p fedimint-simplicity-common --example consensus_reference > /tmp/simplicity-reference.json
diff -u modules/fedimint-simplicity-common/tests/vectors/consensus.json /tmp/simplicity-reference.json
cargo test -p fedimint-simplicity-common
```

The Rust tests exercise every custom jet through its actual C-frame entry point,
checking output bits, declared widths, exact destination cursor movement and
outside guard words. They cover absent assets, invalid indices, foreign outputs,
action outputs and rejection of unsupported execution versions. These are
regression tests, not an independent implementation of the full Simplicity
interpreter or a memory-safety proof. Cross-platform execution and deeper
unsafe-code review remain separate hardening work.

## Bounded mutation and sanitizer campaigns

The opt-in mutation test reuses the fixed vectors and, with `compiler` enabled,
a valid Schnorr-signature program. It mutates program/witness bytes, exercises
decoding and inferred types, compares decoded versus ordinary VM execution, and
calls each custom Rust/C frame adapter with valid and arbitrary input bits,
checking frame guard words and cursor movement. Decoded mutations use their own
commitments so they reach execution rather than stopping at CMR mismatch. This
is seeded mutation testing, not coverage-guided fuzzing or a worst-case execution
bound, and there is no automatic PR fuzz job.

```sh
FM_SIMPLICITY_MUTATION_ROUNDS=100000 FM_SIMPLICITY_MUTATION_SEED=5065796730156482561 \
  cargo test --release --locked -p fedimint-simplicity-common --features compiler \
  --lib seeded_decode_execute_and_frame_campaign -- --ignored --nocapture
```

Rounds are bounded to 100–1,000,000. Preserve the seed, count, source revision,
lockfiles, feature set and log; Rust panics report the iteration and mutated
bytes. Native sanitizer aborts may only identify the last 1,000-iteration progress
checkpoint; replay the same deterministic seed to reproduce them.

For AddressSanitizer, use a separate target directory, a matching nightly
`rust-src`, `-Zbuild-std`, an explicit target, and instrument C dependencies as
well as Rust, as the
[Rust sanitizer guide](https://doc.rust-lang.org/unstable-book/compiler-flags/sanitizer.html)
describes. Rust and C must share one sanitizer runtime. A successful ordinary run
is not evidence that the instrumented run passed; keep their results separately.
Toolchain workarounds from an earlier macOS campaign are preserved in the
[October 2026 macOS notes](../../../../docs/simplicity/release/asan-macos-2026-10.md).

## Hosted native comparison and Linux sanitizers

The `Simplicity release checks` workflow
(`.github/workflows/simplicity-consensus.yml`) runs on pushes and pull requests to
the Simplicity release branches and by manual dispatch. Its native jobs use hosted Ubuntu 24.04 x86-64 and ARM64
runners, checks their actual architecture, and pins Rust 1.93.0 with the committed
lockfile. Ordinary tests still check the independent fixture; the ignored
observation test writes actual implementation results, including wire encodings,
hashes, all custom jet outputs, program commitments, static bounds and execution
fees. The mutation campaign also hashes its generated inputs and observed
decode/VM/frame results, not just pass counts. A dependent job requires identical
JSON reports from both architectures.

To emit the same reports locally:

```sh
FM_SIMPLICITY_REPORT_DIR=/tmp/simplicity-observations \
FM_SIMPLICITY_MUTATION_ROUNDS=100000 FM_SIMPLICITY_MUTATION_SEED=5065796730156482561 \
  cargo +1.93.0 test --release --locked -p fedimint-simplicity-common \
  --features compiler --lib -- --ignored --nocapture --test-threads=1
```

The Linux sanitizer job uses nightly-2026-02-10, Clang 21, instrumented Rust std
and target C/C++ dependencies, and one external Clang ASan runtime, with leak
detection enabled. Before running ordinary library tests and the same bounded
campaign, `scripts/tests/simplicity-sanitizers.sh` requires deliberate C and Rust
heap overflows and a C leak to produce their expected diagnostics; a toolchain
setup failure fails the job rather than silently disabling instrumentation.

Artifacts contain only synthetic vector reports, positive-control diagnostics and
build metadata, never wallet databases, guardian secrets or live federation data.
Native reports are compared only within one workflow revision; they are
observations, not replacements for the independent fixture. This is a focused
common-module execution check, not guardian integration, full repository CI,
hardware calibration or exhaustive consensus equivalence.

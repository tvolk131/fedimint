# Consensus reference vectors

`consensus.json` is a fixed compatibility fixture. Tests must not regenerate it
from the implementation under test. A changed expectation requires review of the
consensus change, including its execution-version implications.

`reference.py` derives the fixture using only Python's standard library, without
calling or importing Fedimint, rust-simplicity, or the compiler. It spells out
BigSize framing, enum/dynamic-output framing, the v0/v1 signing preimages,
namespace/asset derivation, and all 36 custom jet identities and type widths.
Its standalone SHA-256 compression routine derives Simplicity tagged midstates
and program CMRs; it checks itself against `hashlib` on a padded test block.
The three execution vectors use literal DAG encodings and independently
calculated static bounds and fees.

To inspect the reference without changing the fixture:

```sh
python3 modules/fedimint-simplicity-common/tests/vectors/reference.py > /tmp/simplicity-reference.json
diff -u modules/fedimint-simplicity-common/tests/vectors/consensus.json /tmp/simplicity-reference.json
cargo test -p fedimint-simplicity-common
```

The Rust tests exercise every custom jet through its actual C-frame entry point,
checking output bits, declared widths, exact destination cursor movement and
outside guard words. They cover absent assets, invalid indices, foreign outputs,
action outputs and execution-version gates. These are regression tests, not an
independent implementation of the full Simplicity interpreter or a memory-safety
proof. Cross-platform execution and deeper unsafe-code review remain separate
hardening work.

## Bounded mutation and sanitizer campaigns

The opt-in mutation test reuses the fixed vectors and, with `compiler` enabled,
a valid Schnorr-signature program. It mutates program/witness bytes, exercises
decoding and inferred types, compares decoded versus ordinary VM execution,
and calls each custom Rust/C frame adapter with valid and arbitrary input bits.
Frame guard words and cursor movement are checked. Decoded mutations use their
own commitments so they reach execution rather than stopping at CMR mismatch.
This is seeded mutation testing, not coverage-guided fuzzing or a worst-case
execution bound. It adds no automatic PR fuzz job.

```sh
FM_SIMPLICITY_MUTATION_ROUNDS=100000 FM_SIMPLICITY_MUTATION_SEED=5065796730156482561 \
  cargo test --release --locked -p fedimint-simplicity-common --features compiler \
  --lib seeded_decode_execute_and_frame_campaign -- --ignored --nocapture
```

Rounds are explicitly bounded to 100–1,000,000. Preserve the seed, count, source
revision, lockfiles, feature set and log; Rust panics report the iteration and
mutated bytes. Native sanitizer aborts may only identify the last 1,000-iteration
progress checkpoint; replay the same deterministic seed to reproduce them.

For AddressSanitizer, use a separate target directory, a matching nightly
`rust-src`, `-Zbuild-std`, an explicit target, and instrument C dependencies as
well as Rust. The [Rust sanitizer guide](https://doc.rust-lang.org/unstable-book/compiler-flags/sanitizer.html)
documents these requirements. On this Mac, Apple's Clang 21 ASan uses a private
ABI incompatible with Rust's runtime; use upstream LLVM Clang for target C/C++
compilation. Set `CMAKE` if it is outside PATH. A successful ordinary run is not
evidence that the instrumented build/run passed; keep their results separately.

The October 2026 AArch64 macOS campaign used nightly-2026-02-10 and upstream
Clang 21.1.8. Both Rust and C must use the same sanitizer runtime. CMake's
standalone compiler probes also need it: the tested C flags included
`-fsanitize=address -fno-sanitize-link-runtime -fno-omit-frame-pointer`, plus
`-L`, `-lrustc-nightly_rt.asan` and an rpath to that nightly's target library
directory. This avoided an upstream Clang runtime initialization hang on this
macOS release. Check a minimal C/Rust executable and a deliberate memory-error
positive control before interpreting a silent process as a running campaign.

On macOS 26.6.2 that runtime's LeakSanitizer shutdown scan also deadlocked in
`get_dyld_hdr` while dynamically loading an introspection library with allocator
locks held. The completed AddressSanitizer run used `detect_leaks=0` with
`detect_stack_use_after_return=1:halt_on_error=1`; it does not establish absence
of leaks. Preserve the failed-run stack sample separately from the successful
ASan log. A supported Linux LeakSanitizer run remains useful.

## Hosted native comparison and Linux sanitizers

The `Simplicity consensus` workflow runs on the prototype branch and by manual
dispatch. It uses hosted Ubuntu 24.04 x86-64 and ARM64 runners, checks their actual
architecture, and pins Rust 1.93.0 with the committed Cargo lockfile. Ordinary
tests still check the independent fixture; the ignored observation test writes
actual implementation results, including wire encodings, hashes, all custom jet
outputs/version gates, program commitments, static bounds and execution fees.
The mutation campaign also hashes its generated inputs and observed decode/VM/
frame results, not just pass counts. A dependent job requires identical JSON
reports from both native architectures.

To emit the same public test reports locally:

```sh
FM_SIMPLICITY_REPORT_DIR=/tmp/simplicity-observations \
FM_SIMPLICITY_MUTATION_ROUNDS=100000 FM_SIMPLICITY_MUTATION_SEED=5065796730156482561 \
  cargo +1.93.0 test --release --locked -p fedimint-simplicity-common \
  --features compiler --lib -- --ignored --nocapture --test-threads=1
```

The Linux sanitizer job uses nightly-2026-02-10, Clang 21, instrumented Rust std
and target C/C++ dependencies, and one external Clang ASan runtime. Leak detection
stays enabled. Before running ordinary library tests and the same bounded
campaign, `scripts/tests/simplicity-sanitizers.sh` requires deliberate C and Rust
heap overflows and a C leak to produce their expected diagnostics. A toolchain
setup failure must fail the job, not silently disable instrumentation or leaks.

Artifacts contain only synthetic vector reports, positive-control diagnostics
and build metadata. They exclude wallet databases, guardian secrets and live
federation data. Native reports are compared only within one workflow revision;
they are observations, not replacements for the independent expected fixture.
This is a focused common-module execution check, not full guardian integration,
full repository Nix CI, hardware performance calibration or exhaustive consensus
equivalence. Server/SDK release-candidate checks remain separate.

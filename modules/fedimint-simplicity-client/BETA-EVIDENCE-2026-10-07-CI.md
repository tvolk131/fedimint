# Hosted native consensus and sanitizer checks

Tested revision: `76dbcba1b3a2289239ffdeb231401c6e70a96e2c`.
The [GitHub Actions run](https://github.com/tvolk131/fedimint/actions/runs/37565943945)
started October 7 UTC (October 6 locally). This is focused common-module
validation, not full repository CI or beta certification. Only tests, CI, and
documentation changed; guardian and client behavior did not change.

## Native comparison

Both hosted Ubuntu 24.04 runners verified their native architecture using
`uname -m`: x86-64 and ARM64. They used Rust 1.93.0, Clang 18.1.3, CMake 3.31.6,
the locked dependency graph, release mode, and the `compiler` feature.
Each passed 19 ordinary library tests, four decoder allocation tests, the
independent Python reference check, and both explicit report/mutation tests.
Clean jobs took 9m05s and 8m57s respectively; the comparison job passed.

Each mutation campaign used seed `5065796730156482561` and 100,000 iterations:
47,880 decoded cases, 42,712 successful executions, and 100,000 custom C-frame calls.
The digest covers generated inputs and observed decoder, VM, and frame results;
matching counters alone are insufficient. The fixed report includes actual
wire encodings, namespace/asset/signing hashes, all 36 custom jets, and three
literal programs' costs, execution fees, and rejection results.

The local macOS 26.6.2 ARM64 run used the same Rust version and source, passed
the same native tests, and produced byte-identical reports to both Linux jobs.
The following SHA-256 hashes identify the complete report files:

```text
consensus.json  f2b3440159972ac994d1b213c3399996e0ae1edcfc4227f6472258d5ff872815
mutation.json   9c796bf55aaa7c74cd1c64d14c8541ba607a6ca43e17323ce1dbabc4094c7283
```

## Linux sanitizers

The Ubuntu x86-64 job passed in 11m42s using nightly-2026-02-10
(`rustc 1.95.0-nightly`, LLVM 22.1.0) and Clang 21.1.8. Rust, rebuilt std, and
C dependencies were instrumented, using `-Zexternal-clangrt` to share Clang's
ASan runtime. The script enabled
`detect_leaks=1:detect_stack_use_after_return=1:halt_on_error=1`.

All three positive controls produced the expected diagnostic and failed as
intended: a C heap overflow, an eight-byte C leak, and a Rust heap overflow.
All 19 ordinary library tests then passed, followed by the report and
100,000-iteration mutation tests in 327.82 s. No sanitizer or leak finding was
reported for the module tests. The sanitizer's reports also matched the native
reports byte-for-byte. The four decoder allocation integration tests ran only
in the native jobs, not under ASan.

This resolves the earlier Mac leak-scanner tooling gap without disabling leak
detection. It does not establish absence of all leaks, undefined behavior, or
other memory-safety defects. No production-code fix was needed by this run.

## Reproduction and scope

The [vector instructions](../fedimint-simplicity-common/tests/vectors/README.md)
describe local reproduction; `.github/workflows/simplicity-consensus.yml`
runs the native comparison and `scripts/tests/simplicity-sanitizers.sh`.
The workflow runs on relevant branch pushes and supports manual dispatch.
Hosted artifacts contain synthetic reports and environment metadata only,
with 14-day retention. Downloaded artifacts and logs are also retained locally
under ignored `target/simplicity-ci-20261006/`; no wallet or guardian credentials
are included in those public artifacts.

These checks do not cover a mixed-architecture live federation, Windows,
coverage-guided fuzzing, a long-running guardian leak scan, saturated load,
or hardware performance. Full repository Nix/CI and the chosen release
candidate's packaging, operational pilot, and upgrade checks remain separate.

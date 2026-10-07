# Bounded Mac/Pi hardening checkpoint

This records an unattended regtest campaign, not beta certification. The four
guardians ran `598b012f5e5b5d5b89c860b538ee9dc4520cdf35`: two on the M4 Pro Mac,
two on one 8 GB Raspberry Pi 5 with Raspberry Pi OS, SD storage, and stock active
cooling. These are two ARM64 hosts and two failure domains. The Simplicity
guardian implementation is unchanged from that deployment; today's changes
are client optimizations and tests. SDK runtime: `dd91a935a71`; application
runtime: Simplicity Markets `7ee0cc5`. Exact driver hashes and source patches
are retained with the local evidence.

## Execution and recovery

- All 43 server tests passed, including new v0/v1 clock tests (`f7eba746f09`).
  A block vote earlier in the same session closes an admitted claim and opens
  a previously rejected refund. An identical unspent transaction closes in
  session 3 and reopens in session 4; rejection does not mutate its contract.
- All 46 SDK library tests passed. Batched imports and creation-session hints
  authenticate origins, preserve full successor history, and reject incorrect
  hints, ambiguous lineages, and incompatible descriptors atomically. Hinting avoids
  rescanning genesis for each newly announced order, including when history
  exceeds the core API's 512-session cache.
- Mutation harness `2c53d546f22` passed 100,000 deterministic iterations both
  normally (6.94 s) and under AddressSanitizer (125.19 s): 47,880 decoded cases,
  42,712 executions, and 100,000 custom C-frame calls. Seed:
  `5065796730156482561`. All 19 ordinary common-module tests also passed under
  ASan. A deliberate C heap overflow positive control was detected.
- ASan used nightly-2026-02-10, instrumented std and C dependencies, and upstream
  Clang 21.1.8 sharing Rust's runtime. Apple's private ASan ABI was incompatible;
  the upstream runtime also encountered a macOS loader initialization hang.
  LeakSanitizer hung during its shutdown scan on macOS 26.6.2. The completed run
  used `detect_leaks=0:detect_stack_use_after_return=1:halt_on_error=1`.
  This is neither a leak check nor coverage-guided fuzzing. See the
  [mutation instructions](../fedimint-simplicity-common/tests/vectors/README.md).
- The live application acceptance run passed in 71.2 minutes, overlapping load.
  It checked competing fills/swaps, partial fills, mixed routed buys and sells,
  immutable limits, exact accepted fees, unchanged notes on permanent rejection,
  abrupt restart, acceptance before acknowledgment, liquidity withdrawal races,
  and resolution at its opening block. A late observer rebuilt all 44 price
  observations. Three mnemonic-only recoveries preserved holdings, rights,
  chart, depth, portfolio, and full readable history (106 / 108 / 103 entries).
  These recoveries finished after the load campaign. No Keychain wallet was used.

## Two-hour mixed-load run

120 rounds passed over 7,200.38 s, alternating six cases with two validation
workers and concurrent ordinary Mint v2 payments. Each round configured a 40 s
work window, plus setup and in-flight completion: the longest elapsed round was
71.783 s, under a 240 s outer process timeout. Starts were at least one minute
apart; most allowed 20 iterations per worker, the packed case four. This was
bounded mixed traffic, not saturation or a DoS
resistance proof. Every guardian's response and expected live/spent contract
state were checked, including rollback on rejection.

There were 4,134 measured adversarial transactions: 1,734 accepted and 2,400
rejected. There were 1,391 measured concurrent payments, plus 120 setup payments.
Latency includes network/queueing and, for valid transactions, acceptance by all
four guardians. It is not isolated VM timing.

| Case | Transactions | Median | p95 | Maximum |
| --- | ---: | ---: | ---: | ---: |
| Context-heavy | 794 | 1.323 s | 2.427 s | 4.977 s |
| Failure in last input | 800 | 0.620 s | 1.158 s | 1.624 s |
| Packed inputs | 160 | 1.732 s | 2.773 s | 3.331 s |
| Mixed invalid | 800 | 0.705 s | 1.376 s | 1.968 s |
| Signature-heavy | 780 | 1.285 s | 2.626 s | 4.988 s |
| Missing contract | 800 | 0.554 s | 1.057 s | 1.726 s |
| Concurrent ecash payment | 1,391 | 1.206 s | 2.862 s | 5.905 s |

The two Pi guardian PIDs remained unchanged. Once-per-minute RSS samples peaked
at 232.0 and 221.5 MiB; start-to-end growth was 5.5 and 6.7 MiB. This sampling
cannot exclude brief peaks or demonstrate a memory-growth plateau. Maximum
sampled temperature was 63.7 C, with throttling flags always zero.
All four session counts advanced from 545 to 583 during the campaign. Mac
guardian sampled RSS maxima were 225.4 / 253.2 MiB, with start/end values of
98.7 / 136.8 MiB and 96.8 / 138.7 MiB respectively; longer runs are needed to
characterize cache-related growth.

The Pi SD device reported 18.47 GB written while each guardian directory grew
about 17.7 MB. Per-process write counters reported about 9.78 GB each; device and
process accounting are different measures. Directories include DB, checkpoints,
logs and configuration. This campaign does not isolate idle write amplification
from transaction work; prior non-Simplicity controls remain the attribution
evidence. SD endurance remains an operational concern. Mac directory growth was
16.9 / 8.9 MB. CPU/GPU training and other user workloads, compilation, and the
application acceptance driver competed for resources and were recorded.

After load, guardian 2 was restored from a preserved session-562 checkpoint while
the other three maintained quorum. It caught up to the session-680 target in
31.72 s including validation; all four then reported session 681. Final accepted
contracts remained live, their predecessors and asset genesis contracts remained
spent, asset records matched, and completed sessions 562, 563 and 679 matched
across guardians. The original database was preserved. This was a same-version
restoration, not an upgrade test.

## Reproduction and retained fixtures

Bulky logs and private fixtures are in ignored local storage:
`target/simplicity-beta-20261006/`. Do not publish that directory: it contains
regtest mnemonics, notes, guardian credentials and pending transaction material.
`campaign-2/` retains the exact driver source, script, per-round manifests,
transactions, latencies, 121 resource samples and guardian metrics. `summary.json`
contains the numeric summary; `campaign-passed.txt` marks successful completion.
The failed preflight with an exhausted packed-case fixture and the earlier
30-minute application timeout are retained separately, not counted as passes.

`app-hinted-manifest.json`, its source patch, driver binary and acceptance log
identify the live run. `restoration/result.json` records catch-up comparisons.
`compatibility-baseline/` preserves the guardian checkpoint/configuration,
completed and recovered application databases, descriptors/template encodings,
and an offline pending-transaction fixture. Keep copied wallets frozen: they
share a mnemonic/notes and must not become independently active wallets.
This is a baseline for a future upgrade candidate, not evidence that a future
version can load it. Checksums identify the exact retained files.

Ordinary checks: release common/server/SDK suites, application `scripts/check.sh
local`, dependency-free optimizer `scripts/check.sh numeric`, and GPU captures
`scripts/check.sh gpu`. The application has 70 ordinary release tests and 15
software screenshot baselines. Native release preview selected Metal on Apple
M4 Pro and rendered the fixed-state fixture; native mouse automation failed with
`noWindowsAvailable`, so interaction coverage comes from Iced's UI tests.

Full repository Nix/CI, native x86 comparison, Linux leak checking, exact release
packaging, private signet operation, and future-version upgrades are not certified
by these results. The full Nix environment required substantial unrelated builds;
focused native checks and required `just format` passed, but the unavailable
Flakebox commit hook was explicitly skipped for local commits. App hosted CI is
configured but cannot run its SDK-dependent job until the pinned companion
commit is published. Nothing was published during this goal.

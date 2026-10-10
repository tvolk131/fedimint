# Simplicity on Fedimint v0.12.2

The `simplicity-v0.12.2` branch starts at official tag `v0.12.2`, commit
`53be4684015cf25cd784b5d3f473c911f8bc551a`. It ports the Simplicity changes from
`17336264b340f01b1cd786a2a46bb14b5da132af` relative to that development branch's
upstream base, `487948934b8`. It does not merge the intervening upstream master
changes. The development branch remains available independently.

## Compatibility boundaries

The first beta baseline uses module configuration version `0.1` and an
extensible consensus-item envelope. The unreleased upgrade-aware `0.2` candidate
was relabeled before the first release. It requires fresh federation initialization;
earlier prototype history/configurations, including those also labeled `0.1`,
are not a migration source. Identify compatibility by the qualified source
revision and artifact hashes, not just the reused pre-release number. It preserves
contract execution versions 0/1, jet costs, fees, commitments and descriptors.
Future compatible releases retain the `0.1` config while separately advertising
support and activating through ordered votes. See the
[module upgrade protocol](../fedimint-simplicity-common/README.md#module-upgrades).
Earlier qualification records below are evidence for their named revisions;
they do not automatically qualify these new activation rules.

The original port preserved the development module's wire formats, consensus
rules, fee formula, contract templates, funding reservations and authenticated
session-history recovery. The subsequent maximal-pruning change restricts accepted
spends in both execution versions before deployment: every revealed node must
execute and every revealed case must use both branches. Commitments and descriptor
formats are unchanged; fees use the submitted pruned representation. Old unpruned
conditional history may fail replay. Use a fresh federation with matching guardian
and client revisions, rather than treating this as a rolling upgrade. Earlier
qualification results below certify their named revisions, not this change.
Release-specific changes use v0.12.2's existing `anyhow` error boundaries and
fallible client/connector constructors instead of importing the later client
error refactor. No external backup file or deprecated backup endpoint is needed
for recovery with the same wallet software, mnemonic and retained federation
history; see [REQ-simplicity-recovery](../../specs/REQ-simplicity-recovery.md).

Two upstream liveness fixes are prerequisites: PR #9085's overlapping watch
borrow fix for the guardian status endpoint and the merged
[PR #9286 database notification fix](https://github.com/fedimint/fedimint/pull/9286).
The latter replaces the earlier local fix: callers await registration to establish
the subscription before taking a database snapshot. They await the returned
notification future only if the database check needs to wait. External implementations and direct callers of `IDatabase::register`
must adapt to its changed Rust API. `wait_key_check`, stored data and consensus
formats are unchanged. Both fixes retain regression coverage and upstream
authorship. The shared transaction context, preflight/finalization hooks and
mint-v2 durable reservations remain the small integration surface described in
the module docs.

The compiler and VM remain pinned to the development branch's tested versions.
SimplicityHL's Elements dependency requires Rust Bitcoin 0.32.102, so the release
lockfile's Bitcoin 0.32.8 and its companion crates must advance. The necessary
`cc` and secp256k1-zkp versions match the development branch. Other dependencies
retain the release's lockfile versions. This dependency change is why the checks
include shared encoding/signing and client tests as well as the module tests.

The ordinary `fedimintd` build does not enable the module; use the explicit
`experimental-simplicity` feature or `fedimintd-simplicity` Nix package. Record the
Git revision and lockfile hash: the package version alone still says `0.12.2`
and does not identify this extension. All guardians must use the same reviewed
candidate and module configuration. This is not a rolling mixed-version upgrade
promise or a migration from every undeployed prototype. The separate Markets
app, its SDK pin, and the existing regtest federation are not changed by this port.

## Focused release checks

`.github/workflows/simplicity-consensus.yml` runs on every push to this branch
and supports manual dispatch. It covers:

- Native Linux x86-64 and ARM64 common-module tests, independent reference
  fixtures, 100,000 seeded mutations, and byte-for-byte observation comparison.
- Linux ASan and leak checking, with intentional Rust/C failures verifying
  that instrumentation is active.
- Common/server/client tests and affected core, client, mint-v2 and server tests,
  including legacy mint-v2 database migrations;
  four-guardian process tests for submission, conflicts, restart and recovery;
  example compilation; module Clippy; ordinary and enabled guardian builds.
- The release's repository formatting and lint checks through its Nix shell.

Reproduce the focused release job using Rust 1.93.0 and the native dependencies
Clang/libclang, CMake, pkg-config and protoc:

```sh
scripts/tests/simplicity-release-checks.sh tests
scripts/tests/simplicity-release-checks.sh network
scripts/tests/simplicity-release-checks.sh clippy
scripts/tests/simplicity-release-checks.sh guardian
nix develop .#lint --command env NO_STASH=true bash misc/git-hooks/pre-commit
```

The network fixtures use four real guardian processes with TLS, WebSocket,
Aleph and RocksDB, but simulated Bitcoin RPC/funding. Their loopback ports need
to be available. Hosted artifacts contain synthetic reports, environment details
and logs, never guardian databases or wallet secrets. They expire after 14 days;
retain the chosen candidate's evidence separately.

## Candidate validation: October 7, 2026

### Before history cleanup

The original port was tested at `13c53a4f79c6a0cb9b8fb35f0aa83b05eb56efb9`, with
Cargo.lock SHA-256
`3b1f1db253a1aee9d7ef9465d798286c7f927880be15e62dc84b95f6c0a0599d`.
The [hosted run](https://github.com/tvolk131/fedimint/actions/runs/37668146744)
passed all six jobs: native comparison, ASan/leak checks, repository lint,
module/shared tests, four-guardian tests, example compilation, Clippy and both
daemon builds. The ordinary and enabled Linux release binaries each ran
`--version` successfully. The original tip,
`f649ec2fa0aea6b13899c892b0a2f9382085266e`, added only the documentation recording
those results.

Both hosted Linux x86-64 and the ARM64 Mac passed 322 module/shared tests and all
four network scenarios: submission/settlement/disk recovery, sender-receipt
history recovery, shared-market
conflicts/restarts/resolution, and mnemonic-only recovery with spendability.
The common-module vectors and 100,000 seeded mutations also passed locally.
Mac, Linux x86-64, Linux ARM64 and Linux ASan observations matched byte-for-byte:

| Report | SHA-256 |
| --- | --- |
| Consensus observations | `f2b3440159972ac994d1b213c3399996e0ae1edcfc4227f6472258d5ff872815` |
| Mutation observations | `9c796bf55aaa7c74cd1c64d14c8541ba607a6ca43e17323ce1dbabc4094c7283` |

The mutation seed was `5065796730156482561`; the campaign reached 47,880 decoded
programs, 42,712 successful executions and 100,000 C-frame adapter calls. This is
bounded coverage, not exhaustive consensus or memory-safety verification. Focused
independent review found no outstanding issue in the port or CI changes.
The opt-in Nix package's derivation evaluated on the Mac; a complete Nix package
build was not run. The guardian build checks above use Cargo.

### History cleanup and per-commit validation

The original tip is preserved by tag
`simplicity-v0.12.2-before-history-cleanup-20261007`. Before reorganizing commits,
we froze the expected tree after replacing the local database fix with upstream
commit `9b2ee9036b04b24b6d85f4886d043ee77582f9d6`. That replacement changes only
`fedimint-core/src/db/mod.rs` and its `tests/wait_key.rs` regression tests.

The initial ten-commit rewrite, preserved as
`simplicity-v0.12.2-tree-verified-20261007` (`a389d1cec65`), matched that frozen
Git tree exactly: `5b9bcab7d8a5052d149ca08f7feaa05db57c3b86`.
[Its hosted checks](https://github.com/tvolk131/fedimint/actions/runs/37694661337)
also passed. The original authorship of both upstream fixes is retained.

Full-workspace compilation then caught a pre-existing test omission: the mint-v2
migration test did not handle the new `FundingReservation` database prefix.
Commit 5 now checks that the legacy snapshot contains no reservations. The touched
inline migration-test module was moved to `tests/db/mod.rs`, preserving the other
tests and their module paths. Commit 9 adds both legacy migration checks to the
release script. These test changes, and this release-note update, are the only
additional differences from the frozen tree; production code is otherwise
identical.

The corrected code candidate is `0107a0fa0e509856431fddd79acb5e144965347d`, preserved
as `simplicity-v0.12.2-history-candidate-20261007`.
[Its hosted run](https://github.com/tvolk131/fedimint/actions/runs/37699187726)
passed all six jobs, including the added migration tests and both guardian
builds. The lockfile and consensus/mutation report hashes remain those recorded
above; Linux x86-64, ARM64 and ASan observations still match byte-for-byte.

On ARM64 macOS, every commit passed
`cargo check --locked --workspace --all-targets`. Its relevant package tests also
passed in release mode with Rust 1.93.0. The package set includes core, client-module,
client, mint-v2 client, server-core and server, plus each Simplicity crate as it
enters the history; the common crate's compiler feature is enabled. Commit 5
onward also runs the two mint-v2 migration tests. Commit 8 onward additionally
checks the enabled guardian and runs all four guardian scenarios. These are
full-workspace compilation checks and focused tests, not a claim that the entire
workspace test suite ran. Passed test counts are:

| Commit | Scope | Package tests | Migration tests | Guardian scenarios |
| --- | --- | ---: | ---: | ---: |
| 1 | Guardian status liveness | 198 | — | — |
| 2 | Upstream database notifications | 203 | — | — |
| 3 | Guardian context and preflight | 203 | — | — |
| 4 | Client authorization finalization | 207 | — | — |
| 5 | Mint-v2 funding reservations | 212 | 2 | — |
| 6 | Simplicity common types and VM | 235 | 2 | — |
| 7 | Simplicity client and contracts | 283 | 2 | — |
| 8 | Simplicity server and opt-in daemon | 323 | 2 | 4 |
| 9 | Release CI | 323 | 2 | 4 |
| 10 | Design and release documentation | 323 | 2 | 4 |

The final documentation commit records this evidence without changing the tested
code, and is rechecked with the same local commands. Opt-in native mutation and
sanitizer campaigns are covered by the hosted jobs, rather than included in the
routine package-test counts. The history and test correction received independent
review.

The earlier October 6/7 evidence files identify development-branch revisions and
do not certify this branch. The following deployment checks now cover this
candidate; the [beta checklist](BETA-CHECKLIST.md) retains the longer pilot and
future upgrade work. The application and original Mac/Pi federation remain on
their existing development revisions.

### Packaged candidate and isolated Mac/Pi rehearsal

Candidate `41100ea9a5ea7b5014789bc1a28d7006da568a34` has the same code and lockfile
as the corrected hosted candidate above. On October 7 (local time), its explicit
`fedimintd-simplicity` Nix package built and ran natively on ARM64 macOS. Its
closure was 127,219,512 bytes; the output was
`/nix/store/ydjksifn13gca0png1agw47747wrp9dq-fedimintd-simplicity`.
Both deployed guardian builds reported the exact candidate through
`version-hash`. The `flake.lock` SHA-256 was
`fb4553899cb56f234b3cf639855d9e7c90ec1bf7f9961c19b16a58393167dba5`.

Linux ARM64 release binaries were built using Rust 1.93.0 and Debian 12 in an
ARM64 container, then installed and run on an 8 GB Pi 5 with Raspberry Pi OS,
16 KiB OS pages, SD storage and active cooling. The build used
`JEMALLOC_SYS_WITH_LG_PAGE=16`, generic ARM64 code and the repository release
profile. Native startup and transferred hashes passed. This qualifies that
Cargo deployment, not a Linux Nix closure. The [runbook](RUNBOOK.md) records the
build settings and dependency checks.

| Deployed artifact | SHA-256 |
| --- | --- |
| macOS Nix guardian | `3861b030521cc88abb8dda32bdc41714905bba081cf69c4d826b200ca859d980` |
| Linux ARM64 guardian | `85ebb4386cd7c1d7e8a22890f062f7b7964499508a8a5f74a4b2e48be26fd979` |
| macOS SDK wallet example | `ac9fd4cf2add415c15d8262ff54d2047519cff02a86bd48856437cf00ca64241` |
| Linux ARM64 SDK wallet example | `ad0db75435472f15f54100feec1006a63c7ec8c87f8f3edd7a62646f910c41c0` |

A fresh federation used two packaged guardians on the Mac and two on the Pi,
normal DKG/TLS/WebSocket consensus, Mint v2, Wallet v2 and Simplicity, and real
Bitcoin Core 31.1 regtest RPC. The SDK driver ran on the Mac; the Pi SDK received
a native startup check. The isolated deployment passed:

- A real 0.01 BTC deposit and a confirmed 10,000 sat withdrawal.
- Owner funding/release, sender receipts, independent YES/NO assets, pair
  issuance/recombination, and signed YES, NO and INVALID market resolutions.
- Mnemonic-only recovery, exact recoverable holdings/history comparison,
  recovered spending for all three outcomes, and fully spent owner history.
- Two funded attempts consuming the same market state: acceptance with its
  local acknowledgement withheld, restart, permanent conflict, exact original
  note release, and a successful retry against the successor.
- Process kill after durable operation submission, followed by completion
  without duplicate history; process kill during initialized recovery,
  offline confirmation that Simplicity recovery remained unfinished, then
  reopening and completing recovery. That recovery had cursor/progress zero;
  this does not demonstrate resumption from a partially scanned nonzero cursor.
- One guardian offline at a time, with graceful stops and abrupt kills on both
  hosts, transactions accepted by the remaining quorum, and catch-up afterward.
- Restoring one guardian from populated checkpoint 4 while peers had completed
  six sessions. The checkpoint already contains session 4; replay catches up
  through session 5. Outcomes 4 and 5 matched across all four peers; market
  vaults, asset origins and spent authority removal also agreed. The replaced
  current database was retained, and the frozen checkpoint was unchanged.

One comparison initially included nine spent public market predecessors that
Bob had only watched before participating. The recovery contract excludes that
local-only watch cache. The corrected assertion excludes exactly those known
predecessors and their watch-only references, while comparing every owned and
recoverable interaction and its full transaction ID. Independent review checked
this boundary; no production fix was needed.

Final log inspection also found startup `WriteConflict` panics in
`submit_guardian_metadata` on the Pi. That handler is byte-for-byte unchanged
from official v0.12.2: concurrent updates use `commit_tx()` without retrying the
optimistic transaction. The API catches the panic and returns an error; the
service retries, and both guardians subsequently completed the qualification.
This is an upstream metadata-availability/logging follow-up, not a Simplicity
consensus failure. It is retained with the evidence rather than silently counted
as a clean log or folded into this module's patch set.

Private baseline fixtures contain the populated guardian checkpoint, two market
wallets with versioned descriptors, and two funded pending-intent wallets.
All 74 files are checksummed. Disposable wallet copies loaded with OS-enforced
network denial; template commitments and holdings/history matched, and both
pending intents and their transaction/funding records were interpreted. The
live checkpoint restoration supplies the guardian-loading check. These are
same-version fixtures for a future upgrade test, not evidence of an upgrade
that has not happened yet.

A 60-second idle sample and 900-second functional-workload sample recorded Pi
resources while the existing federation and other host workloads remained
running. Sampled resident memory stayed below 178 MiB per candidate Pi guardian
(process high-water marks below 190 MiB); sampled temperature reached 57.3 C.
Kernel-attributed writes remained about 1.2 MiB/s per candidate guardian even
at idle, versus about 22 KiB/s of logical syscall writes at idle. These counters
are not NAND wear measurements. Whole-device SD counters include the original
federation and filesystem activity. This short run does not establish saturated
throughput, storage endurance, or DoS immunity; the existing storage concern
remains. All isolated services were stopped after qualification.

The private evidence bundle is retained outside build caches as
`simplicity-v0.12.2-20261007`, with source, drivers, artifact identities, raw
results and an offline fixture-loader command. It contains guardian secrets,
synthetic mnemonics and regtest ecash: do not publish it or activate duplicate
wallets. Only this summary is committed. The deployment and documentation
received independent review. These follow-up commits change documentation
only; the tested production code remains the candidate identified above.

## Maximal-pruning qualification: October 8, 2026

The code candidate is `928747c0538e8ee037b23172c471399c3bba325a`, appended to
`0a65bebec807b0aafb4920781f88fb8f4d8692d0` without rewriting the prior release
history. Cargo.lock SHA-256 is
`5e4e619d073fb822ad29bc3fb95d2eb56af6f43f85f529dd6d143bd69b989751`.
This is a fresh-federation qualification with matching clients and guardians;
it does not certify replay of old unpruned history or mixed-version deployment.
No consensus version was bumped for this undeployed rule change.

Guardians track execution in the normal VM pass and reject unnecessarily
revealed nodes or case branches. The SDK prunes against the actual transaction
and resolved contract metadata, retaining the original template for future
witnesses and contexts. A pinned-compiler pruning defect required rebuilding
inferred types after hiding branches; canonical decoding remains strict. Tests
cover hidden witness bits, shared DAGs, both execution versions, signed
transactions, changing clocks, market branches, pruning-aware fees and funding
rollback. A deterministic shared-contract race first failed, then passed with
one bounded automatic refresh/rebuild; manual and repeatedly stale plans stop
without submitting an attempt. The implementation received independent review.

[The candidate's hosted run](https://github.com/tvolk131/fedimint/actions/runs/37827166742)
passed all six jobs, including module/shared tests, the four guardian scenarios,
example compilation, Clippy, repository lint, both guardian builds, native
architecture agreement and ASan/leak checks.
The local ARM64 Mac passed 336 module/shared tests, all four network scenarios,
module Clippy and benchmark fixture checks; the two legacy mint-v2 migrations
also passed. The unchanged VM/common code's Mac observations match the final
Linux x86-64, Linux ARM64 and Linux ASan reports byte-for-byte:

| Report | SHA-256 |
| --- | --- |
| Consensus observations | `9ffdc38ba954ae679e8334fd199f02ee41709d6e591148b870a81fac865803ef` |
| Mutation observations | `bfa67e32711670a99a7bc455680808c02a7262ace9922b277ff6e2e92c45939c` |

The 100,000-mutation campaign used seed `5065796730156482561`, reaching 41,920
decoded programs, 30,673 successful executions and 100,000 C-frame adapter calls.
These remain bounded checks, not exhaustive consensus or memory-safety proofs.

The final native macOS Nix guardian package built and reported the exact
candidate. Linux ARM64 binaries used Rust 1.93.0, Debian 12, generic ARM64 code,
`JEMALLOC_SYS_WITH_LG_PAGE=16` and release optimization. The shared Docker VM
ran out of compiler memory with the normal profile; the qualified Linux build
sets `CARGO_PROFILE_RELEASE_LTO=false`, `CARGO_PROFILE_RELEASE_DEBUG=0` and
`CARGO_BUILD_JOBS=1` for all dependencies and binaries. It is a Cargo deployment,
not a Linux Nix closure; the Mac package retains the normal Nix build profile.

| Deployed artifact | SHA-256 |
| --- | --- |
| macOS Nix guardian | `79fa21e0a092c8f8ff25da1c19001bd6a09d35a15632cfa549669930550c299c` |
| Linux ARM64 guardian | `aa44f91fe763f50c6452775a1aca6ae07ead143cb34401d0a1df732342b8dbe2` |
| macOS SDK wallet example | `5b3b17a27f8a6b0804b53d5aad0ef01c755891a3bd60bf45556afea4b1888161` |
| Linux ARM64 SDK wallet example | `445ab1c1956ffbdc0945024762b4b287ae2a40e11b1acb0a6786c056f1dc02ec` |


A new isolated federation ran two packaged Mac guardians and two Pi guardians
with real Bitcoin Core regtest funding. It passed the owner and three-outcome
market lifecycles, fully spent history recovery, mnemonic recovery followed by
spending, lost acknowledgement/conflict/funding reuse, and client process kills
after durable submission and during initialized recovery. As before, the
recovery kill occurred at zero progress; it does not certify nonzero-cursor
interruption. The private 71-file checkpoint/wallet/template/pending-intent
baseline loaded its four wallet copies with networking denied.

All four individual guardian outage/rejoin cases passed, followed by a confirmed
10,000 sat withdrawal. Guardian 2 restored checkpoint 0 and caught up through
session 2. Checkpoint 0 already contains session 0; replay applied sessions 1
and 2. Signed outcomes 0–2 and all three final market vaults/asset origins agreed
across the four guardians; the replaced database and frozen checkpoint were
preserved. The driver's first post-restoration read was premature: the final
vault transactions belonged to still-open session 2, whereas its readiness check
covered only completed sessions. After that session closed, all comparisons
passed without another restoration or transaction submission. The retained
driver now waits through the previously open session before comparing state.

Five caught `submit_guardian_metadata` WriteConflict panics recurred on the Pi,
from the unchanged upstream v0.12.2 handler described above. Guardian shutdowns
also logged expected Aleph shutdown/channel-closure errors during the deliberate stops.
These are retained in the evidence; no Simplicity consensus/replay failure was
observed. The application and original federation were not upgraded.


Two before/after timing runs per revision used the System allocator and 100
one-iteration samples per case on the ARM64 Mac. The old revision was the parent
named above; our compiler container was paused, but other user workloads
continued and were recorded. In-memory core-submission median ranges were:

| Fixture | Before | With pruning |
| --- | ---: | ---: |
| Market issuance | 1.349–1.366 ms | 0.638–0.801 ms |
| Market resolution | 1.440–1.454 ms | 0.877–1.132 ms |
| Packed constants | 17.74–18.07 ms | 17.28–18.30 ms |
| Two deep chains | 15.23–15.34 ms | 15.04–15.54 ms |
| Late failing mixed workload | 20.75–20.91 ms | 20.18–21.41 ms |

The market fixtures intentionally change their submitted representation:
issuance program/witness bytes fall from 1,359/66 to 599/1, and its input fee
from 1,661 to 777 msat; resolution falls to 806/66 bytes and 1,104 msat. Fee
coefficients are unchanged. These short, warm-database comparisons exclude
networking/consensus and client-side pruning; ambient load prevents treating
small timing differences as regressions or improvements. They do not establish
Pi throughput, worst-case latency, or a DoS bound.

The 60-second idle and 900-second functional-window samples recorded Pi RSS
below 188.4 MiB per guardian and sampled process high-water marks below
189.8 MiB. Temperature reached 60.05 C; the final throttling status was zero.
Idle kernel-attributed writes were about 1.24 MiB/s per guardian versus about
24 KiB/s of logical syscall writes, consistent with the pre-existing write
amplification concern. Whole-device counters include the original federation
and other filesystem activity and do not measure NAND wear. The functional
window includes waiting/idle time and concurrent host workloads; it is not a
sustained-load or storage-endurance qualification.

All isolated services were stopped after the checks. The private evidence
bundle `simplicity-v0.12.2-pruning-20261008` is retained outside build caches,
including source archives, build settings, artifact hashes, frozen fixtures,
raw logs and public hosted reports. Its Mac Nix closure is protected by a local
GC root. The bundle contains guardian secrets and synthetic wallet material:
do not publish it or activate duplicate wallets. This documentation follow-up
changes no production code.

## Upgrade activation qualification: October 9, 2026

The upgrade-aware code candidate is
`62f13634bcc233c92f1af41bbcc7744895c9c0e5`: implementation `52e92a62915` plus
a one-line switch to Fedimint's runtime sleep wrapper required by Linux Semgrep.
It establishes the fresh `0.2` configuration baseline. The dependency lockfile,
jet implementation and execution runtime are unchanged from the qualified pruning
candidate; contract execution versions, commitments, descriptor formats and fee
coefficients remain unchanged.

Local Mac checks passed 134 tests/scenarios across common, client and server code,
including four real four-guardian network scenarios. Eleven new regressions cover
readiness with outdated/offline/malformed/silent peers, ordered threshold
activation, minority/invalid votes, unsupported-binary stopping, real RocksDB
reopen and pre-activation checkpoint replay, support/active API separation,
input/output activation gates before decoding, unchanged v0/v1 spending and fees,
future consensus-item encodings, and signed mnemonic-history recovery. Clippy,
formatting and the local repository hooks passed. Independent implementation and
runtime-wrapper reviews reported no blockers.

[The final hosted run](https://github.com/tvolk131/fedimint/actions/runs/37977337010)
passed all six jobs: 347 module/shared tests, two legacy mint-v2 migration tests,
the four network scenarios, example compilation, Clippy, repository lint, both
ordinary and Simplicity-enabled guardian builds, native architecture comparison,
and ASan/leak checks. The initial run's only reported failure was the Linux
Semgrep sleep-wrapper rule; the final candidate resolves it.

The final Linux x86-64, Linux ARM64 and ASan consensus/mutation observations match
the Mac reports byte-for-byte, with the same hashes recorded in the preceding
pruning qualification. The sanitizer run also passed its deliberate overflow
and leak controls. These remain bounded checks, not exhaustive consensus or
memory-safety proofs.

The tests simulate a successor supporting version `0.3` while retaining the two
existing execution environments. There is no production `0.3` feature set in this
release. A concrete future release adding jets, contract formats or other rules
must retain old semantics and receive its own mixed-binary activation rehearsal.

The Mac's 100,000 seeded mutations used seed `5065796730156482561`, decoded 41,920
candidates, successfully executed 30,673 and made 100,000 C-frame calls. Its
consensus and mutation observations match the earlier pruning candidate; the
new envelope has separate fixed-vector tests. Mac reports were collected at
`52e92a62915`; the common crate is byte-identical at `62f13634bcc`.

This qualification does not deploy the new baseline onto the existing Mac/Pi
federation. Earlier `0.1` prototype envelopes/configurations are incompatible.
Fresh `0.2` deployment artifacts, guardian/wallet fixtures and the chosen testnet
pilot remain deployment work; earlier Mac/Pi artifact identities and restoration
evidence must not be attributed to this candidate.

The private evidence bundle `simplicity-v0.12.2-upgrades-20261009` is retained
outside build caches with the candidate source, environments, local and hosted
logs, reports and a checksum manifest. Only this summary is committed; this
qualification follow-up changes no production code.

## First-beta 0.1 qualification: October 9, 2026

Candidate `d64925adb96b9705507cefd0786ef22ce44044ea` relabels the unreleased
upgrade-aware baseline as module config/consensus/API `0.1`. Tests now emulate
successor `0.2`; no production `0.2` feature set is introduced. Contract execution
versions 0/1, dependency locks, VM/jets, fees and descriptors are unchanged.
Earlier qualifications retain their original version labels and source identities.
A fresh federation is required: earlier prototypes also called `0.1` are not a
migration source. The existing application federation was left in place.

The Mac passed 130 ordinary module tests, Clippy and repository commit hooks.
Two explicit observation/mutation tests passed all 100,000 seeded cases. Linux
ARM64, Linux x86-64, Mac ARM64 and Linux ASan observations match byte-for-byte,
with the same report hashes and campaign counts recorded above.
[All six hosted jobs passed](https://github.com/tvolk131/fedimint/actions/runs/38019201881):
repository lint, both native architectures, their comparison, Linux ASan/leak
checking, and the combined module/shared/guardian job. The last job passed 347
ordinary module/shared tests, two mint-v2 migration tests, four network tests,
module Clippy, example checks, and ordinary/opt-in guardian builds. Hosted build
provenance is the exact checkout and retained release environment; `--version`
reports `fedimintd 0.12.2` for both variants.

The fresh rehearsal used two Mac guardians from the opt-in Nix package and two
Pi guardians built in native Linux ARM64 with Rust 1.93.0. Linux used release
optimization, LTO disabled, debug info disabled, one build job and
`JEMALLOC_SYS_WITH_LG_PAGE=16`; startup and hashes were verified on the Pi's
16 KiB-page Debian 13 OS. The initial 3 GiB compiler-container limit caused a
confirmed cgroup OOM in `fedimintd`; the unchanged build passed with 5 GiB.
This was a build-resource failure, not a module test failure. The Mac SDK and
private rehearsal example were built from the candidate archive. The guardian
artifacts report the candidate Git hash:

| Artifact | SHA-256 |
| --- | --- |
| Mac Nix guardian | `a06245929d5e6aa6a1bbca8df23123628aa376de09854aac4423e7013af10e7c` |
| Linux ARM64 guardian | `83cf277c5e8e11d37d370a544f298c8850a468dac4b7c53169ba7a1e3e17e7ef` |

The four-guardian rehearsal passed:

- Real Bitcoin Core regtest deposit and confirmed 10,000-sat withdrawal.
- All peers reporting config, supported and active version `0.1`, including
  after guardian restarts and checkpoint restoration.
- Owner and market mnemonic-only recovery, identical recoverable holdings and
  confirmed history, followed by spending; YES, NO and void market outcomes.
- Competing intents, lost acknowledgement, funding reuse, and recovery of a
  pending wallet operation after a forced process kill.
- Recovery killed with durable cursor `1`, target `3` and incomplete progress.
  Offline database inspection proved completed historical sessions remained
  unprocessed; restart recovered identical holdings and 22 history entries.
- Each guardian stopped or killed individually, continued transactions with
  the remaining quorum, and catch-up after restart.
- Restoration of the session-0 guardian checkpoint, matching all four signed
  session outcomes through session 3 and all three markets' asset/vault records.
- A frozen 71-file compatibility baseline: two recovered market wallets, two
  pending-intent wallets and a guardian checkpoint. Disposable wallet copies
  loaded with OS-enforced network denial and reproduced template commitments.

The market-history comparison preserves the documented boundary:
locally watched, spent public vault predecessors are not wallet-owned recovery
records. The recovery checks used the software, mnemonics and federation, with
no external wallet backup file.

The 60-second idle and 900-second functional-window samples recorded Pi RSS
below 189 MiB, sampled process high-water marks below 191 MiB and temperature
below 59 C; final throttling status was zero. Idle kernel-attributed writes were
about 1.24 MiB/s per guardian versus 22.5 KiB/s of logical syscall writes. This
repeats the existing upstream write-amplification concern. Whole-device counters
include other services; kernel accounting is not NAND wear. The window includes
waiting/idle periods and competing host workloads, not saturated throughput,
storage endurance or a DoS bound.

Five caught upstream `submit_guardian_metadata` WriteConflict panics recurred
on the Pi. All other error-level entries were expected consensus-network stream
closures during deliberate shutdowns. No other panic or unsupported-version
error was observed. The guardians continued and passed the live checks; the
metadata conflict and background write volume remain separate upstream concerns.
The proposed [metadata retry fix](https://github.com/fedimint/fedimint/pull/9313)
is still open at qualification time and is not included in this candidate.

All isolated rehearsal services were stopped. The private evidence bundle
`simplicity-v0.12.2-beta01-20261009` is retained outside build caches with source,
build settings, tested Mac/Pi binaries, SDK probes, fixtures, logs and hosted
reports. All 991 manifest entries and the original 71 fixture checksums were
verified after copying; the tested Mac Nix closure has a persistent GC root.
The relabel, rehearsal harness and retention helper passed independent review.
This qualification follow-up changes no production code.

These checks qualify the fresh baseline for a controlled testnet beta using the
documented artifact paths. Deployment storage, operators, Bitcoin backends and
a small signet pilot remain to be chosen/run before a broader beta. Longer load
and fuzzing campaigns remain ongoing hardening; a feature-bearing successor
needs its own mixed-binary upgrade rehearsal.

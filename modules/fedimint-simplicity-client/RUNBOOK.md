# Simplicity testnet beta: guardian and native SDK walkthrough

This is an unaudited, opt-in module on Fedimint v0.13.0. Use a new federation
on a Bitcoin test network. These instructions prepare a native SDK deployment,
not a migration from disposable prototypes. The execution-version-1 candidate
has not been publicly released for real-money use. The
[execution baseline](../fedimint-simplicity-common/README.md#beta-execution-baseline)
defines the versions and rules all guardians must preserve.

Track current qualification gates in the [beta checklist](BETA-CHECKLIST.md).
The [evidence index](EVIDENCE.md) preserves port provenance and earlier rehearsals
at their exact documented revisions; none qualifies the current candidate.

The default core wallet registers only the single-key owner template and no
application intent handlers. Market/exchange/top-up implementations are separate
reference consumers. Applications explicitly register their templates/handlers
and bundle historical definitions in compatible wallet binaries. Keep the exact
application revision with deployment records; recovery must not require fetching
source or an external metadata backup.

## Build and identify the artifact

Use one reviewed, clean Git commit on every guardian. Preserve its commit ID,
`Cargo.lock`, and `flake.lock` with the release record. The normal daemon package
does not enable Simplicity. Build the explicit artifact:

```sh
nix build .#fedimintd-simplicity
./result/bin/fedimintd --version
./result/bin/fedimintd version-hash
```

This is a Nix package, not a standalone portable executable; deploy its closure
with normal Nix tooling or build the same pinned source on the destination.
The equivalent Cargo build is:

```sh
nix develop -c cargo build --locked --release -p fedimintd --features experimental-simplicity
```

For Raspberry Pi OS on a Pi 5, check `getconf PAGESIZE` before building. The
historical qualification machine used 16 KiB OS pages. The Linux ARM64 Cargo build below
uses jemalloc's logarithmic page-size setting `16` (64 KiB), which supports
that page size; it does **not** mean 16 KiB. Build in an ARM64 Linux environment
with Rust 1.93.0, Clang/libclang, CMake, pkg-config, protoc, and SQLite development
libraries. The [historical packaged rehearsal](EVIDENCE.md#beta-and-release-history)
used Debian 12 in an ARM64 container, with native execution on Raspberry Pi OS.
That was not a Linux Nix-package test or qualification of this candidate.

```sh
CARGO_BUILD_JOBS=1 CARGO_PROFILE_RELEASE_LTO=false CARGO_PROFILE_RELEASE_DEBUG=0 \
JEMALLOC_SYS_WITH_LG_PAGE=16 CC=clang CXX=clang++ \
RUSTFLAGS='--cfg tokio_unstable' \
cargo build --locked --release -p fedimintd -p fedimint-cli \
    -p fedimint-simplicity-client --features fedimintd/experimental-simplicity \
    --bins --example wallet
```

The recipe disables cross-crate LTO and debug information to reduce build-memory
requirements. Record these settings with the artifact and qualify it on the
destination; the Nix package uses its normal profile.

Avoid `target-cpu=native` when the build host differs from the destination.
Preserve the exact source revision when building from an archive; Fedimint's
`FEDIMINT_BUILD_FORCE_GIT_HASH` must identify that verified source, not an
unverified label. Copy the daemon, CLI and wallet example into a new deployment
directory. Check hashes before and after transfer, inspect dynamic dependencies
with `ldd`, and run `--help` and the daemon's `version-hash` on the destination
before creating the federation. These Cargo executables depend on their target
system libraries; they are not a portable Nix closure.

Before distributing a candidate, run the [focused release checks and repository
lint](../fedimint-simplicity-server/TESTING.md#release-qualification), keeping logs
tied to the exact revision and platform. Native architecture comparison and
sanitizers remain separate candidate-specific workflow gates.

The guardian network tests bind local ports. These tests include simulated
Bitcoin funding; a real Bitcoin RPC deployment exercise remains a separate
release check. The example below is built from source, not published to
crates.io: its compiler dependency is pinned to Git.

## Configure the guardians

Follow the normal [federation setup procedure](../../docs/deploying.md) with
four guardians for the beta. Each uses its own persistent data directory and
the same chosen Bitcoin network. Configure `FM_BITCOIN_NETWORK` explicitly
(for example `signet`); the daemon defaults to `regtest`. Use corresponding,
trusted Bitcoin RPC backends and the ordinary RPC credential settings described
by `fedimintd --help` and [SECURITY.md](../../SECURITY.md#guardian-bitcoin-backends).

Keep the admin UI on its trusted interface, configure its authentication, and
expose only the intended API/P2P endpoints. Configure addresses and transport
using the standard daemon settings; this module adds no submission or recovery
listener. In the lead guardian's setup form, explicitly select `simplicity`
alongside the funding modules. This walkthrough requires a bitcoin-denominated
`mintv2`; retain the normal wallet/Lightning modules used to fund the federation.
Check that every guardian's binary offers Simplicity and that their agreed
module list includes it before completing DKG. Module instance IDs come from
the federation config, not this guide.

Retain the existing Bitcoin/backend, consensus, API and disk monitoring. Record
the deployed binary, configuration and database checkpoint together. Never
prune session history needed by this module: spent-output deletion is safe
because the original encrypted descriptors and sender receipts remain in that
history. Asset origins and namespace-use records are also permanent.

## Run the SDK example

[examples/wallet.rs](examples/wallet.rs) uses the real native client, RocksDB,
normal invite/config acquisition, Mint v2, and the persistent Simplicity API.
It supports join, recovery, status/history, receiving ecash, owner-contract
funding, and release back to ecash. Application-specific market policies live
with their separate reference consumers; this example is not a trading application.

Build from the same source in the development shell:

```sh
cargo build --locked -p fedimint-simplicity-client --example wallet
```

Use a fresh test mnemonic. The example reads it from stdin on every invocation,
using Fedimint's standard BIP-39 root-secret derivation; it neither writes a
separate seed file nor accepts the mnemonic as a command-line argument. This
Bash helper reads it without echo or shell history, then passes it through a
pipe. Keep shell tracing disabled:

```bash
set +x
umask 077
read -r -s -p 'Test wallet mnemonic: ' simplicity_mnemonic
printf '\n'
simplicity_example="$PWD/target/debug/examples/wallet"
simplicity_wallet_dir="$PWD/simplicity-wallet"
simplicity_wallet() {
    printf '%s\n' "$simplicity_mnemonic" |
        "$simplicity_example" --data-dir "$simplicity_wallet_dir" "$@"
}
read -r -p 'Federation invite: ' simplicity_invite
simplicity_wallet join "$simplicity_invite"
```

Obtain Mint v2 ecash from a funded test wallet in the same federation, for
example using its normal `fedimint-cli module mintv2 send` operation. Import it
as the second stdin line so bearer ecash also stays out of command arguments:

```bash
read -r -s -p 'Mint v2 ecash: ' simplicity_ecash
printf '\n'
printf '%s\n%s\n' "$simplicity_mnemonic" "$simplicity_ecash" |
    "$simplicity_example" --data-dir "$simplicity_wallet_dir" receive
unset simplicity_ecash
simplicity_wallet lock 100000
simplicity_wallet status
```

`lock 100000` locks 100 sats and requires additional ecash for fees. It prints
the operation ID and contract outpoint before waiting for confirmation. Release
that owner contract using its printed transaction ID and output index:

```bash
simplicity_wallet release TRANSACTION_ID 0
simplicity_wallet status
```

Replacement Mint v2 notes are processed by the ordinary client state machines;
reopening the same database resumes them. If a command is interrupted, use
`simplicity_wallet wait OPERATION_ID` with the recorded operation ID, or inspect
status after reopening. Do not repeat an operation merely because a response was
lost. Inspect a recorded operation without waiting for a federation-history sync:

```bash
simplicity_wallet operation OPERATION_ID
```

`submitted` means its local submission is pending; `accepted_syncing_history`
means acceptance is known but confirmed history is still being synchronized.
`complete` means Simplicity history is synchronized, although another module's
change processing may still be pending. `rejected` does not by itself authorize
funding release. `unknown_local_operation` is also normal for original operation
IDs after mnemonic recovery; inspect confirmed history instead.

The SDK's `operation_status`/`await_operation` and `intent`/`await_intent` methods
expose durable status. A pending transaction retains its funding; cancellation
does not prove rejection or authorize releasing notes.

## Recover and verify

Stop the original client. Use the same mnemonic, same wallet software and same
federation invite with a fresh database directory:

```bash
simplicity_wallet_dir="$PWD/simplicity-wallet-recovered"
simplicity_wallet recover "$simplicity_invite"
simplicity_wallet status
unset simplicity_mnemonic
```

The example passes `None` for the backup snapshot, waits for module recovery,
then reopens the client. While waiting it displays the existing core recovery
progress counters, suppressing duplicate/unchanged percentage updates. Progress
alone cannot report failure or prove completion; the example also waits on the
core's recovery outcome API and propagates failures. Compare holdings and
confirmed transaction IDs with the original view, including transactions whose
contracts have all been spent.
For a spendability check, first retain a funded owner contract and release it
from the recovered wallet. Required inputs are wallet software, mnemonic and
the original federation; no external backup file or deprecated backup service
is used. Retain historical template support in the wallet software.

The example prints public amounts/outpoints and history summaries, not decrypted
descriptors or receipt application data. Protect the local database: it contains
decrypted wallet material. Recovery does not recreate abandoned intents,
original local operation IDs, local-only labels or watch-only subscriptions.
Low-level program imports have no implicit recovery guarantee.

For application wallets, importing a public contract through the watch API alone
is a local subscription.
Participation can store its encrypted descriptor in federation history, but
previously observed public predecessors from before that participation need
not be reconstructed. Compare owned contracts and recoverable interactions,
not the complete local watch cache. This does not permit dropping confirmed
wallet interactions or fully spent owned-contract history.

## Upgrading a federation

### Current candidate: fresh deployment

The v0.13.0 candidate has no deployed state to migrate. Create a fresh federation
with matching guardian and client revisions. Qualify restart, checkpoint
restoration, quorum catch-up, mnemonic-only recovery and spending contracts
created before the restart. Retain this candidate's configuration, history,
checkpoints, wallet descriptors and exact binaries as the first deployment
baseline for future upgrade tests. This is not a promise to import prototype
wallets or perform a cross-core upgrade from v0.12.2.

The first upgrade-aware deployment uses configuration baseline `0.1`.
Earlier prototypes, including those also labeled `0.1`, have
a different consensus-item wire format. The pre-release number was reused; use
the qualified source revision and artifact hashes to identify this baseline.
Do not open old prototype databases with these binaries.

Earlier prototype transitions are [historical evidence](EVIDENCE.md#beta-and-release-history),
not deployment procedures. Retained-checkpoint migration tests are bounded
regressions, not a cross-core upgrade or template-recovery guarantee. After the
first deployment, compatible releases must retain historical template definitions
and recovery support; predeployment resets do not authorize discarding them.

### Module upgrade votes

For a future compatible release, install reviewed binaries on every guardian.
They keep enforcing the active rules until all peers advertise sufficient support
and ordered consensus votes activate the successor. Read each guardian's module
`supported_consensus_version` and compare with the quorum-authenticated
`active_consensus_version`. A missing or outdated peer delays automatic voting.
Readiness can become stale if a guardian goes offline after answering; preserve
normal quorum availability during the rollout.

After activation, verify convergence, historical contract spends and recovery.
Do not reinstall an older binary as a rollback: it must refuse the activated
state. Restore with a binary supporting both the checkpoint and subsequent
history. Never edit votes or the original configuration version to bypass this
check. An old wallet encountering unsupported active rules needs a software
update; restoring the mnemonic does not add missing protocol support.

This release introduces the mechanism, not a production successor. Tests emulate
a successor retaining existing execution environments. The first release adding
jets or other rules needs its own mixed-binary activation rehearsal and fixtures.

## Operational failures and restoration

### Backup, restoration and coordinated halt

Rehearse these steps on the exact candidate before broader beta. Record the
responsible operator, guardian identities, host failure domains, source revision,
artifact checksums, checkpoint/session information, results and private evidence
locations. This procedure does not qualify a prototype migration or a rolling
mixed-version upgrade.

1. **Prepare recoverable backups.** Preserve each guardian's own configuration,
   encrypted secrets and required decryption credentials, exact binary identity,
   and a supported database checkpoint or consistent stopped data-directory
   copy. A guardian configuration backup alone does not retain the database or
   authenticated session history needed for client recovery. Do not copy an
   actively written RocksDB directory as if it were a consistent backup. For a
   stopped copy, stop that guardian through its normal service/process manager
   and wait for process exit before copying; keep a quorum running for routine
   maintenance. In a four-guardian federation, stopping a host with two guardians
   loses quorum. Preserve client mnemonics and baseline fixtures separately.
2. **Retain and verify off-host copies.** Encrypt sensitive backups, restrict
   access and hold decryption credentials separately. Verify checksums after
   copying, and rehearse opening/restoring the
   retained copy rather than trusting file presence. Archive required history
   and selected checkpoints outside automatic retention, build caches and CI
   artifact expiry. Document backup frequency, retention, the expected recovery
   point and who holds the credentials. Never publish databases, mnemonics or
   secrets as release evidence. Do not prune history required by supported
   contracts, receipts or mnemonic recovery to meet a storage target.
3. **Restore the same guardian safely.** Keep the original guardian stopped
   and prevent its automatic restart before starting a restored copy with that
   identity. Never run two instances using the same guardian secrets. Preserve
   the failed/current database for diagnosis, restore a supported checkpoint
   with its matching configuration and secrets, and use the qualified binary.
   Coordinate reconnection with the other operators and verify catch-up against
   their authenticated history. Wait for expected signed transaction outcomes,
   inspect the relevant contract records and spend an unspent contract created
   before the checkpoint/restart. Rehearse mnemonic recovery and spending with
   the matching client. Session counters alone are not sufficient evidence.
4. **Coordinate an emergency halt.** Agree in advance who can call a halt and
   who may authorize reopening. Pause pilot applications and ask participants
   not to submit or retry operations; preserve pending operation records rather
   than assuming they were rejected. Stop the affected guardians through the
   deployment's normal shutdown procedure, disable automatic restart during
   investigation, and verify process exit. A coordinated federation-wide halt
   intentionally stops consensus. Secure stopped database copies, logs, metrics
   and artifact/configuration identities before making changes. Resolve and
   privately escalate unexplained validation or accounting failures as needed.
5. **Verify before reopening.** Resume only the agreed matching candidate and
   compatible state under operator coordination. Check quorum progress, signed
   outcomes, contract/accounting state, backend health and a bounded test payment
   before reopening applications. An older database or binary is not a generic
   rollback after newer state has been accepted; do not delete consensus items
   or edit reservation records to make the federation appear healthy. Follow
   the incident guidance below if restart repeats the failure.

For a private signet pilot, record the intended observation window and monitoring
limits before starting: consensus progress, API/validation latency, admission
backlog, memory, disk capacity/write growth and Bitcoin backend health. Assign
operators to review timestamped samples and alerts. Unexpected accounting or
recovery results, sustained lack of progress, or breached resource limits require
pausing traffic and operator review; specify whether they require a full halt in
the deployment plan. Record deposits, withdrawals, restart/restoration and
mnemonic-recovery results. Only an observed, reviewed pilot completes its
checklist gate; these instructions do not claim that it has run.

### Recovery and pending operations

If recovery stalls, check guardian reachability, available authenticated history,
supported descriptors and local disk space. Preserve the same database so the
scan can resume. Missing/unauthenticated history must not be skipped to report
completion. A pagination cursor becoming stale means restart that local listing;
it does not mean restarting recovery.

After interrupting `recover`, run `simplicity_wallet status` with the same
recovery directory and mnemonic. It opens the existing database, waits for
recovery, and reopens the usable modules. `recover` itself initializes a fresh
database; do not repeat it against an initialized directory.

For pending funds, inspect the recorded operation/intent and resume the same
client. An unproven rejection can require attention while notes remain reserved.
Only definitive rejection plus authenticated permanent conflict permits local
funding release. Never manually edit reservation records to clear a balance.

Restore a failed guardian through Fedimint's normal restoration procedure using
its preserved configuration, secrets and supported database checkpoint. Retain
or restore the federation history required for client recovery and verify
catch-up against the other guardians. Do not let a stale restored guardian act
as an independent federation. History/checkpoint retention and restoration must
be rehearsed before opening the beta broadly. A completed-session counter does
not prove that transactions in the still-open session have replayed. Wait for
the relevant signed outcomes and verify the expected transactions and contract
records before declaring restoration complete.

Monitor disk growth and consensus progress during load. Per-transaction caps do
not limit the number of concurrent submissions. Program decoding and execution
run on dedicated threads: one for agreed transactions, and for submissions a pool
of half the CPU cores (one to eight threads). At most twice that many submissions
hold decoded programs at once. Others wait for admission before decoding rather
than being refused, so heavy submission load shows up as slower submission
responses and a rising `fm_simplicity_admission_waiting`. Agreed transactions
never wait for admission or queue behind submissions, but all these threads share
the CPU, so heavy submission load can still slow consensus, especially with two
guardians on one board. API requests keep running after their client
disconnects, so connection limits do not cap this load. Keep a coordinated
rollback/upgrade plan:
restoring an old binary or old database is not automatically safe after newer
state is accepted.

### Validation takes unexpectedly long

If the consensus session stops advancing, or validation/admission gauges remain
high, collect evidence before restarting:

1. Compare each guardian's session progress and timestamped samples of
   `fm_simplicity_validation_active` by `phase`,
   `fm_simplicity_admission_waiting`, `fm_simplicity_validation_seconds`, and
   `fm_simplicity_validation_calls_total`. Record host CPU, memory, disk and
   thermal state. Active calls include waiting; these gauges alone cannot
   identify a transaction whose validation takes unexpectedly long.
2. Preserve logs around the last advancing session. In retained `fm::consensus` trace logs, inspect
   `Processing consensus item` and the session/item indices; correlate any
   available transaction hash with client submission records. Metrics contain
   no transaction identifiers. Do not submit the transaction again to diagnose it.
3. Capture per-thread CPU observations and, with appropriate local diagnostic
   tooling, thread stacks. Inspect `simplicity-consensus-0` and
   `simplicity-submission-0` through the configured submission pool's last
   index. Preserve timestamps, binary revision/hashes, configuration, logs,
   metric samples and a stopped database copy securely. A transaction may not
   be identifiable from the available logs; record that limitation.
4. Report privately to the maintainers with the evidence and any identified
   transaction. Do not publish the transaction or sensitive database material.

A full process restart clears in-memory submission work, admission permits and
worker pools, but clients can resubmit. Disconnecting a client does not cancel
its API request; dropping a waiting caller does not interrupt a running worker
job. Restart is therefore not a durable remedy. Consensus recovers its persisted
session and replays agreed items; already committed items are skipped, but a
transaction already in an agreed consensus item that has not committed will be
validated again on restart, so a restart may not clear the condition. Preserve
the database and coordinate with maintainers rather than deleting history or
editing consensus items. Follow the backup-based rollback procedure above only
as a coordinated restoration.

## Validation metrics

The module uses the existing guardian Prometheus endpoint. Scrape each guardian
process separately, including two guardians sharing a Pi; keep the existing
metrics endpoint access controls. The module adds five metric families:

- `fm_simplicity_validation_seconds`: histogram of hook wall time by `phase`.
- `fm_simplicity_validation_calls_total`: finished/dropped hook calls by `phase`
  and fixed `outcome` category (`ok`, `interrupted`, or a rejection category).
- `fm_simplicity_validation_active`: calls currently inside each hook, including
  those awaiting database access, admission or a worker thread. This is not a
  queue-length or CPU-use gauge.
- `fm_simplicity_admission_waiting`: submissions waiting for admission before
  decoding their programs. A sustained non-zero value means submissions arrive
  faster than this guardian can check them.
- `fm_simplicity_program_cache_total`: decoded-program cache lookups by `outcome`
  (`hit` or `miss`). A miss decodes the program.

The four phases are `structure` (cheap transaction checks), `resolve` (stored
contract reads), `prepare` (decoding, commitments and aggregate cost checks), and
`validate` (asset accounting, context construction and program execution).
Structure/preparation run per module kind; resolution/validation run per
instance. All instances are aggregated in these metrics.

These measure work attempts in both admission and consensus, including retries;
they are not unique transaction counts. An `ok` hook can be followed by a later
rejection or rollback. `interrupted` means the call was dropped without returning
an outcome, such as task cancellation. Timings include waiting and are not pure
CPU measurements. Counters reset on process restart. No metric changes fees,
validity, or admission behavior.

Outcomes include `resource_limit`, `program`, `commitment`, `program_rejected`,
`unknown_contract`, `assets`, and signature/context categories. In particular,
`unknown_contract` also covers ordinary shared-contract races; rejection rate
alone is not evidence of an attack. Labels contain no transaction IDs, asset IDs,
contract commitments, wallet identifiers or raw error text. Compare per-guardian
phase latency and active work with existing session progress and host CPU,
memory, disk and thermal measurements when calibrating the Pi.

## Local preflight diagnostics

`fedimint_simplicity_client::preflight::analyze(&transaction, federation_id,
&snapshots)` checks an exact candidate using a map of module IDs to
`PruningSnapshot`s. It never queries guardians, opens a wallet, reserves notes,
constructs signatures, prunes the candidate, or submits anything. Reuse context
already held by the application; the existing `pruning_snapshot` helper can
fetch context separately, disclosing the requested outpoints to guardians.
Keep collection times and provenance alongside the supplied observations.

The report separates passed, failed, and not-checked conditions. It includes
aggregate static milliweight and redemption bytes across typed Simplicity
instances, exact Simplicity input/output fees, per-input outer signatures and
program execution/pruning, and pure asset conservation/authority checks.
Funding/change and other modules' fees are outside this report; use the normal
quote API for those. An unsigned draft can still undergo local program checks,
but its missing outer authorization is reported as not checked.

Consumed records and clocks are caller-supplied, not an atomic ledger snapshot.
Default snapshots do not establish fresh clocks. Namespace-use markers and
asset-registry membership are not checked. A passing report never guarantees
inclusion: a concurrent spend or a clock transition can invalidate the exact
same candidate. Unknown active versions stop local execution. Decode every
known Simplicity instance with its module decoder; opaque foreign bytes cannot
be inspected as Simplicity.

The native example accepts a bounded JSON request on stdin:

```sh
cargo run --locked -p fedimint-simplicity-client --example diagnostics -- preflight < request.json
```

Request fields are `federation_id`, `transaction_hex` (consensus encoding), and
`modules`, a JSON object mapping **every** Simplicity module ID to either `null`
(context unavailable) or an object with `consensus_version`, `session_index`,
`block_count`, and `contracts`. Contracts are a list of `[OutPoint,
StoredContract]` pairs using their existing Serde representations. Unknown
foreign modules retain their bytes. Requests are capped at 1 MiB.

Treat this input as spending material: pipe it locally or protect any temporary
file. The CLI prints only the report; it does not print signatures, witnesses,
contract identifiers or recovery annotations. Parse errors omit input details.
Exit zero means no checked condition failed, **not** that all checks were possible
or that the transaction will be accepted. No networking is initialized for this
command. Do not send the request to guardians or a remote diagnostic service.

## One-shot operator status

The `status::query` SDK helper accepts an existing `DynGlobalApi`, module ID and
positive request timeout. It queries existing supported/active-version and
block-count module endpoints, plus the existing core `status` endpoint. It opens
no wallet, touches no database, submits no votes or transactions, and requires
no wallet/admin credentials (a federation's API access secret can still apply).

```sh
# The invite is read from stdin; no wallet directory or mnemonic is needed.
cargo run --locked -p fedimint-simplicity-client --example diagnostics -- status --module 4 < invite.txt
# Machine-readable report, including each guardian's existing core status:
cargo run --locked -p fedimint-simplicity-client --example diagnostics -- status --module 4 --json < invite.txt
```

Replace `4` with the configured Simplicity instance ID. Configuration download
and each individual query have a bounded timeout (default 10 seconds,
`--timeout-seconds` accepts 1–300). The report issues four endpoint requests per
guardian, at most four guardians concurrently, once each without retries.
Configuration bootstrap uses the existing invite downloader with its own retries
inside the same deadline. Bootstrap requires a quorum to download configuration,
so the invite-only CLI cannot produce a partial report when fewer than a quorum
are reachable. Applications with an already initialized API can call
`status::query` directly without that bootstrap requirement. The invite and raw
transport errors are not printed.

Each field independently reports a value, timeout, or unavailable response.
Unavailable includes an unsupported endpoint or malformed response; do not infer
that the entire guardian is offline. Unknown future version numbers remain
printable. A quorum-observed active version requires the normal Fedimint threshold
of identical replies from distinct configured peers. Exit zero means this
agreement was observed, not that every guardian is healthy or upgrade-ready.

Collection start/end times delimit separate observations, not an atomic snapshot.
Core status describes the responding guardian's view of peer connectivity,
contributions and attention flags. Reachability from the operator's machine is a
different observation. Equal session counts do not prove full synchronization;
the module block count is not an individual Bitcoin backend tip. Differing active
versions during activation/catch-up are not automatically a consensus failure.
The endpoints do not expose pending upgrade votes or the local readiness cache.

Use the existing guardian Prometheus endpoint and the validation metric guidance
above for ongoing monitoring. This command adds no daemon, monitoring endpoint,
watch mode, inferred health score, or new consensus behavior.

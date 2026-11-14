# Simplicity operator runbook

This runbook is for people running guardians or native clients with the
experimental Simplicity module on Fedimint v0.13.0. The module is unaudited and
opt-in. Use a new federation on a Bitcoin test network and test funds: the
execution-version-1 candidate has not been released for real-money use, and
there is no deployed state to migrate.

- The [module README](../fedimint-simplicity-common/README.md) describes the
  protocol, API, fees and limits; its
  [execution baseline](../fedimint-simplicity-common/README.md#execution-baseline)
  defines what every guardian must run.
- The [beta checklist](../../docs/simplicity/release/beta-checklist.md) tracks
  qualification gates. The [evidence index](../../docs/simplicity/release/evidence-index.md)
  preserves earlier rehearsals at their exact revisions; none qualifies the
  current candidate.

The default wallet registers only the single-key owner template and no
application intent handlers. Market, exchange and top-up implementations are
separate reference consumers that register their own templates and handlers and
bundle historical definitions in their wallet binaries. Keep the exact
application revision with deployment records; recovery must not require fetching
source or an external metadata backup.

## Build and identify the artifact

Use one reviewed, clean Git commit on every guardian. Preserve its commit ID,
`Cargo.lock` and `flake.lock` with the release record. A compatible artifact is
identified by source revision and hashes, not by the pre-release version label,
which earlier incompatible prototypes reused. The normal daemon package does not
enable Simplicity; build the explicit artifact:

```sh
nix build .#fedimintd-simplicity
./result/bin/fedimintd --version
./result/bin/fedimintd version-hash
```

This is a Nix package, not a portable executable; deploy its closure with normal
Nix tooling or build the same pinned source on the destination. The equivalent
Cargo build is:

```sh
nix develop -c cargo build --locked --release -p fedimintd --features experimental-simplicity
```

For Raspberry Pi OS on a Pi 5, check `getconf PAGESIZE` before building; the
historical qualification machine used 16 KiB pages. The Linux ARM64 recipe below
sets jemalloc's logarithmic page size to `16` (64 KiB), which supports that page
size; it does **not** mean 16 KiB. Build in an ARM64 Linux environment with Rust
1.93.0, Clang/libclang, CMake, pkg-config, protoc and SQLite development
libraries. The [historical packaged rehearsal](../../docs/simplicity/release/evidence-index.md#beta-and-release-history)
built in a Debian 12 ARM64 container and ran natively on Raspberry Pi OS; that
was neither a Linux Nix-package test nor qualification of this candidate.

```sh
CARGO_BUILD_JOBS=1 CARGO_PROFILE_RELEASE_LTO=false CARGO_PROFILE_RELEASE_DEBUG=0 \
JEMALLOC_SYS_WITH_LG_PAGE=16 CC=clang CXX=clang++ \
RUSTFLAGS='--cfg tokio_unstable' \
cargo build --locked --release -p fedimintd -p fedimint-cli \
    -p fedimint-simplicity-client --features fedimintd/experimental-simplicity \
    --bins --example wallet
```

The recipe disables cross-crate LTO and debug information to reduce build
memory. Record these settings with the artifact and qualify it on the
destination; the Nix package uses its normal profile. Avoid `target-cpu=native`
when the build host differs from the destination. When building from an archive,
`FEDIMINT_BUILD_FORCE_GIT_HASH` must identify the verified source, not an
unverified label. Copy the daemon, CLI and wallet example into a new deployment
directory, check hashes before and after transfer, inspect dynamic dependencies
with `ldd`, and run `--help` and the daemon's `version-hash` on the destination
before creating the federation. These Cargo executables depend on their target
system libraries. The SimplicityHL compiler is a pinned Git dependency, so the
client example is built from source, not installed from crates.io.

Before distributing a candidate, run the
[release qualification checks](../fedimint-simplicity-common/README.md#release-qualification)
and keep their logs tied to the exact revision and platform. Native architecture
comparison and sanitizers are separate candidate-specific workflow gates. The
guardian network tests simulate Bitcoin; a real Bitcoin RPC deployment exercise
is a separate release check.

## Configure the guardians

Follow the normal [federation setup procedure](../../docs/deploying.md) with four
guardians for the beta, each with its own persistent data directory and the same
Bitcoin network. Set `FM_BITCOIN_NETWORK` explicitly (for example `signet`); the
daemon defaults to `regtest`. Use corresponding, trusted Bitcoin RPC backends and
the ordinary credential settings described by `fedimintd --help` and
[SECURITY.md](../../SECURITY.md#guardian-bitcoin-backends).

Keep the admin UI on its trusted interface with authentication configured, and
expose only the intended API and P2P endpoints; the module adds no submission or
recovery listener. In the lead guardian's setup form, explicitly select
`simplicity` alongside the funding modules. The client walkthrough requires a
bitcoin-denominated `mintv2`; keep the normal wallet and Lightning modules used to
fund the federation. Check that every guardian's binary offers Simplicity and
that the agreed module list includes it before completing DKG. Module instance
IDs come from the federation configuration.

Keep the existing Bitcoin backend, consensus, API and disk monitoring, and record
the deployed binary, configuration and database checkpoint together. **Never
prune session history this module needs.** Deleting spent outputs is safe only
because the original encrypted descriptors and sender receipts remain in that
history. Asset origins and namespace-use records are also permanent.

## Run a client

[examples/wallet.rs](examples/wallet.rs) uses the real native client, RocksDB,
normal invite and config acquisition, Mint v2 and the persistent Simplicity API.
It supports join, recovery, status and history, receiving ecash, locking ecash in
an owner contract and releasing it back to ecash. It is not a trading
application. Build it from the same source:

```sh
cargo build --locked -p fedimint-simplicity-client --example wallet
```

Use a fresh test mnemonic. The example reads it from stdin on every invocation
using Fedimint's standard BIP-39 root-secret derivation; it writes no seed file
and does not accept the mnemonic as an argument. This Bash helper reads it without
echo or shell history and passes it through a pipe. Keep shell tracing disabled:

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

Obtain Mint v2 ecash from a funded test wallet in the same federation (for
example with `fedimint-cli module mintv2 send`) and import it as the second stdin
line, so bearer ecash also stays out of command arguments:

```bash
read -r -s -p 'Mint v2 ecash: ' simplicity_ecash
printf '\n'
printf '%s\n%s\n' "$simplicity_mnemonic" "$simplicity_ecash" |
    "$simplicity_example" --data-dir "$simplicity_wallet_dir" receive
unset simplicity_ecash
simplicity_wallet lock 100000
simplicity_wallet status
```

`lock 100000` locks 100 sats (the amount is in msat) and needs additional ecash
for fees. It prints the operation ID and contract outpoint before waiting for
confirmation. Release the contract with its transaction ID and output index:

```bash
simplicity_wallet release TRANSACTION_ID 0
simplicity_wallet status
```

Replacement Mint v2 notes are processed by the ordinary client state machines,
and reopening the same database resumes them. If a command is interrupted, run
`simplicity_wallet wait OPERATION_ID` or inspect status after reopening. **Do not
repeat an operation because a response was lost.** Inspect an operation without
waiting for history synchronization:

```bash
simplicity_wallet operation OPERATION_ID
```

- `submitted`: the local submission is pending.
- `accepted_syncing_history`: acceptance is known; confirmed history is still
  synchronizing.
- `complete`: Simplicity history is synchronized, though another module's change
  processing may still be pending.
- `rejected`: does not by itself authorize releasing funding.
- `unknown_local_operation`: also normal for original operation IDs after
  mnemonic recovery; inspect confirmed history instead.

A pending transaction keeps its funding; cancellation does not prove rejection.

## Recover a client and verify

Stop the original client. Use the same mnemonic, wallet software and federation
invite with a fresh database directory:

```bash
simplicity_wallet_dir="$PWD/simplicity-wallet-recovered"
simplicity_wallet recover "$simplicity_invite"
simplicity_wallet status
unset simplicity_mnemonic
```

The example passes `None` for the backup snapshot, waits for module recovery and
reopens the client. It shows the core recovery progress counters, but progress
alone cannot report failure or prove completion, so it also waits on the core's
recovery outcome API and propagates failures. Compare holdings and confirmed
transaction IDs with the original view, including transactions whose contracts
are all spent. For a spendability check, keep a funded owner contract and release
it from the recovered wallet. The only inputs are the wallet software, mnemonic
and original federation: no backup file or deprecated backup service.

The example prints public amounts, outpoints and history summaries, not decrypted
descriptors or receipt data. **Protect the local database**: it holds decrypted
wallet material and is excluded from database dumps. Recovery does not recreate
abandoned intents, original operation IDs, local labels or watch-only
subscriptions, and low-level program imports have no recovery guarantee. For
application wallets, compare owned contracts and recoverable interactions, not
the whole local watch cache: public predecessors observed before the wallet
participated need not be reconstructed, but confirmed interactions and fully
spent owned contracts must be.

If recovery is interrupted, run `simplicity_wallet status` with the same recovery
directory and mnemonic: it opens the existing database, waits for recovery and
reopens the modules. `recover` initializes a fresh database; do not repeat it
against an initialized directory.

## Upgrades and activation

### Current candidate: fresh deployment

Create a fresh federation with matching guardian and client revisions. Qualify
restart, checkpoint restoration, quorum catch-up, mnemonic-only recovery and
spending contracts created before the restart. Keep this candidate's
configuration, history, checkpoints, wallet descriptors and binaries as the first
deployment baseline for future upgrade tests. There is no import of prototype
wallets and no cross-core upgrade from v0.12.2.

Earlier prototypes, including those also labeled configuration `0.1`, use a
different consensus-item format: do not open their databases with these binaries.
Fresh guardian module databases use schema version `0` with no prototype
migrations; recreate disposable pre-release databases. Earlier transitions are
[historical records](../../docs/simplicity/release/evidence-index.md#beta-and-release-history),
not procedures. After the first deployment, compatible releases must keep
historical template definitions and recovery support; predeployment resets do not
authorize discarding them.

### Module upgrade votes

For a future compatible release, install reviewed binaries on every guardian.
They keep enforcing the active rules until every peer advertises support and
ordered votes reach the threshold (the
[protocol](../fedimint-simplicity-common/README.md#module-upgrades) has the
details). Compare each guardian's `supported_consensus_version` with the
quorum-authenticated `active_consensus_version`, for example with the
[status helper](#operator-status). A missing or outdated peer delays automatic
voting, and readiness can go stale if a guardian goes offline after answering, so
keep normal quorum availability during the rollout.

After activation, verify convergence, historical contract spends and recovery.
**Do not reinstall an older binary as a rollback**: it must refuse the activated
state. Restore with a binary that supports both the checkpoint and the later
history. Never edit votes or the configuration version to bypass this. A wallet
that meets unsupported active rules needs a software update; restoring the
mnemonic does not add protocol support.

This release introduces the mechanism, not a successor. Tests emulate a successor
that keeps existing execution environments; the first release adding jets or
other rules needs its own mixed-binary activation rehearsal and fixtures.

## Monitoring

### Validation metrics

The module uses the existing guardian Prometheus endpoint. Scrape each guardian
process separately, including two guardians sharing a Pi, and keep the endpoint's
access controls. The module adds five metric families:

- `fm_simplicity_validation_seconds`: histogram of validation wall time by
  `phase`.
- `fm_simplicity_validation_calls_total`: finished or dropped calls by `phase`
  and `outcome` (`ok`, `interrupted`, or a rejection category).
- `fm_simplicity_validation_active`: calls currently in each phase, including
  those awaiting database access, admission or a worker thread. It is not a queue
  length or CPU gauge.
- `fm_simplicity_admission_waiting`: submissions waiting for admission before
  decoding. A sustained non-zero value means submissions arrive faster than this
  guardian can check them.
- `fm_simplicity_program_cache_total`: decoded-program cache lookups by `outcome`
  (`hit` or `miss`); a miss decodes the program.

Each Simplicity instance's transaction validation runs four phases, once per
attempt: `structure` (cheap transaction checks), `resolve` (active rules and
stored contract reads), `prepare` (admission, decoding, commitments and the cost
budget) and `validate` (asset accounting, context construction and program
execution). Metrics aggregate all instances.

They count work attempts in both admission and consensus, including retries, not
unique transactions. An `ok` call can be followed by a later rejection or
rollback; `interrupted` means the call was dropped, for example by task
cancellation. Timings include waiting. Counters reset on restart. No metric
affects fees, validity or admission. Rejection categories include
`resource_limit`, `program`, `commitment`, `program_rejected`,
`unknown_contract`, `assets`, and signature and context categories;
`unknown_contract` also covers ordinary shared-contract races, so rejection rate
alone is not evidence of an attack. Labels never contain transaction, asset,
contract or wallet identifiers or raw error text. Compare per-guardian phase
latency and active work with session progress and host CPU, memory, disk and
thermal measurements.

### Load

Monitor disk growth and consensus progress under load. Resource limits apply per
transaction and do not limit concurrent submissions. Each Simplicity module
instance owns its own worker threads, admission limit and decoded-program cache
(one set per guardian process, since Fedimint creates one instance per module
kind). Decoding and execution run on dedicated threads: `simplicity-consensus-0`
for agreed transactions and a `simplicity-submission-N` pool of half the CPU cores
(one to eight threads) for submissions. At most twice the pool size of
submissions hold decoded programs at once; others wait for admission rather than
being refused, so heavy submission load shows as slower submission responses and
a rising `fm_simplicity_admission_waiting`. Agreed transactions never wait for
admission or queue behind submissions, but all threads share the CPU, so heavy
submission load can still slow consensus, especially with two guardians on one
board. API requests keep running after their client disconnects, so connection
limits do not cap this load.

## Failure handling

### Backup, restoration and coordinated halt

Rehearse these steps on the exact candidate before broader beta. Record the
responsible operator, guardian identities, host failure domains, source revision,
artifact checksums, checkpoint and session information, results and private
evidence locations. This procedure does not qualify a prototype migration or a
rolling mixed-version upgrade.

1. **Prepare recoverable backups.** Preserve each guardian's configuration,
   encrypted secrets and their decryption credentials, exact binary identity, and
   a supported database checkpoint or consistent stopped data-directory copy. A
   configuration backup alone does not keep the database or the session history
   client recovery needs. Do not copy an actively written RocksDB directory: stop
   that guardian through its service manager and wait for process exit, keeping a
   quorum running for routine maintenance. In a four-guardian federation,
   stopping a host with two guardians loses quorum. Preserve client mnemonics and
   baseline fixtures separately.
2. **Keep and verify off-host copies.** Encrypt sensitive backups, restrict
   access and hold decryption credentials separately. Verify checksums after
   copying and rehearse restoring the copy rather than trusting file presence.
   Archive required history and selected checkpoints outside automatic retention,
   build caches and CI artifact expiry. Document backup frequency, retention, the
   expected recovery point and who holds credentials. Never publish databases,
   mnemonics or secrets as release evidence, and never prune history required by
   supported contracts, receipts or mnemonic recovery to meet a storage target.
3. **Restore the same guardian safely.** Keep the original guardian stopped and
   prevent its automatic restart before starting a restored copy. **Never run two
   instances with the same guardian secrets**, and do not let a stale restored
   guardian act as an independent federation. Preserve the failed database for
   diagnosis, restore a supported checkpoint with its matching configuration and
   secrets, and use the qualified binary. Coordinate reconnection with the other
   operators and verify catch-up against their authenticated history. A
   completed-session counter does not prove the open session has replayed: wait
   for the expected signed transaction outcomes, inspect the relevant contract
   records, and spend an unspent contract created before the checkpoint. Rehearse
   mnemonic recovery and spending with the matching client.
4. **Coordinate an emergency halt.** Agree in advance who can call a halt and who
   may authorize reopening. Pause pilot applications and ask participants not to
   submit or retry; keep pending operation records rather than assuming
   rejection. Stop the affected guardians through the normal shutdown procedure,
   disable automatic restart and verify process exit. A federation-wide halt
   intentionally stops consensus. Secure stopped database copies, logs, metrics
   and artifact and configuration identities before changing anything, and
   escalate unexplained validation or accounting failures privately.
5. **Verify before reopening.** Resume only the agreed candidate and compatible
   state under operator coordination. Check quorum progress, signed outcomes,
   contract and accounting state, backend health and a bounded test payment
   before reopening applications. An older database or binary is not a rollback
   after newer state has been accepted; do not delete consensus items or edit
   reservation records to make the federation look healthy. If restart repeats the
   failure, follow [validation takes unexpectedly long](#validation-takes-unexpectedly-long).

### Private signet pilot

Before starting, record the observation window and monitoring limits: consensus
progress, API and validation latency, admission backlog, memory, disk capacity and
write growth, and Bitcoin backend health. Assign operators to review timestamped
samples and alerts. Unexpected accounting or recovery results, sustained lack of
progress or breached resource limits require pausing traffic and operator review;
the deployment plan states which require a full halt. Record deposits,
withdrawals, restart and restoration, and mnemonic-recovery results. Only an
observed, reviewed pilot completes its checklist gate.

### Client recovery and pending operations

If recovery stalls, check guardian reachability, available authenticated history,
supported descriptors and local disk space, and keep the same database so the scan
resumes. Missing or unauthenticated history is never skipped to report completion.
A stale pagination cursor means restarting that local listing, not recovery.

For pending funds, inspect the recorded operation or intent and resume the same
client. An unproven rejection can require attention while notes stay reserved;
only a definitive rejection plus an authenticated permanent conflict permits local
funding release. **Never edit reservation records to clear a balance.**

### Validation takes unexpectedly long

If the consensus session stops advancing, or validation or admission gauges stay
high, collect evidence before restarting:

1. Compare each guardian's session progress with timestamped samples of
   `fm_simplicity_validation_active` by `phase`,
   `fm_simplicity_admission_waiting`, `fm_simplicity_validation_seconds` and
   `fm_simplicity_validation_calls_total`. Record host CPU, memory, disk and
   thermal state. Active calls include waiting, so these gauges alone cannot
   identify a slow transaction.
2. Preserve logs around the last advancing session. In retained `fm::consensus`
   trace logs, inspect `Processing consensus item` and the session and item
   indices, and correlate any transaction hash with client submission records.
   Metrics contain no transaction identifiers. Do not resubmit the transaction to
   diagnose it.
3. Capture per-thread CPU observations and, with suitable local tooling, thread
   stacks of `simplicity-consensus-0` and the `simplicity-submission-N` pool.
   Preserve timestamps, binary revision and hashes, configuration, logs, metric
   samples and a stopped database copy securely. Record it if the transaction
   cannot be identified.
4. Report privately to the maintainers with the evidence. Do not publish the
   transaction or sensitive database material.

A process restart clears in-memory submission work, admission permits and worker
pools, but clients can resubmit; disconnecting a client does not cancel its API
request, and dropping a waiting caller does not interrupt a running worker job.
Consensus recovers its persisted session and replays agreed items: committed items
are skipped, but a transaction in an agreed, uncommitted item is validated again,
so a restart may not clear the condition. Preserve the database and coordinate
with maintainers rather than deleting history or editing consensus items; use the
backup procedure above only as a coordinated restoration.

## Diagnostics

### Local preflight

`fedimint_simplicity_client::preflight::analyze(&transaction, federation_id,
&snapshots)` checks an exact candidate against a map of module IDs to
`PruningSnapshot`s. It never queries guardians, opens a wallet, reserves notes,
signs, prunes or submits. Reuse context the application already holds; the
`pruning_snapshot` helper can fetch it separately, disclosing the requested
outpoints to guardians. Keep collection times and provenance with the supplied
observations.

The report separates passed, failed and not-checked conditions. It includes static
milliweight and redemption bytes of the most loaded Simplicity instance (limits
apply per instance), exact Simplicity input and output fees, per-input outer
signatures, program execution and pruning, and pure asset conservation and
authority checks. Funding, change and other modules' fees are outside it; use the
quote API. An unsigned draft can still run program checks, with its missing outer
authorization reported as not checked.

Consumed records and clocks are caller-supplied, not an atomic ledger snapshot,
and default snapshots establish no fresh clocks. Namespace-use markers and asset
registry membership are not checked. A passing report never guarantees inclusion:
a concurrent spend or clock transition can invalidate the same candidate. Unknown
active versions stop local execution. Decode every known Simplicity instance with
its module decoder; opaque foreign bytes cannot be inspected.

The native example accepts a bounded JSON request on stdin:

```sh
cargo run --locked -p fedimint-simplicity-client --example diagnostics -- preflight < request.json
```

Request fields are `federation_id`, `transaction_hex` (consensus encoding) and
`modules`, an object mapping **every** Simplicity module ID to `null` (context
unavailable) or an object with `consensus_version`, `session_index`,
`block_count` and `contracts`, a list of `[OutPoint, StoredContract]` pairs in
their Serde representations. Unknown foreign modules keep their bytes. Requests
are capped at 1 MiB.

**Treat the request as spending material**: pipe it locally or protect any
temporary file, and never send it to guardians or a remote service. The command
initializes no networking and prints only the report, without signatures,
witnesses, contract identifiers or recovery annotations; parse errors omit input
details. Exit zero means no checked condition failed, **not** that every check was
possible or that the transaction will be accepted.

### Operator status

The `status::query` SDK helper takes an existing `DynGlobalApi`, module ID and
positive request timeout. It queries the supported and active version and
block-count module endpoints plus the core `status` endpoint. It opens no wallet,
touches no database, submits nothing and needs no wallet or admin credentials
(a federation's API access secret can still apply).

```sh
# The invite is read from stdin; no wallet directory or mnemonic is needed.
cargo run --locked -p fedimint-simplicity-client --example diagnostics -- status --module 4 < invite.txt
# Machine-readable report, including each guardian's core status:
cargo run --locked -p fedimint-simplicity-client --example diagnostics -- status --module 4 --json < invite.txt
```

Replace `4` with the configured Simplicity instance ID. Configuration download and
each query have a bounded timeout (default 10 seconds; `--timeout-seconds` accepts
1–300). The report issues four requests per guardian, at most four guardians
concurrently, once each without retries. Bootstrap uses the invite downloader with
its own retries inside the same deadline and needs a quorum, so the invite-only
CLI cannot report when fewer than a quorum are reachable; applications with an
initialized API can call `status::query` directly. The invite and raw transport
errors are not printed.

Each field reports a value, timeout or unavailable response; unavailable includes
an unsupported endpoint or malformed response and does not mean the guardian is
offline. Unknown future versions remain printable. A quorum-observed active
version requires the normal threshold of identical replies from distinct peers;
exit zero means that agreement was observed, not that every guardian is healthy or
upgrade-ready. Collection times delimit separate observations, not an atomic
snapshot. Core status is the responding guardian's view of peers, which differs
from reachability from the operator's machine. Equal session counts do not prove
synchronization, the module block count is not any single backend's tip, and
differing active versions during activation or catch-up are not automatically a
failure. Pending upgrade votes and the readiness cache are not exposed. The
command adds no daemon, monitoring endpoint, watch mode or health score.

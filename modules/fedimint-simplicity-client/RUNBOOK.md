# Simplicity testnet beta: guardian and native SDK walkthrough

This is an unaudited, opt-in module. Use a new federation on a Bitcoin test
network. These instructions prepare a native SDK deployment; they do not claim
that Pi 5 calibration, cross-architecture execution, or a sustained pilot has
been completed. The [execution baseline](../fedimint-simplicity-common/README.md#beta-execution-baseline)
defines the versions and rules all guardians must preserve.

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

Before distributing a candidate, run the repository's normal checks and the
module tests; keep logs tied to the exact revision and platform:

```sh
nix build -L .#ci.workspaceBuild .#ci.workspaceTest
nix develop -c cargo test --locked -p fedimint-simplicity-common -p fedimint-simplicity-client -p fedimint-simplicity-server --lib
nix develop -c cargo test --locked -p fedimint-client -p fedimint-client-module -p fedimint-mintv2-client -p fedimint-server -p fedimint-server-core --lib
```

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
funding, and release back to ecash. Application-specific market policies remain
in the SDK; this example is not a trading application.

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
status after reopening. Do not repeat a purchase merely because a response was
lost. The SDK's `await_operation` and `intent`/`await_intent` methods
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
then reopens the client. Compare holdings and confirmed transaction IDs with
the original view, including transactions whose contracts have all been spent.
For a spendability check, first retain a funded owner contract and release it
from the recovered wallet. Required inputs are wallet software, mnemonic and
the original federation; no external backup file or deprecated backup service
is used. Retain historical template support in the wallet software.

The example prints public amounts/outpoints and history summaries, not decrypted
descriptors or receipt application data. Protect the local database: it contains
decrypted wallet material. Recovery does not recreate abandoned intents,
original local operation IDs, local-only labels or watch-only subscriptions.
Low-level program imports have no implicit recovery guarantee.

## Operational failures and restoration

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
be rehearsed before opening the beta broadly.

Monitor disk growth and consensus progress during load. Per-transaction caps do
not limit the number of concurrent submissions. There is no module-owned global
admission queue. Keep a coordinated rollback/upgrade plan: restoring an old
binary or old database is not automatically safe after newer state is accepted.

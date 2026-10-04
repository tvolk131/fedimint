# Simplicity contract prototype

This experimental module locks bitcoin and explicit asset balances to real Simplicity programs. The
client compiles SimplicityHL with Fedimint context jets; guardians execute the
resulting bytecode with `rust-simplicity`. It is opt-in and disabled by default.
The [architecture record](../../specs/ARCH-simplicity.md) explains its boundary
with Fedimint consensus and other modules.
The agreed wallet recovery contract is recorded in
[REQ-simplicity-recovery](../../specs/REQ-simplicity-recovery.md). The persistent
Rust client implements it for versioned wallet templates.

## Run the prototype

From the repository root, inside `nix develop`:

```sh
cargo test -p fedimint-simplicity-common -p fedimint-simplicity-client -p fedimint-simplicity-server --lib
```

The transaction integration tests use Fedimint's actual transaction processor and Mint v2
blind signatures with an in-memory database. It issues real test notes, deposits
one into a contract, adds a second note to increase the contract's balance,
spends the contract back into notes for the entire balance minus the execution
fee, and spends those notes to verify their signatures. A dummy module provides
only the initial test funding and final accounting sink. A separate market test starts four guardians with TLS P2P, WebSocket APIs,
Aleph consensus, and RocksDB; it needs permission to bind local ports. Bitcoin
RPC and funding are simulated. It takes one guardian offline during
settlement, reopens its database, and checks catch-up before redemption.

The tests also exercise consensus timelocks, authorization of foreign blinded
outputs, covenant state preservation, funding failures, invalid outer signatures,
duplicate spends, malformed bytecode/witnesses, output limits, and rollback.

To include the guardian module in a daemon build:

```sh
cargo build -p fedimintd --features experimental-simplicity
```

The module still has to be selected explicitly during federation setup. Existing
federations and default builds do not enable it. Wallet applications register
`SimplicityClientInit::default()` in their client module registry. There is no
CLI wallet integration yet.

Guardian initialization, configuration validation, and client-config export reject
module consensus versions other than `0.1` before decoding the configuration.
This prototype does not silently activate new rules from an older configuration
or provide a migration/rolling-upgrade path for earlier experimental deployments.

## Guardian and client API

`fedimint-simplicity-common` owns consensus types, the jet encoding, execution
limits, and the authorization digest. Its optional `compiler` feature adds the
pinned SimplicityHL adapter. `fedimint-simplicity-server` owns the contract UTXO
ledger, consensus block-count votes, validation, and the bitcoin liability audit.
`fedimint-simplicity-client` provides low-level Rust builders and the persistent
`SimplicityClientModule`.

A `ContractOutput` contains the execution version, bitcoin amount in msats,
program commitment (CMR), 32-byte application state, and bounded recovery bytes.
A `ContractInput` references its outpoint and supplies the redemption program,
witness, and a claim key used by the outer Fedimint transaction signature.
An input consumes one UTXO; a contract output creates one. Version-one action
outputs describe asset operations and do not create spendable UTXOs. A transaction can include many
of both and combine them with other modules' ordinary inputs and outputs.

The low-level builder flow is:

1. `ContractProgram::compile(source, arguments(...))` compiles a policy. The
   [example](../fedimint-simplicity-client/contracts/top_up_or_release.simf)
   checks an owner signature and both clocks, then either preserves its CMR and
   state in a successor of at least the current value or releases the balance.
2. `program.output(amount, state, recovery)` creates a funded output request.
   A CMR alone is not a recoverable program. Use the persistent wallet below
   when mnemonic recovery is required.
3. For a spend, use `program.input(outpoint, claim_key, witnesses(...))` with
   `placeholder_signature()` to assemble a draft. Choose all contract inputs,
   all outputs, the transaction nonce, and required funding. Estimate spending
   fees with `runtime::input_fee` using the actual branch and witness shape;
   output fees come from `output_fee`.
4. Use `signature_value(federation_id, module_id, &transaction, owner_key)` to
   replace each placeholder. Other contracts may use different witnesses or
   authorization policies. Rebuild the input with those witnesses.
5. Apply the ordinary outer signatures after witnesses are final. The prototype
   `sign_transaction` helper supports exactly one signing key per outer input,
   in transaction order. Submit through the normal Fedimint transaction API.

The [integration tests](../fedimint-simplicity-server/src/tests.rs) are executable
examples of this sequence. Final outer signatures cover the actual transaction
including embedded witnesses. An owner key and claim key can differ: a contract
must authorize its chosen claim key through the inner digest if it delegates
outer signing.

Module API version 0.0 exposes `contract(OutPoint) -> Option<StoredContract>` and
`block_count(()) -> u64`. The first returns the current UTXO including its creation
clocks. Neither response by itself is a proof of federation consensus; clients
must use the normal federation query/transaction confirmation mechanisms.

`contract` and the v0.1 `asset` endpoint each perform one database point lookup.
`block_count` reads at most one vote per configured guardian and sorts that bounded
set. None compiles or executes a program, enumerates contracts, or scans history.
Regression tests exercise the real endpoint wrappers with maximum-shaped records:
compact JSON result budgets are 16 KiB for a contract, 1 KiB for an asset origin,
and 20 bytes for the block count, excluding the transport envelope. These are
regression budgets, not additional runtime response limits. Tests also cover
malformed parameters, missing/spent contracts, and retained asset origins.
Per-request work stays bounded by record/configuration limits; simultaneous calls,
transport parsing, and core history downloads are outside these module API bounds.

## Execution environment v0

| Jet | Result / indexing |
| --- | --- |
| `fm_sig_hash_all()` | Domain-separated authorization digest |
| `fm_session_index()` | Current zero-based Fedimint consensus session |
| `fm_block_count()` | Threshold-agreed Bitcoin block count (tip height + 1) |
| `fm_creation_session()`, `fm_creation_block_count()` | Stored creation clocks |
| `fm_current_amount()`, `fm_current_cmr()`, `fm_current_state()` | Consumed contract data |
| `fm_current_index()`, `fm_input_count()` | Index/count among this module instance's inputs |
| `fm_output_count()` | Count of all outer transaction outputs |
| `fm_output_amount(i)`, `fm_output_cmr(i)`, `fm_output_state(i)` | Contract fields at outer output index `i`; fail for foreign outputs |
| `fm_output_module(i)`, `fm_output_hash(i)` | Module instance and canonical encoded hash for any outer output |

The inner digest commits to the federation, module instance, execution version,
ordered contract outpoints and claim keys, transaction nonce, and **every outer
output**, including mint blinded nonces. It excludes witnesses, outer signatures,
and foreign funding inputs. This avoids signing a signature and permits a funding
sponsor to add inputs. Reordering/removing/changing this module's inputs or any
output requires fresh inner authorization. Changing witnesses requires fresh
outer signatures.

Programs receive rich typed successor data for their own module instance.
Foreign outputs have an authenticated module ID and opaque hash; they do not get
a mint-specific blinded-nonce parser. The current consumed UTXO is exposed, but
rich indexed access to *other consumed contracts* is not part of this first jet
set. There are no foreign-input inspection jets.

Output indices are outer transaction indices; input indices are module-local.
A program can inspect the same successor as another program. Applications that
need distinct successor allocation must enforce it in their policies; the module
does not infer exclusivity or prevent contract-author double-satisfaction bugs.

Bitcoin votes are monotonic and require the configured guardian threshold to
advance the clock. With insufficient votes, the exposed count is zero. Session
indices are supplied by the core during both live consensus and replay. Admission
checks use the current session; acceptance can still fail if state changes before
ordering. Clocks are not wall time, and different modules' block-count votes need
not be processed at the same point.

## Limits, fees, and retention

Both execution versions allow at most 32 contract inputs and 32 contract outputs for this
module instance, within at most 128 total outputs. Each program and witness is
limited to 8 KiB, each recovery annotation to 1 KiB. An allocation-free structural
scan checks declared node counts and constant payload lengths against the actual
program bytes before the pinned upstream decoder reserves memory. Upstream still
checks canonical encoding, sharing, and types; inferred type sizes are then
checked before decoding padded witnesses. Execution is capped by static cost,
cell, and frame bounds; the constants are in `runtime::decode_program`.

Across all Simplicity instances in one outer transaction, redemption programs and
witnesses may total at most **16 KiB**, and static program costs plus creation
authorization charges may total at most **2,000,000 milliweight**. Each asset
creation signature consumes 100,000 milliweight from that budget; one signature
can still authorize a batch of assets. These are consensus constants in
`resources`, not local timeouts. The existing 10,000,000 per-program ceiling is
retained as a decoder safeguard, but a spend must also fit the stricter aggregate
budget. Fees are unchanged; resource charges do not add a second fee.

See [validation ordering](../../specs/ARCH-simplicity.md#module-and-transaction-boundaries)
for the guardian phases and client finalization boundary. Multiply-invalid
transactions return the first error in that order; module preflight faults use
an input-error envelope. Creation destinations must be asset-bundle outputs in
their own instance, and several assets may share one destination.

Guardian preparations use an 8 MiB conservative logical retention budget across
all instances in one transaction, with re-decoding on cache misses. This is not
an RSS ceiling: decoder/accounting scratch, an uncached program, snapshot records
and the VM require additional memory. Outer transaction bytes, recovery data,
assets, types, cells and frames retain their separate limits. None of these
bounds aggregate guardian load from repeated requests.

Fixed [consensus vectors](tests/vectors/README.md) pin v0/v1 encodings and signing
hashes, asset IDs, all custom jet identities/types/costs, and selected execution
commitments/resource bounds. Direct jet tests cover the C-frame adapter boundary;
server tests also exercise two instances through core processing and rollback.

Spending costs 100 msat plus one msat per rounded static cost weight unit and
per encoded program/witness byte. Each output costs 100 msat plus one msat per
recovery byte; v1 also charges one msat per encoded extension byte and 100 msat
per newly registered asset ID. The asset charge applies once at genesis, not on
later issuance of the same asset. Rejected transactions pay no module fee.
These are the agreed prototype coefficients, pending production calibration.
The submitted redemption program's static bound determines the spend fee;
guardians do not time execution or charge script cost on creation.

The [resource benchmark harness](../fedimint-simplicity-server/benches/resources/README.md)
measures decoding, execution, context costs and guardian validation separately,
with representative, near-limit and rejected inputs. Its measurements inform
future calibration; they do not set or change the experimental coefficients.
Raspberry Pi 5 is the minimum guardian performance target. Production calibration
requires measurements on that hardware; faster-machine results alone are insufficient.

Spending removes the live UTXO and recovery annotation. Any state needed by a
successor must be carried forward. Fedimint's existing transaction/session history
may retain all original bytes indefinitely: removing the live record does **not**
erase historical ciphertext. Recovery bytes are opaque public data to this module;
the persistent wallet encrypts descriptors before use. There is no public wallet
identifier or new guardian scanning endpoint.

The [recovery design](../../specs/ARCH-simplicity.md#wallet-recovery-design) restores
holdings and confirmed interactions from federation history, including fully
spent contracts. [REQ-simplicity-recovery](../../specs/REQ-simplicity-recovery.md)
defines the mnemonic/software/federation requirement and exact history boundary.

## Persistent wallet API

Register `SimplicityClientInit::default()` and obtain `SimplicityClientModule` from
the normal Fedimint client. Native funding/change uses the client's primary
module. The API is currently Rust-only:

- `receive(amount, bundle)` makes a fresh owner policy with encrypted recovery
  metadata, ready to hand to a sender.
- `output(descriptor, amount, state, bundle)` does the same for a versioned
  application template. Built-ins cover owner outputs, top-up/release, and the
  binary-market vault. Applications can supply a `ContractTemplates` registry.
- `submit(spends, outputs, creation_keys)` reserves selected contracts and returns
  an operation ID and transaction ID after durable submission is recorded.
  `SpendIntent::owner(outpoint)` installs an owner signature automatically;
  custom intents supply other witnesses and an optional signature witness name.
  Asset change and authority successors remain explicit outputs.
- `await_operation(id)` waits for acceptance and history synchronization or
  rejection cleanup. The core executor resumes pending submissions on restart.
- `submit_with_receipt(..., context)` explicitly includes a sender receipt with
  optional versioned application data. Ordinary `submit` adds a minimal receipt
  automatically when no owned input or output identifies the operation.
- `sync()`, `contracts()`, and `history()` provide a refresh, all recognized
  contracts (including spent ones), and ordered confirmed transactions. Filter
  `spent_by == None` for current holdings. Shared market collateral is not an
  owner's native balance merely because the wallet watches its vault.

Descriptors carry template ID/version, parameters, random key salt, and optional
application data. Their authenticated encrypted envelope must fit the existing
1 KiB annotation limit. Keep old template definitions in wallet releases. Use
fresh receive requests: repeated ciphertext or policies can link transfers.
Spending and metadata keys are derived independently from the module root secret,
federation identity, and instance ID. No backup upload or external file is used.

Use the normal client `recover(..., None)` flow with the same root secret after
losing its database. Wait for recovery before transacting, then reopen the client.
Required history must remain available and owned descriptors supported; missing
or unsupported data cannot be silently skipped.

Sender receipts use the action output's existing 1 KiB annotation allowance and
per-byte fee. `history().sent` records sender activity without claiming recipient
ownership. [Receipt commitments and finalization](../../specs/ARCH-simplicity.md#wallet-recovery-design)
are part of the wallet architecture.
Low-level callers bypass these wallet guarantees. Arbitrary imported policies,
local labels, failed attempts, and original operation IDs are not implicitly
recoverable; confirmed transactions and encrypted application context are.

## Prototype boundary

Native bitcoin contracts, public asset issuance/transfers/destruction, and a
binary-market example are implemented, together with persistent submission,
input reservations, encrypted descriptors, and history-based recovery. Private
transfers, general market discovery/indexing, CLI support, and a production
trading UI remain later work. Rejected conflicting vault spends must be rebuilt
by the application against the accepted successor.

The runtime, compiler revision, core jet allowlist, custom jet identifiers and
CMRs, types, and costs are consensus-critical. Custom environment jets currently
use domain-separated prototype commitments; formal Simplicity specifications and
production cost calibration remain outstanding. Unsupported jets are rejected.
Liquid programs must be ported to this environment. Do not reinterpret existing
v0 outputs when adding versions: migration requires an authorized spend.

This is a development prototype, not an audited module for holding real funds.


## Explicit assets and execution version one

Module consensus version 0.1 adds execution version 1. Existing v0 outputs keep
exactly their previous binary encoding, digest, jet allowlist, and fee behavior;
v0 database records need no migration. New asset jets and `multiply_64` are
rejected when spending a v0 output. Moving bitcoin into v1 requires an authorized
transaction. All guardians must agree on the upgraded module consensus version;
this is not automatic activation in an existing federation.

`program.asset_output(bitcoin, state, recovery, AssetBundle { balances,
authorities })` creates a v1 UTXO. Balances have strictly sorted unique asset IDs
and positive u64 quantities; authorities are strictly sorted unique IDs. Bitcoin
remains a separate msat field. One output may bundle several assets under one
program/state, but spending any part consumes the whole output. Owners can split
or merge balances through ordinary successors. Authority-bearing contracts are
excluded from the SDK's `assets::select_assets` helper; applications spend those
explicitly. Selection handles asset change; native funding and fees are separate.

One `assets::action_output(AssetActions)` may accompany a transaction. It carries
creation batches, issuance quantities, and explicit burns. It has no value, CMR,
or state and creates no UTXO. It may carry bounded opaque recovery bytes, including
an encrypted sender receipt. The core's validation hook
resolves all consumed contracts before any inputs or outputs are processed. The
module checks each asset with u128 accumulation:

`consumed + authorized issuance = created + explicit burns`.

Unknown assets, duplicate inputs, duplicate authorities, implicit burning, and
unauthorized issuance are rejected. An authority can have at most one successor;
omitting it permanently destroys it. Issuance requires consuming that asset's
authority and satisfying its program. Bitcoin conservation remains core-owned,
and token quantities do not enter the bitcoin liability audit. Failed funding,
signatures, or module validation roll back the entire transaction.

`assets::creation(federation, module, fresh_key, authority_output_indices)` returns
an unsigned creation batch and precomputable IDs. Its namespace hashes a versioned
domain, federation, module instance, and fresh public key; asset IDs hash a separate
domain, namespace, and ordinal. One key can create many assets with any funding
input structure. Creation has zero supply and exactly one authority per asset,
placed in the designated outer output. The first issuance is a second transaction
spending that authority. No initial-issuance bypass exists.

After assembling outputs, call `assets::sign_creation` for every creation key.
V1 programs use `assets::signature_value` rather than the v0 helper. The v1 digest
covers all module spend references/claim keys, nonce, and outer outputs, including
asset operations, but substitutes zeroes for creation signatures in v1 action outputs across all
decoded Simplicity instances, preserving their module IDs. This avoids circular
commitments when several instances create assets together. Other foreign output
bytes remain opaque and unchanged. Sign creations before any v0 program signatures in
a mixed transaction, then apply outer signatures after all witnesses are final.
Foreign funding inputs remain excluded from inner signatures for sponsorship.

Namespace reuse is rejected forever, including after all authorities and tokens
are destroyed. Immutable `AssetRecord`s retain the original authority outpoint,
CMR, state, creation key, and ordinal. API version 0.1 adds
`asset(AssetId) -> Option<AssetRecord>`; use federation consensus query mechanisms
to authenticate its response. The creation key has no later issuance privilege.
Records are public; fresh keys avoid creating a stable wallet identifier.

V1 adds these jets (input indices remain module-local, output indices outer):

| Jet family | Arguments and result |
| --- | --- |
| `fm_input_amount/cmr/state/version(i)` | Resolved consumed contract fields |
| `fm_input_outpoint_hash(i)` | Hash of the canonical consumed outpoint |
| `fm_output_version(i)` | Successor execution version |
| `fm_input_asset_quantity((i, id))`, `fm_output_asset_quantity((i, id))` | u64 quantity, zero for an absent ID |
| `fm_input_authority((i, id))`, `fm_output_authority((i, id))` | Authority membership as bool |
| `fm_input_asset_count(i)`, `fm_output_asset_count(i)` | Number of balances |
| `fm_input_authority_count(i)`, `fm_output_authority_count(i)` | Number of authorities |
| `fm_input_asset_id((i, entry))`, `fm_output_asset_id((i, entry))` | Balance ID at sorted entry index |
| `fm_input_authority_id((i, entry))`, `fm_output_authority_id((i, entry))` | Authority ID at sorted entry index |
| `fm_issued_quantity(id)`, `fm_burned_quantity(id)` | Aggregate transaction quantity, zero if absent |

Invalid contract/entry indices and foreign output inspection fail; asset output
jets also reject action outputs. Foreign outputs remain opaque to programs.
There are at most 32 distinct asset IDs per transition, 32 entries of either kind
per bundle, and 32 created assets per transaction. V1 output fees add one msat per
encoded extension byte and 100 msat per newly registered asset to contribute toward permanent
records. These fees and context-jet costs still require production calibration.

## Binary prediction-market example

The client `market::BinaryMarket` compiles
[binary_market.simf](../fedimint-simplicity-client/contracts/binary_market.simf).
One vault owns both unique issuance authorities and the bitcoin collateral. It
must be module input 0 and recreate itself at outer output 0. `ACTION` witnesses:

| Action | Rule |
| --- | --- |
| 0: issue | Before the deadline, deposit q sats and issue q YES plus q NO |
| 1: recombine | While unresolved, burn q of each and release q sats |
| 2: resolve | During the resolution window, verify an oracle signature for YES=1, NO=2, or INVALID=3; at/after the deadline only INVALID timeout is allowed |
| 3: redeem | Burn winners for 1000 msat/unit, or either side for 500 msat/unit when INVALID |

State 0 means unresolved. Resolution permanently commits state 1, 2, or 3 in the
vault lineage. Authorities remain in the resolved vault but its program forbids
further issuance. Even an empty vault retains its recorded outcome. Concurrent
collateral operations contend for that output and must be rebuilt after a
conflict. Ordinary position transfers do not touch it.

Oracle messages commit the federation, module, both asset IDs, event identifier,
resolution-rules hash, oracle key, window, and outcome. Guardians never contact the
oracle. Clocks constrain transaction acceptance, not when the oracle published a
signature. If the oracle equivocates before resolution, the first accepted
resolution wins; the prototype assumes the configured oracle reports honestly.

Call `BinaryMarket::validate_genesis` with authenticated asset records before
accepting assets as positions. Checking only the current vault is insufficient:
an issuer could mint elsewhere and later move authority into the market program.
The helper verifies derived IDs, a shared original vault, the expected CMR, and
unresolved initial state. Transfer recipients must additionally check their actual
output quantities and ownership policy.

The vault enforces collateral reduction and matching burns. Position-owner
signatures authorize the payout destinations; an oracle signature authorizes only
resolution, never an unrestricted release. The examples use external fee
sponsorship. Owners can instead pay fees from an authorized redemption payout;
the vault must still preserve all collateral backing the remaining positions. The generic ledger grants no bitcoin entitlement merely
for burning a token. Multi-vault policies must prevent reusing the same burn to
satisfy multiple obligations; this example uses one unique authority-bearing vault.

[Asset integration tests](../fedimint-simplicity-server/src/tests/assets.rs) cover
creation, collateral funding from real Mint v2 notes, split holdings, independent
YES trading for ecash, recombination, all outcomes, timeout, redemption into ecash,
and spending the resulting note. Negative cases cover forgery, inflation,
namespace replay, authority copying/destruction, overflow, invalid signatures,
provenance, legacy compatibility, and transaction rollback.

[Market hardening tests](../fedimint-simplicity-server/src/tests/assets/market_hardening.rs)
exercise oracle domain binding, exact resolution/timeout boundaries, altered
successor policies, unequal pairs, forbidden state transitions, repeated issuance,
independent transfers of both sides, and partial redemptions until every outcome's
vault is empty. Distinct competing redemptions must rebuild against the accepted
successor. Transactions admitted before a deadline must fail if consensus
executes them after expiry. Most policy cases sponsor fees with the dummy module; a separate
exact-funding lifecycle uses real Mint v2 notes and authorized change, checks a
one-msat shortfall rolls back, and reconciles all Simplicity fees. That fixture
configures zero mint fees; it is not a production fee-calibration test.

The [network test](../fedimint-simplicity-server/src/tests/assets/network.rs)
submits market transactions through the federation API, verifies all guardians'
contract and origin records, and kills a guardian process while the remaining quorum settles the market.
Restarting it from the same RocksDB exercises recovery of committed state and
catch-up of missed consensus history. The separate
[wallet network test](../fedimint-simplicity-server/src/tests/assets/network/wallet.rs)
restarts a client with a persisted submission, exercises native top-up/release,
creates and transfers assets, discards entire client databases, recovers from
root secrets without backup snapshots, spends recovered contracts, and restores
history after all contracts are spent. Unit tests cover interrupted open-session
replay, changed/missing prefixes, unsupported owned descriptors, foreign/copied
annotations, and public-vault successors. These tests do not inject crashes at
every database-write boundary. No test
claims exhaustive bytecode fuzzing or production security assurance.

## Durable shared-contract intents

`SimplicityClientModule::submit_intent(intent, policy)` persists a versioned
semantic request and returns its local operation ID. `intent` reports the durable
record; `intents` lists local operations after restart, and `await_intent` returns
when an operation completes or needs user action.
`retry_intent` resumes a manual conflict, and `cancel_intent` stops future attempts.
Cancellation cannot retract a transaction already submitted: it still resolves
as accepted or rejected. Losing connectivity leaves that same attempt pending.

`IntentPolicy` defaults to manual retry, at most three attempts, and at most 100
sats of total transaction fees per attempt. Configure those limits for the app.
New intent attempts require funding-reservation support (currently Mint v2).
An optional session deadline prevents preparing new attempts; contract clocks
govern actual acceptance. Automatic retry is opt-in with bounded exponential
backoff and jitter. Both modes share the original limits and immutable parameters.
Unproven rejections pause with funds reserved; cancellation cannot release them.

[Conflict handling](../../specs/ARCH-simplicity.md#shared-contract-conflict-handling)
defines proof requirements, funded fee checks, durable submission, release and
retry ordering. The shared APIs are `TransactionBuilder::with_funding_reservations`
and `ClientContext::release_funding_after_conflict`. The originating wallet must
authenticate permanent invalidity before requesting local release of owned notes.
Release is durable and idempotent; a concurrent operation may select restored
notes before retry. Ordinary submissions and older pre-reservation attempts keep
their original funding behavior, including possible reclaim fees. Imported ecash
still requires reissuance; these APIs cannot restore arbitrary supplied notes.

The first built-in handler is `intent::MintPairs`, for buying a fixed quantity of
binary-market pairs with independent, fixed YES and NO recipient outputs:

```rust,ignore
let anchor = wallet.watch_market(&market).await?;
let intent = MintPairs {
    market,
    anchor,
    quantity,
    yes_destination, // zero native amount, exactly quantity YES, no authorities
    no_destination,  // zero native amount, exactly quantity NO, no authorities
}.into_intent();
let id = wallet.submit_intent(intent, IntentPolicy::default()).await?;
let record = wallet.await_intent(id).await?;
```

`watch_market` verifies asset origins and imports the vault's authenticated history
through the wallet's scanned prefix; ordinary sync then follows successors. The
handler refuses issuance after resolution. Recombination, redemption and resolution
retain low-level submission APIs; register additional semantic handlers through
`SimplicityClientInit`'s `IntentHandlers` implementation.

Database restarts resume pending intents. Mnemonic recovery restores confirmed
activity, not unfinished intentions or watch-only subscriptions without confirmed
participation; applications can re-add those subscriptions.

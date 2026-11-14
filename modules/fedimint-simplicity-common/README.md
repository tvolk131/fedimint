# Simplicity contract module

This experimental module locks bitcoin and explicit asset balances to real
Simplicity programs. The client compiles SimplicityHL with Fedimint context jets;
guardians execute the resulting bytecode with `rust-simplicity`. It is opt-in,
disabled by default, and an unaudited development prototype: do not use it to
hold real funds.

This document is for developers and integrators. Related documents:

- [ARCH-simplicity](../../specs/ARCH-simplicity.md): the invariants the module
  maintains and which component enforces each one.
- [REQ-simplicity-recovery](../../specs/REQ-simplicity-recovery.md): the agreed
  wallet recovery contract.
- [Operator runbook](../fedimint-simplicity-client/RUNBOOK.md): building,
  deploying, upgrading, monitoring, recovery, failure handling and diagnostics.
- [Release records](../../docs/simplicity/release/): the
  [beta checklist](../../docs/simplicity/release/beta-checklist.md) and the
  revision-bound [evidence index](../../docs/simplicity/release/evidence-index.md).
- [SECURITY.md](../../SECURITY.md#experimental-simplicity-contracts): trust
  boundaries and privacy properties.

## Crates and builds

- `fedimint-simplicity-common` owns consensus types and encodings, the jet
  encoding, [consensus limits and fee terms](src/limits.rs), stateless resource
  checks, the runtime and the authorization digest. Its optional `compiler`
  feature adds the SimplicityHL adapter. SimplicityHL is a Git dependency pinned
  to one commit pending an upstream fix; it is not a released crate.
- `fedimint-simplicity-server` owns the contract UTXO ledger, block-count and
  upgrade votes, transaction validation, the bitcoin liability audit and
  validation metrics.
- `fedimint-simplicity-client` provides low-level Rust builders, the persistent
  `SimplicityClientModule`, durable intents, local preflight and operator status
  helpers. Its optional `ptlc` feature adds the [PTLC example](#ptlc-settlement-example).

Build a daemon that includes the guardian module with
`cargo build -p fedimintd --features experimental-simplicity` (or
`nix build .#fedimintd-simplicity`). The module still has to be selected
explicitly during federation setup; existing federations and default builds do
not enable it. Wallet applications register `SimplicityClientInit::default()` in
their client module registry. There is no CLI wallet integration and the API is
Rust-only.

The module consensus configuration is empty: the guardian takes the peer count
and threshold from core. Configuration version `0.1` is the fixed deployment
baseline (see [module upgrades](#module-upgrades)).

## Data model

The module's output type is the extensible enum `SimplicityOutput`. Codecs are
derived; unknown variants decode as `Default { variant, bytes }` so history stays
decodable, and guardians reject them.

- `Contract(ContractOutput { version, amount, cmr, state, recovery, assets })`
  creates one spendable UTXO: the execution version, a bitcoin amount in msat,
  the program commitment (CMR), 32 bytes of application state, bounded opaque
  recovery bytes and an `AssetBundle` (empty for native-only contracts). Only
  execution version 1 is valid; other versions decode and are rejected by
  validation, not by the decoder. Genuine contracts may have zero bitcoin or
  state.
- `Actions(ActionOutput { actions, recovery })` declares asset creations,
  issuance and burns (`AssetActions`) for its instance. At most one is allowed
  per transaction per instance. It has no value, CMR or state and creates nothing
  spendable. Its recovery bytes can carry an encrypted
  [sender receipt](#sender-receipts). Programs see no contract view of it.

A `ContractInput { outpoint, claim_key, program, witness }` consumes one UTXO and
supplies the redemption program, its witness, and a claim key that signs the
outer Fedimint transaction. The owner key and claim key can differ: a contract
that delegates outer signing must authorize its chosen claim key through the
inner digest. A transaction can include many contract inputs and outputs and
combine them with other modules' ordinary inputs and outputs.

`StoredContract { output, creation_session, creation_block_count }` is the live
record a guardian keeps and returns from the `contract` endpoint.

Consensus items are `BlockCount` votes, `ModuleConsensusVersion` votes, and a
`Default` variant that future releases' items decode into.

### Explicit assets

Asset balances and issuance authorities live in a contract's `AssetBundle {
balances, authorities }`. Balances have strictly sorted unique asset IDs and
positive u64 quantities; authorities are strictly sorted unique IDs. Bitcoin
remains the separate msat field. One output can bundle several assets under one
program and state, but spending any part consumes the whole output; owners split
or merge balances through ordinary successors. Application-specific restrictions
belong to the application template registry, not to string checks in the generic
wallet.

Guardians check every asset with u128 accumulation:

`consumed + authorized issuance = created + explicit burns`

Unknown assets, duplicate inputs, duplicate authorities, implicit burning and
unauthorized issuance are rejected. An authority can have at most one successor;
omitting it permanently destroys it. Issuance requires consuming that asset's
authority and satisfying its program. Bitcoin conservation remains core-owned,
and token quantities do not enter the bitcoin liability audit. Failed funding,
signatures or module validation roll back the entire transaction.

`assets::creation(federation, module, fresh_key, authority_output_indices)`
returns an unsigned creation batch and precomputable IDs. Its namespace hashes a
versioned domain, the federation, the module instance and the fresh public key;
asset IDs hash a separate domain, the namespace and an ordinal, so they do not
depend on funding inputs. One key can create many assets. Creation starts at zero
supply with exactly one authority per asset, placed in the designated outer
output, which must be a contract output of the same instance; several assets may
share one destination. The first issuance is a second transaction spending that
authority; there is no initial-issuance bypass.

After assembling all outputs, call `assets::sign_creation` for every creation
key, then apply outer signatures last. Namespace reuse is rejected forever, even
after every authority and token is destroyed. Immutable `AssetRecord`s retain the
original authority outpoint, CMR, state, creation key and ordinal; the creation
key has no later issuance privilege. Records are public; fresh keys avoid a
stable wallet identifier.

`program.asset_output(bitcoin, state, recovery, bundle)` builds an asset-bearing
contract (`program.output` uses an empty bundle), and `assets::action_output`
builds the action output. `assets::select_assets` selects ordinary asset outputs
and computes asset change; it excludes authority-bearing contracts, which
applications spend explicitly, and leaves native funding and fees to the caller.

## Execution environment v1

### Jets

Input indices are module-local; output indices are outer transaction indices.

| Jet | Result |
| --- | --- |
| `fm_sig_hash_all()` | Domain-separated authorization digest |
| `fm_session_index()` | Current zero-based Fedimint consensus session |
| `fm_block_count()` | Threshold-agreed Bitcoin block count (tip height + 1) |
| `fm_creation_session()`, `fm_creation_block_count()` | Stored creation clocks |
| `fm_current_amount()`, `fm_current_cmr()`, `fm_current_state()` | Consumed contract data |
| `fm_current_index()`, `fm_input_count()` | Index/count among this instance's inputs |
| `fm_input_amount/cmr/state/version(i)` | Resolved consumed contract fields |
| `fm_input_outpoint_hash(i)` | Hash of the canonical consumed outpoint |
| `fm_output_count()` | Count of all outer outputs |
| `fm_output_amount/cmr/state/version(i)` | Contract fields at outer output `i`; fail for foreign or action outputs |
| `fm_output_module(i)`, `fm_output_hash(i)` | Module instance and canonical encoded hash of any outer output |
| `fm_input_asset_quantity((i, id))`, `fm_output_asset_quantity((i, id))` | u64 quantity, zero for an absent ID |
| `fm_input_authority((i, id))`, `fm_output_authority((i, id))` | Authority membership as bool |
| `fm_input_asset_count(i)`, `fm_output_asset_count(i)` | Number of balances |
| `fm_input_authority_count(i)`, `fm_output_authority_count(i)` | Number of authorities |
| `fm_input_asset_id((i, entry))`, `fm_output_asset_id((i, entry))` | Balance ID at a sorted entry index |
| `fm_input_authority_id((i, entry))`, `fm_output_authority_id((i, entry))` | Authority ID at a sorted entry index |
| `fm_issued_quantity(id)`, `fm_burned_quantity(id)` | Aggregate transaction quantity, zero if absent |

Invalid contract or entry indices fail. Output counts, hashes and module IDs
include action and foreign outputs; foreign outputs are otherwise opaque (there
is no mint-specific blinded-nonce parser and no foreign-input inspection). A
program can inspect the same successor as another program: applications that
need distinct successor allocation must enforce it in their policies, since the
module does not infer exclusivity or prevent double-satisfaction bugs.

### Authorization digest

The v1 digest (`common::signature_hash`) commits to the federation, module
instance, this instance's ordered contract outpoints and claim keys, the
transaction nonce, and **every outer output**, including mint blinded nonces and
asset actions. It excludes witnesses, outer signatures, foreign funding inputs,
and the creation signatures in action outputs of every decoded Simplicity
instance (replaced by zeroes, keeping their module IDs). This avoids signing a
signature, avoids cross-instance cycles, and lets a sponsor add funding inputs.
Reordering, removing or changing this instance's inputs or any output requires
fresh inner authorization; changing witnesses requires fresh outer signatures.

### Consensus clocks and expiring spend paths

Bitcoin block-count votes are monotonic per guardian and the exposed count
advances only with the configured threshold of votes; with insufficient votes it
is zero. It is a federation-agreed count, not a live tip that retreats on a
reorganization. Session indices come from core during live consensus and replay.
Neither clock measures wall time, and different modules' block-count votes need
not be processed at the same point.

This deliberately differs from
[Liquid's Simplicity timelocks](https://docs.simplicity-lang.org/documentation/timelocks/#no-maximum-time-constraints),
which inspect a transaction's declared locktime or sequence; chain rules then
enforce only a minimum inclusion time, so those jets cannot enforce expiry. That
is an execution-environment choice, not a limitation of the language. Under
Fedimint's normal Byzantine assumptions finalized consensus history does not roll
back on a Bitcoin reorganization, so genuine expiry fits here, as in the
[Lightning v2 module](../fedimint-lnv2-server/src/lib.rs).

Programs can require `fm_block_count() < deadline` for a claim and
`fm_block_count() >= deadline` for a refund: advancing the agreed clock closes the
claim without a competing transaction, though moving funds still needs a spend.
A predicate such as an even session index can close and reopen a path while the
contract stays unspent; monotonic clocks do not imply monotonic validity.

- Deadlines apply at ordered execution, not submission. Admission can succeed
  before a deadline and execution fail afterward, including when a block-count
  vote precedes the transaction in the same session. Consensus validation builds
  the current environment and executes again; no admission-time authorization
  result is cached.
- Preserve a usable fallback and allow for outages, delayed votes and inclusion
  delays. A deadline does not guarantee inclusion.
- Rejection need not be permanent. The [intent API](#durable-shared-contract-intents)
  keeps primary funding reserved after an unproven rejection; a timeout or error
  string is not evidence for safe reuse, while a confirmed competing spend can
  establish permanent invalidity.
- Expiring or reopening policies can cause repeated validation without an
  accepted-transaction fee. Resource limits bound each transaction, not the
  aggregate cost of concurrent or repeated submissions.

### Pruning

Guardians require maximal pruning: every revealed node must execute, and both
sides of each revealed `case` must execute at least once. Unused branches are
hidden commitments; a shared case can keep both used branches, and branch-free
programs are unchanged. Pruning preserves the CMR, while fees and resource limits
use the pruned bytes and static cost. A hidden branch cannot be rebuilt from the
submitted bytes, so retain the original template and witness material. Maximal
pruning commits a spend to its branch: if a clock change selects a hidden branch,
rebuild from the template. A branch-free predicate can still close and reopen for
the same submitted bytes.

### Execution baseline

Every guardian of a deployment must preserve this interpretation. Record the exact
Git commit, `Cargo.lock` and `flake.lock` with the deployed artifacts; a branch
name or the shared workspace version is not a sufficient identity.

| Component | Pinned interpretation |
| --- | --- |
| Module kind / configuration baseline | `simplicity` / `0.1` |
| Contract execution version | `1` (bitcoin and explicit assets); prototype version `0` is rejected |
| Guardian Rust runtime | `simplicity-lang =0.9.0` |
| C runtime and frame adapters | `simplicity-sys =0.8.0` |
| Wallet compiler | SimplicityHL Git commit `351eb068e30affc69189993739cd1b30b02b269d` |
| Jet encoding | One family bit: `0` + upstream Core encoding, or `1` + eight-bit context-jet ID |
| Context jet identities | SHA-256 of UTF-8 `fedimint/simplicity/jet/v0/` followed by the jet name |
| Context jet cost | 1,000 milliweight each; allowed Core jets use the pinned runtime's costs |

The `jet/v0/` domain names the custom-jet commitment scheme, not execution
version zero; it is kept so existing jet identities and CMRs do not change.
[The jet definitions](src/jet.rs) own the allowlist, IDs, types and adapters, and
the fixed [consensus vectors](tests/vectors/README.md) independently pin them.
Unsupported jets are rejected; Liquid programs must be ported. These are
prototype primitive identities, not CMRs backed by formal upstream jet
specifications, and pinning them establishes no worst-case cost calibration or
security proof. Treat changes to decoder allocation limits, the Core allowlist,
static costs, context interpretation, signature normalization or fee rounding as
consensus changes; a library patch release is not automatically safe to
substitute.

## Client API

### Low-level builders

1. `ContractProgram::compile(source, arguments(...))` compiles a policy;
   `owner_program(owner)` builds the minimal single-key policy.
2. `program.output(amount, state, recovery)` or `program.asset_output(...)`
   builds a funded output. A CMR alone is not a recoverable program: use the
   persistent wallet when mnemonic recovery is required.
3. `program.input(...)` with placeholder signatures assembles an unpruned draft.
   Select inputs, outputs, nonce and funding. Obtain a `PruningSnapshot` of
   resolved inputs and consensus clocks; `snapshot.environment(...)` builds each
   input's execution context.
4. Compute the real signature witnesses, then call
   `program.input_with_environment(outpoint, claim_key, witnesses, &environment)`,
   which executes and prunes from the original template. Estimate fees with
   `runtime::input_fee` on these bytes and `output_fee` for outputs. If funding
   changes the context, rebuild signatures and pruning and recheck fees.
5. Sign creations, then apply outer signatures once all witnesses are final.
   The prototype `sign_transaction` helper takes exactly one key per outer input,
   in transaction order. Submit through the normal Fedimint transaction API.

The [server tests](../fedimint-simplicity-server/src/tests.rs) are executable
examples. Low-level callers bypass the wallet's recovery and reservation
guarantees.

### Persistent wallet

Obtain `SimplicityClientModule` from a normal Fedimint client. Native funding and
change come from the client's primary module (bitcoin-denominated Mint v2 in the
examples).

- `receive(amount, bundle)` makes a fresh owner policy with encrypted recovery
  metadata, ready to hand to a sender. `output(descriptor, amount, state,
  bundle)` does the same for a versioned application template. The default
  `BuiltinTemplates` registry contains only the owner template; applications
  supply their own `ContractTemplates`, which may enforce output rules through
  `validate_output`.
- `submit_plan(TransactionPlan { spends, outputs, creations, receipt, max_fee })`
  reserves the spent contracts, obtains funding and change, authorizes the final
  transaction and durably records the submission, returning the operation and
  transaction IDs; the core executor resumes it across restarts.
  `SpendIntent::owner(outpoint)` installs an owner signature automatically;
  custom intents supply other witnesses and an optional signature witness name.
  `outputs` are `SimplicityOutput`s, including at most one action output; asset
  change and authority successors are explicit outputs. `creations` are fresh
  creation keys, used only at submission. An empty `spends` list is a direct send.
  `max_fee` caps the funded transaction's total fee, checked again after note
  selection.
- `quote_transaction(&plan)` runs the same preparation with a funding dry run;
  `plan_fee_request` prepares offline against a reusable snapshot so route
  planners avoid network requests per candidate, and `quote_fee_request` prices
  the result. Quotes reserve nothing and authorize nothing.
- `operation_status(id)` reads local submitted/accepted/complete/rejected
  progress without a federation request; `await_operation(id)` waits for
  acceptance and history synchronization or rejection cleanup. Unknown IDs,
  including original IDs after mnemonic recovery, return `None`.
- `sync()`, `contracts()` and `history()` refresh and list all recognized
  contracts (including spent ones) and ordered confirmed transactions; filter
  `spent_by == None` for current holdings. `contracts_page`/`history_page` page
  the same views; a continuation token belongs to one wallet view and must be
  restarted after a sync changes it. `watch_contract(s)` adds a local
  subscription to a public contract; watching a shared vault does not make its
  collateral the wallet's balance.
- `active_consensus_version()` returns the quorum-authenticated active rules.

The wallet signs and prunes a draft before selecting funding, then rebuilds with
final signatures. A branch whose fee changes after funding is rejected before any
reservation is committed; use the low-level fully funded construction for such
policies. `pruning_snapshot` queries the existing contract and clock endpoints,
which discloses interest in those outpoints; applications may supply already
authenticated metadata instead. Clock observations do not reserve an inclusion
window, and construction can fail early when a contract is not currently valid.

Descriptors carry template ID and version, parameters, a random key salt and
optional application data; the encrypted envelope must fit `MAX_RECOVERY_BYTES`.
Spending and metadata keys derive independently from the module root secret,
federation identity and instance ID. Use fresh receive requests, since repeated
ciphertext or policies link transfers. No backup upload or external file is used.

To recover after losing the database, use the normal client `recover(..., None)`
flow with the same root secret, wait for recovery, then reopen the client. The
wallet cannot submit until recovery completes. Recovery reconstructs holdings and
confirmed activity, including fully spent contracts, from authenticated
federation history (see [REQ-simplicity-recovery](../../specs/REQ-simplicity-recovery.md)).
Missing or unauthenticated history, or an owned descriptor whose template or
descriptor version this wallet does not support, fails recovery rather than being
skipped. Arbitrary imported programs,
local labels, failed attempts, original operation IDs, unfinished intents and
watch-only subscriptions without confirmed participation are not recovered.

### Sender receipts

When no owned input or output identifies a transaction, `submit_plan` adds an
encrypted sender receipt to the instance's action output; set
`TransactionPlan::receipt` to a `SenderReceipt` to include one anyway, optionally
with versioned `ReceiptContext` application data. Receipts use the action
output's recovery allowance and per-byte fee, create no UTXO, and need no guardian
endpoint. `history()` records them as sent activity without claiming recipient
ownership. Copies on unrelated transactions are ignored.

### Durable shared-contract intents

`submit_intent(intent, policy)` persists a versioned semantic request and returns
its local operation ID. `intent` and `intents` read durable records after
restarts; `await_intent` returns when an operation completes or needs attention;
`retry_intent` resumes a manual conflict; `cancel_intent` stops future attempts
but cannot retract a submitted transaction, which still resolves as accepted or
rejected. Losing connectivity leaves the same attempt pending.

`IntentPolicy` defaults to manual retry, at most three attempts and at most 100
sats of total fees per attempt. Automatic retry is opt-in with bounded,
persisted exponential backoff and jitter; both modes share the original limits
and immutable parameters. An optional session deadline stops preparing new
attempts; contract clocks govern acceptance. New attempts require primary-module
funding reservations (currently Mint v2) through
`TransactionBuilder::with_funding_reservations`. After authenticating permanent
invalidity, the originating module calls
`ClientContext::release_funding_after_conflict`; release is durable and
idempotent, and a concurrent operation may select restored notes first. Unproven
rejections pause with funds reserved and cancellation cannot release them.
Ordinary submissions and older pre-reservation attempts keep their original
funding behavior, including possible reclaim fees; imported ecash still requires
reissuance.

The default `NoIntentHandlers` registry rejects application intents. Supply an
`IntentHandlers` implementation through `SimplicityClientInit`. Database restarts
resume pending intents; mnemonic recovery does not recreate them.
[ARCH-simplicity](../../specs/ARCH-simplicity.md#shared-contract-conflicts)
states the safety rules.

### Diagnostics

`preflight::analyze` checks an exact candidate transaction offline against
caller-supplied snapshots, and `status::query` takes a one-shot operator view of
version and clock endpoints. Both are documented with their CLI in the
[runbook](../fedimint-simplicity-client/RUNBOOK.md#diagnostics).

## Guardian API

| Endpoint | Since | Result |
| --- | --- | --- |
| `contract(OutPoint)` | 0.0 | `Option<StoredContract>`, the current UTXO with creation clocks |
| `block_count(())` | 0.0 | The agreed block count |
| `asset(AssetId)` | 0.1 | `Option<AssetRecord>`, the immutable origin |
| `supported_consensus_version(())` | 0.1 | This binary's supported module rules |
| `active_consensus_version(())` | 0.1 | The durably active module rules |

All are unauthenticated. No single response proves federation consensus; use the
normal federation query and transaction confirmation mechanisms. `contract` and
`asset` perform one database point lookup; `block_count` reads at most one vote
per guardian. None compiles or executes a program, enumerates contracts or scans
history. Tests pin compact JSON result budgets of 16 KiB for a contract, 1 KiB
for an asset origin and 20 bytes for the block count, excluding the transport
envelope; these are regression budgets, not runtime limits. Simultaneous calls,
transport parsing and core history downloads are outside these bounds.

## Module upgrades

Configuration version `0.1` is the fixed baseline. The compiled
`SUPPORTED_CONSENSUS_VERSION` and the active consensus version are separate:
installing a newer binary neither activates its rules nor rewrites the
configuration. This release supports only the baseline; earlier prototypes,
including some also labeled `0.1`, used a different consensus-item encoding and
are not an upgrade source; their unpruned conditional spends are also invalid
under mandatory pruning.

Every guardian polls every peer's `supported_consensus_version` over the existing
module API, with a ten-second per-peer timeout, every thirty seconds. Missing,
malformed or older responses prevent proposing a higher version. These
observations are local and short-lived, never consensus state, and there is no
quorum-only override. When all peers report support, a guardian proposes a
`ModuleConsensusVersion` vote in the ordered consensus stream. Each peer's highest
vote is stored (missing means the baseline), and the active version is the highest
version a threshold of votes supports. It changes at the ordered item that reaches
the threshold, even within a session, and later votes or lost readiness cannot
lower it.

The vote encoding accepts future versions even on old binaries. An old binary
records minority votes but stops at an unsupported activation, on startup, during
validation and proposals, or when replay from an older checkpoint reaches that
boundary; an activated database cannot be downgraded by reinstalling an old
binary. Clients query `active_consensus_version` with quorum authentication
before building submission snapshots. Unsupported active rules produce an
update-required error and put automatic intents into attention.
`PruningSnapshot::default()` assumes the baseline.

When adding a future execution environment, extend the execution-version
activation table, preserve earlier environments' semantics and costs, gate both
creation and spending before expensive decoding, and keep accepting the original
configuration baseline and version-vote envelope. An old client is not promised
to understand future contract formats. Only a spend authorized by the contract
moves it to a new environment. Each concrete release needs its own compatibility
fixtures and mixed-version tests. The operator procedure is in the
[runbook](../fedimint-simplicity-client/RUNBOOK.md#upgrades-and-activation).

## Fees and limits

All consensus limits and fee terms are constants in
[`fedimint_simplicity_common::limits`](src/limits.rs); changing any of them
requires a new execution version. Every resource limit applies per module
instance, except `MAX_TRANSACTION_OUTPUTS`, which counts all outer outputs of a
transaction with Simplicity items. Fedimint creates one instance per module kind,
so in practice they are per-transaction limits.

- **Counts and sizes.** `MAX_CONTRACTS` Simplicity inputs and, separately,
  Simplicity outputs (including the action output) per instance; `MAX_PROGRAM_BYTES` and `MAX_WITNESS_BYTES` per input;
  `MAX_TRANSACTION_REDEMPTION_BYTES` of programs plus witnesses per instance;
  `MAX_RECOVERY_BYTES` per output; `MAX_ASSETS` entries of either kind per bundle,
  created assets per action output, and distinct assets per transition.
- **Decoding.** An allocation-free structural scan checks declared node counts
  and constant lengths against the actual bytes before the pinned decoder
  reserves memory. Upstream then checks canonical encoding, sharing and types,
  and inferred type sizes (`MAX_TYPE_BITS`, `MAX_TOTAL_TYPE_BITS`) are checked
  before witnesses are decoded. Execution is bounded by static cost,
  `MAX_EXTRA_CELLS` and `MAX_EXTRA_FRAMES`.
- **Cost.** Each program's static cost is capped by `MAX_PROGRAM_MILLIWEIGHT`
  (kept as a decoder safeguard), and the instance's programs plus
  `CREATION_SIGNATURE_MILLIWEIGHT` per creation batch must fit the stricter
  `MAX_TRANSACTION_MILLIWEIGHT`. One creation signature can authorize several
  assets. Resource charges add no second fee.

Fees:

- A **spend** costs `BASE_ITEM_FEE_MSAT` plus one msat per rounded weight unit of
  the submitted program's static cost and per program and witness byte.
- An **output** costs `BASE_ITEM_FEE_MSAT` plus one msat per recovery byte, plus
  one msat per byte of the encoded asset bundle (contracts) or encoded actions
  (action outputs), plus `CREATION_FEE_MSAT` per created asset. The creation fee
  applies once at genesis, not on later issuance.

Rejected transactions pay no module fee. Guardians do not time execution or charge
script cost on creation. These coefficients are prototype values pending
production calibration; Raspberry Pi 5 is the minimum guardian performance target,
and calibration requires measurements on it. The
[resource benchmark harness](../fedimint-simplicity-server/benches/resources/README.md)
informs, but does not set, the coefficients.

Guardian validation of one instance runs in the order recorded in
[ARCH-simplicity](../../specs/ARCH-simplicity.md#transaction-validation); core
validates touched instances in ascending instance ID order, so a multiply-invalid
transaction returns the first failure in that order. Structure failures use an
input-error envelope. Validation retains decoded programs within an 8 MiB logical
budget per attempt, re-decoding on a miss, and each instance keeps a 32 MiB cache,
measured the same way, of programs that matched a stored contract. Neither is an
RSS ceiling, and neither bounds aggregate load from repeated requests.

## Retention and privacy

Spending removes the live UTXO and its recovery annotation, so any state a
successor needs must be carried forward. Core transaction history retains the
original bytes indefinitely: removing the live record does **not** erase
historical ciphertext. Values, policies, revealed programs, witnesses, asset
flows and recovery bytes are public to guardians and in retained history; the
wallet encrypts descriptors and receipts. There is no public wallet identifier and
no guardian scanning endpoint. Hidden branches reveal only commitments, which
does not hide executed policy, values or witnesses.

## Applications and templates

The core SDK supplies native contracts, public asset operations, persistent
submission, reservations, encrypted descriptors, receipts and history-based
recovery, plus generic template and intent-handler extension points. It is not a
market or exchange kit. `tvolk131/fedimint-simplicity` maintains binary-market,
limit-order, partial-order, constant-product and top-up/release implementations as
reference consumers of the public Rust API, with their policy and oracle helpers,
examples, template vectors and ledger/live lifecycle tests. They register
explicitly; the core crates do not depend on them, and they are not officially
supported. Private transfers, discovery and indexing, CLI support and trading UIs
are out of scope. Applications validate immutable asset origins, not only current
holdings, and follow successors through the public watch and history interfaces.

Wallet binaries must bundle every template definition needed to interpret their
historical descriptors, including the version-one `owner` template; recovery must
not fetch policy source or need another backup. Never silently reinterpret a
deployed template version: keep its source, argument encoding and compiler output
unchanged and ship a new version instead (see the
[template vectors](../fedimint-simplicity-client/tests/vectors/README.md)).
Policy migration requires an authorized spend. Consumer qualification must name
exact core and application revisions and exercise construction, spending, conflict
handling, database loss, recovery and a subsequent spend through public
interfaces; a local path override is development evidence only.

## PTLC settlement example

The optional `ptlc` client feature demonstrates an interactive point-locked
exchange using execution version one: guardians verify ordinary BIP340 signatures
and their agreed block count, and no jets, consensus rules, endpoints or guardian
secrets are added. It is not a Lightning implementation: there are no invoices,
routing, gateway driver, offline receiving or recovery descriptor for PTLCs. The
caller retains the terms, template, signing keys and adaptor transcripts.

`ptlc::Ptlc` commits to three distinct keys (the funder's claim and refund keys
and the claimant's key), a full secp256k1 payment point and an expiry. Its output
state is SHA-256 of the compressed point, and `validate_output` checks the agreed
amount and empty bundle; applications must still authenticate the output's
inclusion and exact outpoint. Before expiry the claim branch requires **both**
the funder's claim-key signature and the claimant's signature over the inner
digest; at or after expiry the refund branch
requires only the funder's refund key, with no claimant cooperation (its outer
claim key can be the funder's own). Both branches verify the payment commitment,
and both still need outer signatures. The claim signatures bind payout outputs
(including mint blinded nonces), claim keys, nonce and consumed outpoints, so
neither party can redirect a co-authorized claim; after expiry the funder signs a
refund to any destination. A refund after a claim has spent the output fails.

The funder's claim and refund keys must differ: `REFUND` is a witness outside the
inner digest, so with one key a claimant could replay a completed pre-expiry claim
signature through the refund path after expiry. `Ptlc::program` rejects duplicate
keys. The point relationship is enforced by the off-chain adaptor exchange, not on
the ledger:

1. Agree and authenticate the terms and the funded contract, and assemble the
   exact claim transaction (outputs, claim key, nonce, fees).
2. The funder computes `common::signature_hash(federation, module, &transaction)`,
   calls `AdaptorSignature::encrypt` with its key, the point and that digest, and
   persists the transcript before handing it over.
3. The claimant checks outputs and fees, `verify`s the adaptor, and once it knows
   the scalar calls `complete` and signs the same digest.
4. Supply both values through `Ptlc::witnesses(SpendPath::Claim, ...)`, prune with
   `input_with_environment` against an authenticated snapshot, recheck the fee and
   sign the outer transaction. Any change to signed fields restarts signing.
5. The funder `extract`s the scalar from the published witness with its retained
   transcript and checks it against the full payment point.

`schnorr_fun` implements the adaptor operations with nonce derivation that
includes the encryption point; do not improvise nonces, reuse them, or hand over
an unrestricted normal claim signature instead. For sending, the user funds and a
gateway claims after settling an external PTLC; for interactive receiving, the
gateway funds and the online recipient claims. Offline receiving needs another
mechanism. External protocols may need point-tweak translation and their own
expiry rules.

**Publishing a completed signature immediately reveals the scalar to anyone
holding the adaptor transcript**, even if the transaction is rejected, delayed or
loses a competing spend; extraction is not proof of acceptance. Expiry uses the
agreed block count, not wall time or an external node's height, so admission
before expiry does not reserve inclusion. After expiry the funder can refund even
if the claimant learned the scalar, so a receiver must secure its claim well
before the deadline. Repeating external payments or revealing new claims while an
earlier attempt is unresolved needs a separate durable protocol. Real applications need coordinated timeout margins and
monitoring; these tests establish no production Lightning safety margin.

```sh
cargo test -p fedimint-simplicity-client --features ptlc --lib ptlc::
cargo test -p fedimint-simplicity-server --lib tests::ptlc::
```

The server fixtures fund PTLCs with real Mint v2 notes, settle into new notes with
exact execution fees and spend those notes; dummy funding only bootstraps and sinks
value, and positive final spends use normal SDK pruning and the real transaction
processor. Coverage includes adaptor parity and point signs, transcript tampering,
wrong scalars, keys and messages, funded-term validation, redirected payouts,
unfunded spends, duplicate and competing claims, and admission versus ordered
expiry. The fixtures use zero mint fees and are not fee calibration or live-network
qualification.

## Testing

Put each check in the cheapest layer that can fail for the right reason.

| Layer | Question it answers | Where | Cost |
| --- | --- | --- | --- |
| Unit / module policy | Do hooks, config, API and upgrade logic behave? | server `src/tests.rs`, `src/tests/*.rs` | seconds |
| VM | Does a program decode and execute to the expected result, cost and error? | common crate VM and jet tests; each resource fixture in `fixtures::check_all` | seconds |
| Core | Does Fedimint's transaction processor give the same outcome in submission and consensus modes, with funding and without leaking writes? | server `src/tests/assets/{instances,context,resources}.rs`, `tests/resource_workloads.rs` | seconds to minutes |
| Live | Do separate guardian processes, TLS P2P, WebSocket API, Aleph consensus, RocksDB and real clients agree? | server `src/tests/assets/network.rs` and below | minutes each |

Core tests use the real transaction processor with Mint v2 blind signatures and
an in-memory database; a dummy module provides only initial funding and the final
accounting sink. They cover timelocks, foreign blinded outputs, covenant state,
funding failures, invalid outer signatures, duplicate spends, malformed
bytecode and witnesses, limits, two instances, and rollback.
`tests/resource_workloads.rs` runs the benchmark corpus's correctness assertions
(`fixtures::check_all` and the adversarial families) as ordinary tests.

Live scenarios run four guardians as OS processes, re-executing the test binary
through the ignored `guardian_process_entry`
(`guardian_entry_is_a_registered_ignored_test` guards its name). Bitcoin RPC is
simulated through a file and funding is the dummy module plus real Mint v2 ecash;
each scenario has its own timeout.

| Scenario (`tests::assets::network::`) | Timeout | What only a live run shows |
| --- | --- | --- |
| `four_guardians_submit_settle_and_recover_assets_from_disk` | 180 s | Asset lifecycle reaches all guardians; a killed guardian rejoins on its RocksDB and catches up; spent contracts stay spent. |
| `sessions::creation_sessions_and_expired_policy_replay_match_authenticated_history` | 180 s | Creation sessions and expired-policy replay match authenticated history across a restart. |
| `status::operator_status_observes_four_guardians_and_a_missing_peer` | 90 s | Operator status, including one guardian down. |
| `wallet::direct_sender_receipts_restore_history_without_owning_recipient_contracts` | 180 s | Receipt history and recovery for sends funded by another module. |
| `wallet::mnemonic_only_client_recovery_preserves_assets_history_and_spendability` | 180 s | Recovery from the root secret and federation history alone. |
| `wallet::pruning::funding_sensitive_pruning_and_stale_plans_roll_back_real_ecash` | 180 s | Funding-sensitive pruning and stale plans roll back reservations and real ecash. |
| `wallet::receipts::watched_shared_contract_submission_survives_mnemonic_only_recovery` | 180 s | A watched shared contract's submission survives recovery. |

The release check requires exactly these names (`simplicity_network_tests` in
`scripts/tests/simplicity-release-checks.sh`), and
`scripts/tests/simplicity-test-selection.sh` fails when one is missing, ambiguous
or ignored; change the list in the same commit as the scenarios. Application
lifecycles are owned by `tvolk131/fedimint-simplicity` (`tests/ledger`,
`tests/live`); their relocation is not permission to drop those assertions.

[REQ-simplicity-recovery](../../specs/REQ-simplicity-recovery.md) acceptance
coverage:

| Condition | Live scenario | In-process |
| --- | --- | --- |
| Database deleted, no backup; holdings, authorities and spendability restored | `mnemonic_only_client_recovery_…` | |
| A wallet that spent every contract recovers its history | `mnemonic_only_client_recovery_…` | |
| Direct sends restore sender activity; receipts confer no ownership; copies create no history; receipt context survives | `direct_sender_receipts_…` | client `src/receipt/tests.rs` |
| A watched shared contract's confirmed submission recovers | `watched_shared_contract_submission_…` | |
| Guardian state survives a hard restart | `four_guardians_…_from_disk`, `creation_sessions_…` | |
| Historical descriptor versions | not live | client `src/wallet/tests.rs` (`compatible_wallet_software_restores_historical_template_versions`) |
| Interrupted recovery resumes without loss or duplicates | not live | client `src/wallet/tests.rs` (`pending_prefix_resumes_after_reopening_and_rejects_history_gaps_or_changes`) |
| Foreign or copied records ignored; unsupported owned templates fail atomically | not live | client `src/wallet/tests.rs` |

### Running

`scripts/tests/simplicity-release-checks.sh` pins the toolchain and exports
`RUSTFLAGS="--cfg tokio_unstable"` and `FM_TEST_USE_REAL_DAEMONS=0`; export the
same when running `cargo` directly, or Cargo rebuilds the workspace. Live tests
bind local ports.

```sh
# Library tests of the three crates.
cargo test -p fedimint-simplicity-common -p fedimint-simplicity-client -p fedimint-simplicity-server --lib
# Everything except the live scenarios, as the release check runs it.
bash scripts/tests/simplicity-release-checks.sh tests
# Resource-workload correctness only.
cargo test --release --locked -p fedimint-simplicity-server --test resource_workloads
# The live scenarios with the required-selection guard.
bash scripts/tests/simplicity-release-checks.sh network
# One live scenario while developing.
cargo test --release --locked -p fedimint-simplicity-server --lib -- \
  tests::assets::network::status:: --nocapture --test-threads=1
```

The fixed [consensus vectors](tests/vectors/README.md) pin encodings, the signing
hash, asset IDs, custom jets and selected execution results, and describe the
mutation, sanitizer and cross-architecture campaigns.

### Release qualification

On the exact clean candidate source, in the development environment, run every
focused phase:

```sh
just format
bash scripts/tests/test-simplicity-test-selection.sh
bash scripts/tests/simplicity-release-checks.sh tests
bash scripts/tests/simplicity-release-checks.sh docs
bash scripts/tests/simplicity-release-checks.sh network
bash scripts/tests/simplicity-release-checks.sh guardian
bash scripts/tests/simplicity-release-checks.sh clippy
nix develop .#lint --command env NO_STASH=true bash misc/git-hooks/pre-commit
```

The driver checks required legacy-mint and network test names with the same
package and feature selection used for execution; missing, ambiguous or ignored
required tests fail, and execution must account for every selected runnable test.
Inventories, ignored names, totals and failures go to
`evidence/test-selections/<selection>/` (`result.txt` records status and exit
code; a new attempt invalidates an older success first). These guards cover the
filtered selections, not every suite or doctest; Mint v2 `db::snapshot_`
generation tests are intentionally filtered out. Guardian builds require clean
source and keep ordinary and enabled artifacts separately with source, lockfile,
compiler, feature and checksum identities; a version probe does not establish a
functional module.

The `Simplicity release checks` workflow
(`.github/workflows/simplicity-consensus.yml`) runs these phases on the Simplicity
release branches and adds native Linux x86-64/ARM64 comparison, seeded mutations
and instrumented sanitizer and leak checks. Local Mac results do not replace
these candidate-specific jobs. These
focused checks do not qualify the whole workspace, WASM, live Bitcoin or Lightning
backends, Pi resources or a deployment; the
[beta checklist](../../docs/simplicity/release/beta-checklist.md) tracks those
gates.

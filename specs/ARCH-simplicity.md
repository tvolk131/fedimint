# ARCH-simplicity: Experimental Simplicity contracts

The opt-in Simplicity module extends the module topology in
[ARCH-fedimint](ARCH-fedimint.md) with a contract UTXO ledger for bitcoin and
explicit assets whose spending conditions are Simplicity programs. It depends on
core transaction funding, outer signatures and consensus ordering; no other
module depends on it. The persistent wallet must satisfy
[REQ-simplicity-recovery](REQ-simplicity-recovery.md). Usage, API, limits and
tests are in the [module README](../modules/fedimint-simplicity-common/README.md);
operation is in the [runbook](../modules/fedimint-simplicity-client/RUNBOOK.md).

## Responsibilities

- **Core** orders transactions, verifies outer signatures, enforces native
  bitcoin funding and conservation, rolls back a failed transaction across all
  modules, and retains session history. It gives module hooks a read-only view of
  the actual outer transaction, the federation identity, module instance, session
  index and processing mode. It knows nothing about programs or asset quantities.
- **`fedimint-simplicity-common`** owns versioned consensus encodings, the
  deterministic runtime and jets, the consensus limits and fee terms, and the
  authorization digest.
- **The guardian module** owns live contract UTXOs with their creation clocks,
  block-count and upgrade votes, namespace markers and asset origin records,
  program execution, asset accounting and the bitcoin liability audit. It never
  compiles source, trusts caller-supplied environment values, or interprets
  recovery annotations.
- **The client** owns SimplicityHL compilation, witnesses and pruning, funding
  reservations, submission tracking, encrypted descriptors and receipts,
  authenticated recovery and history, and durable intents.
- **Applications** own their policies, oracles, templates and semantic intent
  handlers, and any rule that successors must be distinct.

## Transaction validation

Validity is a deterministic function of the transaction, the ordered database
snapshot, the consensus clocks and the active module version. Admission and
ordered execution use the same hooks, and replay uses the replayed session.
Processing mode, scheduling, caches and timing may change performance but never a
result or a fee.

Core calls each touched module instance's `validate_transaction` once, in
ascending instance ID order, after every input's `verify_input` and before any
input or output is processed, against the unmodified snapshot. The typed result
is passed only to that instance's `process_input_with_context` and
`process_output_with_context`; modules without whole-transaction validation use
`()` and keep their original behavior. No core wire format changes.

For each instance the Simplicity guardian runs, in order: cheap structure checks;
resolution of every spent contract from its own database namespace; admission,
program decoding on a worker pool, the static-cost budget, and program
commitment and execution-version checks; then asset accounting and program
execution. **No program executes until every program of the instance has passed
its checks**, and nothing expensive happens before the cheap checks. Processing
then applies the validated changes: inputs remove live records, outputs insert
contracts, namespace markers and origin records.

Each contract input reports its gross bitcoin value to core funding and each
contract output the value it locks, so contract execution cannot mint native
bitcoin, bypass outer signatures or commit partial spends. The client runs the
same structural and resource checks before committing reservations, before outer
signatures exist.

## Authorization and execution environment

Programs authorize an inner digest binding the federation, the module instance,
this instance's ordered spent outpoints and claim keys, the nonce, and every
outer output. Exclusions are deliberate: witnesses and outer signatures would be
circular; foreign funding inputs are left out so a sponsor can add funding; and
creation signatures in every Simplicity instance's action output are zeroed to
avoid self-reference and cross-instance signing cycles. The claim keys' outer
signatures then cover the whole transaction, witnesses included.

A program sees its consumed contract, every resolved contract its instance
spends, typed contract successors within its instance, opaque module IDs and
hashes of all other outputs, issuance and burn quantities, and consensus clocks.
It has no typed access to foreign modules' data and no contract view of action
outputs. Several programs may inspect one output; assigning distinct successors
is an application policy obligation.

Submitted programs must be maximally pruned for their witness and the actual
environment: every revealed node executes and every revealed `case` executes both
branches. The guardian checks this during its single VM pass; canonical decoding
and maximal sharing remain the pinned runtime's responsibility. The client prunes
from the original template against an observed snapshot, but guardians build
their own context. Fees and limits apply to the pruned bytes, so a hidden branch
can be used only by rebuilding from the template.

## Consensus clocks

The block count is the threshold-th highest of monotone per-guardian votes, zero
until a threshold has voted; the session index comes from core. Neither is wall
time. Validity is evaluated at ordered execution, so admission reserves nothing:
a clock change ordered before a transaction can invalidate it, and an expired or
closed path can reopen. Because finalized consensus history does not roll back
with Bitcoin reorganizations, a `count < deadline` path genuinely expires, unlike
locktime-style timelocks.

## Assets

Native bitcoin conservation is core-owned; asset conservation is module-owned:
for every asset, consumed plus authorized issuance equals created plus explicit
burns. Issuance requires consuming the asset's authority and satisfying its
program. Authorities are unique and indivisible, have at most one successor, and
are destroyed when omitted. Core accounting, the mint and the liability audit
never see asset quantities.

Creation starts at zero supply under a namespace derived from a fresh client key,
the federation and the instance; asset IDs derive from the namespace and an
ordinal, independent of funding inputs. Namespace markers and immutable origin
records are permanent, so destroyed assets cannot be recreated and clients can
verify an asset's initial authority policy; the creation key confers no further
authority. At most one action output per instance carries a transaction's
creations, issuance and burns, and it creates nothing spendable.

## Resource bounds

Every consensus limit and fee term is a constant in
`fedimint_simplicity_common::limits`; changing one requires a new execution
version. Every limit applies per module instance, except
`MAX_TRANSACTION_OUTPUTS`, which counts all outer outputs. Fedimint creates
exactly one instance per module kind, so these are per-transaction limits in
practice; if a federation could ever hold several instances of one kind, the
per-transaction bound would multiply and need revisiting.

Bounds are enforced before the work they bound: a structural scan checks declared
sizes before the decoder allocates, type bounds are checked before witnesses are
decoded, and the static-cost budget is checked before any program runs. Fees use
static bounds and encoded bytes, never measured execution. Rejected transactions
pay nothing, so the limits bound each transaction's work, not aggregate load from
repeated or concurrent submissions.

Each instance owns its worker threads, admission limit and decoded-program
cache. Decoding and execution run on dedicated threads, never the async runtime
that serves the API and drives consensus: one thread for agreed transactions and
a separate submission pool, so agreed transactions never queue behind submissions
(though all share the CPU). A submission waits for one of a fixed number of
admissions before decoding and holds it until its programs are freed, bounding
how many submissions hold decoded programs. Submissions are delayed, never
refused, because clients would read a refusal as an invalid transaction;
connection limits do not bound them because API requests outlive connections.
Programs are dropped on worker threads, whose large stacks fit deeply nested
types.

Retention of decoded programs within one attempt and the per-instance cache
change only performance. The cache admits a program only after it passed the cost
and commitment checks against a stored contract, keyed by SHA-256 of its program
and witness bytes, so admission, revalidation and consensus share it. The
commitment does not cover the witness, so an owner can churn the cache with spends
that fail execution; validation then decodes as it would without a cache.

## Versioning and activation

Execution version one is the sole baseline; prototype version zero is rejected and
no prototype state migrates. An execution version's runtime, jets, commitments
and costs never change for existing contracts. A new environment requires an
activated module version before creation or spending, and only a spend authorized
by the contract moves it there.

The configuration baseline is fixed, and compiled support is distinct from the
active rules. Guardian-local observations that every peer supports a version only
authorize proposing a vote; they never enter validation or recovery. Ordinary
ordered consensus stores monotone per-peer votes, and a threshold activates a
version at an exact item; missing peers delay proposals but never reverse an
activation. Guardians must decode future votes they cannot execute, and an
unsupported activation stops the guardian, including at startup or checkpoint
replay, instead of becoming an ordinary rejected item that would let it continue
under divergent rules. The security assumption remains fewer than one third
faulty guardians. History decoding preserves unknown output and consensus-item
variants, without promising that old wallets understand future contracts.
Clients read the active version with quorum authentication and check
construction before reserving funding.

## Retention and privacy

Spending deletes the live record and its annotation; core history retains the
original transactions indefinitely, and recovery depends on that retention.
Guardians treat annotations as opaque bounded bytes and identify no wallet.
Contract amounts, asset transfers, policies and revealed witnesses are public.

## Client and application boundary

The core client owns generic construction, fee preparation, authorization,
funding and reservations, submission tracking, assets, descriptors, receipts and
authenticated recovery and history. Its default template registry contains only
the single-key owner policy; `ContractTemplates` and `IntentHandlers` are explicit
extension points, and application-specific output checks belong to templates.

Market, oracle, order, AMM and top-up policies and their handlers live in a
separate reference repository outside the core client's dependency graph; they
consume public APIs and register explicitly, without an official support promise.
Guardians have no application-specific rules: the reference binary market, for
example, encodes collateral, oracle resolution and redemption entirely in
Simplicity, serializes collateral operations through one shared vault, and relies
on clients verifying immutable asset origins as well as current holdings.
Wallet releases bundle historical template definitions: recovery never fetches
source, and moving application code changes neither descriptor meaning nor policy
commitments.

## Wallet recovery

The wallet reconstructs current contracts and confirmed interaction history from
one ordered scan of existing federation session history, using Fedimint's
history-recovery infrastructure, and persists progress so an interruption
resumes. It cannot submit until recovery completes; other modules follow their
own rules. Completed sessions use the signed-session API when the negotiated core
API and trusted broadcast keys support it; open sessions, older APIs and configs
without those keys use quorum-authenticated history. Invalid signed data fails
over to another peer and is never accepted unauthenticated. Unknown modules keep
their bytes for signature verification. Recovery, ongoing sync and watch imports
share this path; there is no recovery endpoint, live-contract scan or concurrent
backfill.

Wallet software owns versioned templates, descriptors, key derivation,
annotation encryption and recognition of its activity. A versioned descriptor
names a template, its parameters, a random key salt and optional application
context; encryption and spending keys use separate mnemonic derivations scoped to
federation and module. Receivers hand senders a destination contract with a
freshly encrypted annotation, so senders need no discovery key and wallets no
stable identifier. Wallet-specific information that cannot be derived must be in
federation records; a commitment alone cannot recover a program. A decrypted
descriptor counts only if it recompiles to the contract's execution version and
commitment (otherwise it is treated as copied ciphertext), and only authenticated
history counts. Missing history or an unsupported owned descriptor fails recovery
instead of completing.

Each authenticated session prefix updates recognized contracts, spent status,
confirmed transactions, successor links and the scan cursor in one client
database transaction, and an open session's saved prefix must match its later
extensions exactly. Original spent descriptors identify terminal spends without
an extra UTXO. Templates can recognize successors that preserve a policy and its
authorities, or through a contract-enforced mapping from module-local input index
to absolute output index; a copied policy alone never proves lineage, and watching
a shared contract does not make its value wallet funds. Importing a new watched
origin replays its authenticated history through exactly the already-scanned
prefix and merges the result atomically under the scan lock, so it cannot race a
cursor that already passed a consumption. Local pages over contracts and history
never drop spent records; a continuation token belongs to one wallet view.

When no recognized wallet input or output identifies a submission, the wallet adds
an encrypted sender receipt, at most one per instance, in the action output's
recovery bytes. Receipts use their own mnemonic derivation and fresh randomness
and record sent activity without implying ownership. Their commitment binds input
order and module IDs, the nonce and outputs; Simplicity inputs contribute
outpoints and claim keys while foreign inputs keep their full encoding. Programs,
witnesses and outer signatures are excluded, and across all Simplicity instances
receipt annotations and creation signatures are normalized out to break
circularity. Copied receipts with a mismatching commitment are ignored; an
authenticated, matching but unsupported receipt is an error.

Core client finalizers prepare reserved receipt metadata after funding, change
and nonce are fixed, then authorize outputs and inputs, then verify final
invariants before outer signatures and state-machine IDs; replacements cannot
change the transaction shape or cross module boundaries, and core checks that
fees are unchanged. Simplicity reservations commit with durable core submission
state, are released on rejection, and accepted transactions synchronize into
confirmed history. Initial recovery uses core's unusable-module mode, and
applications reopen the client afterwards.

## Shared-contract conflicts

A durable, versioned semantic intent is a client operation above individual
submissions; wallet software registers handlers that keep historical intent
meaning, and the default registry has none. Guardians enforce the same contracts
either way, and these mechanisms change no consensus rule.

Each attempt's core submission, primary funding, Simplicity reservations and
association with its intent commit in one client database transaction. A pending
attempt must resolve before a replacement is built. A definitive rejection permits
rebuilding only after authenticated history shows a competing transaction spending
a designated shared input; error strings and timeouts are insufficient. Handlers
read contracts and authenticated successor links from one snapshot, so a rebuilt
attempt follows the shared contract to its current successor. Manual
retry is the default; automatic retry uses persisted backoff and jitter. Attempt
limits, a final funded fee cap per attempt (core checks actual total fees,
including funding and change overpayment, before authorization) and an optional
preparation deadline cannot be reset by retry.

New attempts use durable primary funding reservations through the shared client
interface. The funding module keeps owned notes on rejection; Simplicity
authenticates a permanent conflict and requests local release, then waits for
restoration before retrying or finishing cancellation. Unproven rejections pause
with funding reserved and no automatic paid reclaim; timeouts cannot expire a
submitted reservation, and cancellation still resolves in-flight submissions. An
unavailable federation leaves the attempt pending, and construction or funding
errors pause for attention rather than resubmitting. Pre-reservation operations
keep their original funding behavior.

Intent progress waits on committed database notifications; timers only drive
backoff and retry failed advancement, and every wakeup rechecks durable state.
Database restarts resume pending intents, but mnemonic recovery must not recreate
or execute unfinished intentions, and watch-only subscriptions without confirmed
participation are local state.

## Alternatives

Compact module-specific recovery history remains a possible download
optimization. It must retain enough information to reconstruct confirmed
activity as well as current holdings. A live-contract scan alone cannot recover
fully spent activity, and combining it with historical backfill would add scan
consistency and concurrent-operation complexity; it is deferred until recovery
measurements justify it. Neither optimization is required by
[REQ-simplicity-recovery](REQ-simplicity-recovery.md).

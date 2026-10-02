# ARCH-simplicity: Experimental Simplicity contracts

## Status

The guardian contract ledger, execution environments, explicit assets, and
client builders, and persistent wallet described below are implemented as an
experimental prototype. Encrypted descriptors and authenticated history replay
support mnemonic-only recovery for the wallet's supported contracts. The wallet
must satisfy
[REQ-simplicity-recovery](REQ-simplicity-recovery.md).

## Module and transaction boundaries

The opt-in Simplicity module extends the module topology in
[ARCH-fedimint](ARCH-fedimint.md) with a contract UTXO ledger for bitcoin and
explicit assets.
It depends on Fedimint transaction funding and consensus ordering; the mint does
not depend on it. [Prototype usage and limits](../modules/fedimint-simplicity-common/README.md)
belong with the implementation.

Core consensus supplies modules with a read-only view of the actual outer
transaction, the federation identity, module instance, and current session index.
Admission and ordered execution use the same context-aware validation hooks;
replay uses the session being replayed. Existing modules retain their original
validation behavior through default hook implementations. No new core transaction
wire format is introduced.

Core invokes a module validation hook against the unmodified transaction snapshot
before processing inputs or outputs. A transaction-local, type-erased result is
passed only to that module's processing hooks. Simplicity resolves every consumed
contract, validates asset accounting, and executes programs in that phase; it
applies the validated changes during ordinary input/output processing.

Each contract input consumes one module UTXO and reports its gross bitcoin value
to core funding. Each contract output separately reports the value it locks.
Core funding, outer signatures, and transaction-wide database rollback remain
responsible for conservation and atomicity across modules. Contract execution
cannot mint native bitcoin, bypass outer signatures, or commit partial spends.

The common crate owns versioned consensus encodings and the deterministic runtime.
The guardian owns current UTXOs, creation clocks, and threshold block-count votes.
The client owns SimplicityHL compilation and witness construction; guardians do
not compile source or trust caller-supplied environment values. Programs authorize
an inner digest that binds all this module instance's spending references and
claim keys, the nonce, and every outer output. Witnesses and outer signatures are
excluded to avoid circular commitments. Foreign funding inputs are excluded to
permit sponsorship.

The first execution environment exposes the current consumed contract, rich
successor views within its module instance, opaque hashes of foreign outputs,
and consensus clocks. It does not provide typed access to foreign modules'
internal data. Multiple programs may inspect the same output; assigning distinct
successors is an application policy obligation.

Live contract records, including opaque recovery annotations, disappear on spend.
Core history retains their original transactions for mnemonic recovery. Contract
amounts, asset transfers, policies, and public witnesses remain transparent.

## Execution versions and explicit assets

Execution version zero pins its runtime, permitted jets, commitments, and cost
semantics. Future versions must preserve the interpretation of existing outputs;
contract-authorized spending is the migration boundary.

Execution version one adds bounded multi-asset balances and unique, indivisible
issuance authorities to contract outputs. A separate module action output carries
creation, issuance, and destruction declarations without creating a UTXO. Asset
conservation is module-owned; core bitcoin accounting and the mint remain unaware
of asset quantities. Issuance requires consuming the relevant authority and
satisfying its program. Authorities cannot be copied and may be destroyed.

Creation namespaces derive from fresh client signing keys, federation identity,
and module instance; ordinal-derived asset IDs are independent of funding inputs.
Creation is authorized over the version-one intent and starts with zero supply.
Permanent namespace markers prevent replay after destruction. Immutable asset
records identify the initial authority policy so clients can verify provenance.
Creation keys confer no ongoing authority. Creation signatures across Simplicity
module instances are excluded from the v1 intent to avoid self-reference and
cross-instance signing cycles; v0 encoding and signing remain unchanged.

The expanded execution environment exposes all resolved module inputs, successor
asset balances and authorities, and issuance/destruction quantities. The client
SDK constructs these transitions. Its binary-market example encodes collateral,
oracle resolution, and redemption policy entirely in Simplicity, without guardian
market-specific rules. A unique shared vault serializes collateral operations;
independent position transfers do not consume it. Clients verify immutable asset
origins as well as current holdings before trusting the market policy.

## Wallet recovery design

The initial persistent wallet reconstructs current contracts and confirmed wallet
interaction history in one ordered scan of existing federation session history.
It uses Fedimint's history-recovery infrastructure and persists progress so an
interruption can resume. The Simplicity wallet cannot submit new transactions
until recovery completes; other modules follow their own recovery rules. There
is no separate live-contract scan or concurrent history backfill in this design.
No new guardian recovery endpoint is required for the initial history scan.

Wallet software owns versioned contract templates, descriptors, key derivation,
annotation encryption, recognition of its historical activity, and reconstruction
of usable state. Wallet-specific information that cannot be derived must be
preserved in federation records. A program commitment alone cannot recover an
arbitrary program or its secrets. Older template and descriptor versions must
remain interpretable by compatible wallet releases.

Guardians continue treating annotations as opaque, bounded transaction data;
they do not identify wallets or validate the meaning of encrypted descriptors.
Wallets must verify recovered descriptors against the actual contract and use
authenticated federation history. Recovery requires retention of the historical
records, even after the corresponding live contracts are deleted. The scan must
recognize terminal spends with no Simplicity successor and preserve their
confirmed activity rather than only the remaining holdings.

The recovery contract does not depend on Fedimint's deprecated encrypted-backup
service. A versioned descriptor identifies a software template, its parameters,
a random key-derivation salt, and optional application context. Encryption and
spending keys use separate mnemonic derivations scoped to federation and module.
Receivers provide the sender with a destination contract and freshly encrypted
annotation; the sender needs no discovery key or stable wallet identifier.

Each authenticated session prefix updates recognized contracts, spent status,
confirmed transactions, and the scan cursor in one client database transaction.
The open session's saved prefix must match later extensions exactly. Original
spent descriptors identify terminal interactions without an extra receipt UTXO.
A shared binary-market vault remains recognizable through successors preserving
its policy and issuance authorities, even when another participant replaces its
annotation. Watching that vault does not count all its collateral as wallet funds.

The initial persistent submission API requires at least one recognized wallet
input or output. Directly funding only someone else's contracts from another
module is rejected because it would leave no recoverable sender history. The
wallet can first deposit into its own contract, then transfer it. Application
metadata promised to survive must fit a descriptor or be derivable; arbitrary
program imports and local-only notes have no implicit recovery guarantee.

Core client finalizers authorize the transaction after funding, change and nonce
are fixed, before outer signatures and state-machine IDs. Module replacements
cannot change the transaction shape or cross module boundaries, and core checks
that fees remain unchanged. Simplicity reserves inputs together with durable core
submission state, releases reservations on rejection, and synchronizes accepted
transactions into confirmed history. Initial recovery uses the core's unusable
module mode; applications reopen the client after recovery completes.

## Alternatives

Compact module-specific recovery history remains a possible download
optimization. It must retain enough information to reconstruct confirmed
activity as well as current holdings. A live-contract scan alone cannot recover
fully spent activity. Combining it with historical backfill would add scan
consistency and concurrent-operation complexity; it is deferred until recovery
measurements justify it. Neither optimization is required by
[REQ-simplicity-recovery](REQ-simplicity-recovery.md).

# ARCH-simplicity: Experimental Simplicity contracts

The opt-in Simplicity module extends the module topology in
[ARCH-fedimint](ARCH-fedimint.md) with a bitcoin-denominated contract UTXO ledger.
It depends on Fedimint transaction funding and consensus ordering; the mint does
not depend on it. [Prototype usage and limits](../modules/fedimint-simplicity-common/README.md)
belong with the implementation.

Core consensus supplies modules with a read-only view of the actual outer
transaction, the federation identity, module instance, and current session index.
Admission and ordered execution use the same context-aware validation hooks;
replay uses the session being replayed. Existing modules retain their original
validation behavior through default hook implementations. No new core transaction
wire format is introduced.

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
Core history can retain their original transactions. The current module provides
no transfer privacy or mnemonic recovery protocol. Separate assets and private
transfers are not part of the prototype's current responsibilities.

Execution version zero pins its runtime, permitted jets, commitments, and cost
semantics. Future versions must preserve the interpretation of existing outputs;
contract-authorized spending is the migration boundary.

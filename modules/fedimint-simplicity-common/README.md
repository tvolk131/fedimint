# Simplicity contract prototype

This experimental module locks bitcoin balances to real Simplicity programs. The
client compiles SimplicityHL with Fedimint context jets; guardians execute the
resulting bytecode with `rust-simplicity`. It is opt-in and disabled by default.
The [architecture record](../../specs/ARCH-simplicity.md) explains its boundary
with Fedimint consensus and other modules.

## Run the prototype

From the repository root, inside `nix develop`:

```sh
cargo test -p fedimint-simplicity-common -p fedimint-simplicity-server --lib
```

The integration test uses Fedimint's actual transaction processor and Mint v2
blind signatures with an in-memory database. It issues real test notes, deposits
one into a contract, adds a second note to increase the contract's balance,
spends the contract back into notes for the entire balance minus the execution
fee, and spends those notes to verify their signatures. A dummy module provides
only the initial test funding and final accounting sink. This is not a running
multi-guardian network test.

The tests also exercise consensus timelocks, authorization of foreign blinded
outputs, covenant state preservation, funding failures, invalid outer signatures,
duplicate spends, malformed bytecode/witnesses, output limits, and rollback.

To include the guardian module in a daemon build:

```sh
cargo build -p fedimintd --features experimental-simplicity
```

The module still has to be selected explicitly during federation setup. Existing
federations and default builds do not enable it. There is no CLI wallet or
persistent `ClientModule` integration yet.

## Guardian and client API

`fedimint-simplicity-common` owns consensus types, the jet encoding, execution
limits, and the authorization digest. Its optional `compiler` feature adds the
pinned SimplicityHL adapter. `fedimint-simplicity-server` owns the contract UTXO
ledger, consensus block-count votes, validation, and the bitcoin liability audit.
`fedimint-simplicity-client` is a low-level Rust builder.

A `ContractOutput` contains the execution version, bitcoin amount in msats,
program commitment (CMR), 32-byte application state, and bounded recovery bytes.
A `ContractInput` references its outpoint and supplies the redemption program,
witness, and a claim key used by the outer Fedimint transaction signature.
An input consumes one UTXO; an output creates one. A transaction can include many
of both and combine them with other modules' ordinary inputs and outputs.

The client flow is:

1. `ContractProgram::compile(source, arguments(...))` compiles a policy. The
   [example](../fedimint-simplicity-client/contracts/top_up_or_release.simf)
   checks an owner signature and both clocks, then either preserves its CMR and
   state in a successor of at least the current value or releases the balance.
2. `program.output(amount, state, recovery)` creates a funded output request.
   Retain the source/template identity and arguments locally: a CMR alone is not
   a recoverable program.
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

Version 0 allows at most 32 contract inputs and 32 contract outputs for this
module instance, within at most 128 total outputs. Each program and witness is
limited to 8 KiB, each recovery annotation to 1 KiB. Inferred type sizes are
checked before decoding padded witnesses. Execution is capped by static cost,
cell, and frame bounds; the constants are in `runtime::decode_program`.

Spending costs 100 msat plus one msat per rounded static cost weight unit and
per encoded program/witness byte. Creation costs 100 msat plus one msat per
recovery byte. These are experimental fixed coefficients, not a benchmarked
production fee policy. The submitted redemption program's static bound determines
the fee; guardians do not time execution or charge script cost on creation.

Spending removes the live UTXO and recovery annotation. Any state needed by a
successor must be carried forward. Fedimint's existing transaction/session history
may retain all original bytes indefinitely: removing the live record does **not**
erase historical ciphertext. Recovery bytes are opaque public data to this module;
wallets must encrypt them before use. No wallet identifier, scanning API, recovery
encryption scheme, or mnemonic recovery implementation is provided yet.

## Prototype boundary

Only native bitcoin contracts are implemented. Asset issuance/reissuance,
prediction-market application contracts, private transfers, durable wallet state
machines, recovery scanning, and a complete indexed input environment are later
work. This prototype validates the execution and accounting foundation first.

The runtime, compiler revision, core jet allowlist, custom jet identifiers and
CMRs, types, and costs are consensus-critical. Custom environment jets currently
use domain-separated prototype commitments; formal Simplicity specifications and
production cost calibration remain outstanding. Unsupported jets are rejected.
Liquid programs must be ported to this environment. Do not reinterpret existing
v0 outputs when adding versions: migration requires an authorized spend.

This is a development prototype, not an audited module for holding real funds.

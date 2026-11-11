# PTLC settlement example

The optional `ptlc` client feature demonstrates an interactive point-locked
exchange using the existing Simplicity execution version one. Guardians verify
ordinary BIP340 signatures and their agreed Bitcoin block count. No new jets,
consensus rules, server endpoints, or guardian secrets are added.

This is an experimental example, not a complete Lightning implementation. It
does not implement invoices, routing, a gateway driver, offline receiving, or a
persistent-wallet recovery descriptor for PTLCs. The caller must retain the
terms, original template, signing keys and off-chain adaptor transcripts.

## Contract and signing protocol

`ptlc::Ptlc` commits to three distinct keys: the funder's claim and refund keys
and the claimant's signing key, plus a full secp256k1 payment point and an expiry.
Its output state is SHA-256 of the compressed payment point. The agreed amount
and empty asset bundle are checked by `validate_output`.
Applications must also authenticate the output's inclusion and exact outpoint.

The claim branch, before expiry, requires **both** signatures over the module's
inner transaction digest. The refund branch, at or after expiry, requires only
the funder's dedicated refund-key signature. Both branches verify the output's
payment commitment.
The refund's outer claim key can be the funder's own key; it needs no claimant
cooperation. Both paths still need the normal outer transaction signatures.

Separate claim and refund keys are essential: `REFUND` is a witness excluded
from the inner digest. Reusing one funder key for both paths would let a
claimant take a completed pre-expiry claim signature, flip `REFUND` after
expiry, and collect its old payout through the refund path. `Ptlc::program`
rejects duplicate keys, and the integration tests cover substitution in both
directions. Both funder keys should be controlled and retained by the funder.

The point relationship is enforced by the off-chain adaptor exchange, not by
an on-ledger scalar-multiplication check:

1. Agree and authenticate the terms and the funded contract. Assemble the exact
   claim transaction, including outputs, claim key, nonce and fees.
2. Compute `common::signature_hash(federation, module, &transaction)`.
   The funder calls `AdaptorSignature::encrypt` with its key, the payment point
   and this digest. Persist the transcript before handing it to the claimant.
3. The claimant checks its intended outputs and fees and calls `verify` on the
   adaptor. Once it knows the payment scalar, it calls `complete` and signs
   the same digest with its own key.
4. Supply the two signature values through `Ptlc::witnesses(SpendPath::Claim,
   ...)`. Prune the original program with `input_with_environment` against an
   authenticated `PruningSnapshot`, recheck the fee, then sign the outer
   transaction. If outputs or other signed fields change, restart signing.
5. The funder observes the completed signature in the transaction's published
   witnesses and calls `extract` with its retained adaptor transcript. It checks
   the recovered scalar against the exact, full payment point.

`schnorr_fun` implements adaptor signing, verification, completion and extraction;
the helper converts its completed signatures to the existing secp256k1 type.
Its deterministic nonce derivation includes the encryption point and is distinct
from ordinary signing. Do not substitute an improvised nonce scheme or reuse
nonces across signatures. Neither party should supply an unrestricted normal
claim signature in place of its agreed adaptor exchange.

## Sending and interactive receiving

For sending, the user is the funder and the gateway is the claimant. The gateway
learns the scalar by settling an external PTLC, completes its authorized claim,
and the user extracts a payment secret from the completed signature.

For receiving, the gateway is the funder and the recipient is the claimant. The
online recipient knows the scalar and completes the claim. The gateway extracts
the scalar and uses it to settle its incoming external PTLC. The integration
example models that external settlement with a second adaptor signature; it
does not contact a Lightning node. External protocols may additionally require
point-tweak translation and their own expiry/safety rules.

Offline receiving needs another mechanism, such as conditional threshold secret
release. Merely preparing the contract does not make the recipient's later
claim happen while its wallet is offline.

## Deadlines and disclosure

Expiry uses the federation's agreed Bitcoin **block count** (tip height + 1),
not wall time or an external Lightning node's current height. The claim requires
`count < expiry`; the refund requires `count >= expiry`. Admission before expiry
does not reserve inclusion: a clock vote ordered before a claim can invalidate
it in the same session. A refund after a claim has spent the output fails.

**Publishing a completed signature reveals the scalar to anyone holding its
adaptor transcript immediately**, even if the transaction is rejected, delayed,
or loses a competing spend. Extraction is not proof of federation acceptance.
This example is not safe for an exchange
that assumes secrets stay hidden until confirmation. Real applications need
adequate, coordinated timeout margins, inclusion assumptions, and monitoring
on both sides; these tests do not establish a production Lightning safety margin.

After expiry the funder can refund even if the claimant has learned the scalar.
An interactive receiver must complete and secure its claim sufficiently before
that deadline. Repeating external payments or revealing new claims while an
earlier attempt is unresolved needs a separate durable operation protocol.

The two signatures bind payout outputs (including mint blinded nonces), claim
keys, nonce, federation/module identity and the module's consumed outpoints.
Neither party can unilaterally redirect a co-authorized claim. The funder may
choose any refund destination by signing a new refund after expiry.

## Executable examples

From the development environment:

```sh
cargo test -p fedimint-simplicity-client --features ptlc --lib ptlc::
cargo test -p fedimint-simplicity-server --lib tests::ptlc::
```

The server fixtures issue real Mint v2 notes, fund PTLCs, settle into new notes
with exact execution fees, and spend the redeemed notes to verify their blind
signatures. Dummy funding only bootstraps the initial notes and provides the
final accounting sink; no server validation is bypassed. Test-only pruning skips
assertions to prepare fee quotes and invalid fixtures; positive final spends use
normal SDK pruning and the real transaction processor.

Coverage includes adaptor parity and point signs, transcript tampering, wrong
scalars/keys/messages, funded-term validation, both claim signatures, redirected
payouts, unfunded spends, duplicate/competing claims, and admission versus ordered
expiry. The fixtures configure zero Mint v2 fees; they are not a production
fee-calibration or live-network qualification.

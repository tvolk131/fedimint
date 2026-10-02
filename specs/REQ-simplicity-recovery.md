# REQ-simplicity-recovery: Wallet and confirmed activity recovery

## Status

These are the agreed requirements for the persistent Simplicity wallet. The
prototype implements a persistent client wallet using encrypted per-output
descriptors and an ordered federation-history scan. Four-guardian tests discard
the client database and recover holdings, authority ownership, spendability, and
confirmed activity, including a fully drained wallet. The architecture is described in
[ARCH-simplicity](ARCH-simplicity.md).

## Source and purpose

The project owner requires recovery into the same wallet software using only
the mnemonic and the original federation, without a separately maintained file
or external backup service. Recovery must preserve confirmed contract activity,
including interactions whose contracts have all been spent. These are product
requirements; the encoding and retrieval mechanism may vary while preserving
them.

## Recovery contract

After complete loss of its local database, a compatible version of the same
wallet software, the original mnemonic, and access to the original federation
must suffice to reconstruct:

- Current spendable or otherwise interactable contracts supported by that
  wallet, including asset balances and issuance authorities it controls.
- The descriptors, parameters, secrets, and derivation state needed to continue
  using those contracts under their original policies.
- Confirmed wallet interactions with supported Simplicity contracts, including
  transfers, contract transitions, and terminal spends, even when no associated
  live output or Simplicity balance remains.

Every piece of information needed for these results must be derivable from the
mnemonic and wallet software or recoverable from federation records. The wallet
must not require an external file, cloud account, original device, third-party
program repository, or Fedimint's deprecated backup API. Software may embed
versioned contract templates; compatible releases must preserve the ability to
interpret their historical descriptors and reproduce the required programs.
An arbitrary imported program cannot be assumed recoverable from its CMR.

Required wallet-specific metadata must be preserved in the federation as part
of the operation that makes it necessary, rather than relying on a later
snapshot upload. Sensitive metadata must be encrypted for local recovery from
mnemonic-derived secrets without publishing a stable wallet identifier. This
does not make the module's transparent contract and asset transfers private.

Federation records needed for recovery must remain available after contracts
are spent. Deleting a live UTXO and its annotation must not delete the only
recoverable copy of required history. A compact history representation may
omit irrelevant bytes but must preserve the information needed for the recovery
contract above. Recovery must authenticate the records and must not report
completion when required data is missing or unsupported.

## History boundary

Confirmed history means wallet-related interactions accepted by the federation
and the recorded context needed to interpret them. It does not promise recovery
of abandoned drafts, rejected attempts, local-only labels, or exact original UI
state. If a wallet feature promises recovery of additional metadata, it must
also preserve that metadata in the federation or derive it from the permitted
inputs. Recovery restores the ability to use a contract under its policy; it
does not bypass signatures, oracle attestations, or other policy conditions.

## Acceptance conditions

Recovery must be exercised after deleting the complete client database, with
no external backup and without invoking the deprecated backup service. Coverage
must include mixed current and spent contracts, asset transfers and authority
ownership, historical descriptor versions, and a wallet that has spent all its
Simplicity contracts but must recover its confirmed interaction history.
Recovered holdings must exclude spent outputs, and confirmed interactions must
not disappear or duplicate when recovery is interrupted and resumed.

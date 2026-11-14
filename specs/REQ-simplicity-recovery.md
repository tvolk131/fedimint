# REQ-simplicity-recovery: Wallet and confirmed activity recovery

## Source and purpose

The project owner requires recovery into the same wallet software using only
the mnemonic and the original federation, without a separately maintained file
or external backup service. Recovery must preserve confirmed contract activity,
including interactions whose contracts have all been spent. These are product
requirements for the persistent Simplicity wallet; the encoding and retrieval
mechanism may vary while preserving them.
[ARCH-simplicity](ARCH-simplicity.md#wallet-recovery) describes the current
design, and the [module README](../modules/fedimint-simplicity-common/README.md#testing)
maps the acceptance conditions below to tests.

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

Direct sends funded only by another module must restore sender activity without
requiring an intermediate owned contract. A sender receipt must not turn recipient
outputs into sender holdings, and copying its public ciphertext into a different
transaction must not manufacture wallet history. Explicit receipt application
context must survive mnemonic recovery within the bounded annotation size.

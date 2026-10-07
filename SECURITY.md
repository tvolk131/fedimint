# Security Policy

## Reporting a Vulnerability

Do **not** open a public GitHub issue for security bugs.

Send a report to **security@fedimint.org** (this address forwards to the
maintainers listed below) or message **`@elsirion.21`** on Signal.

Please include:

- What the bug is and where it is in the code.
- How to reproduce it, if possible.
- What an attacker can do with it (steal funds, break consensus, leak user
  data, stop the federation, etc.).
- Your name or handle, if you want credit in the fix announcement.

## Encrypted Reports

If the report is sensitive, encrypt it with PGP. Mail sent to
security@fedimint.org goes to both maintainers, so encrypt to **both keys**.

| Maintainer | Email | Key fingerprint |
| --- | --- | --- |
| dpc | `dpc@dpc.pw` | `23B8 147B 42EB 74CB 801F F76F 930E AF17 AB8F F29C` |
| elsirion | `elsirion@protonmail.com` | `B3CD FF6F 6D4B 2BE9 EA8B 0020 B300 5E57 1AA3 14DA` |

Both keys are hosted on the Proton Mail key server. To fetch them:

```sh
gpg --fetch-keys 'https://api.protonmail.ch/pks/lookup?op=get&search=dpc@dpc.pw'
gpg --fetch-keys 'https://api.protonmail.ch/pks/lookup?op=get&search=elsirion@protonmail.com'
```

Check the fingerprints against the table above before you use the keys.

Please keep the bug private until a fix is released and federation operators
had time to upgrade.

## Supported Versions

We only fix security bugs in the latest stable release line. Older releases do
not get patches. Run a current release if you run a federation in production.

## Scope

In scope:

- All code in this repository: `fedimintd`, `fedimint-cli`, the client
  libraries, the modules (mint, wallet, lightning, meta) and the gateway.
- Consensus safety, fund safety, user privacy, and denial of service against a
  federation.

Out of scope:

- Bugs in third-party software we depend on (report them upstream, but tell us
  too if Fedimint is affected).
- Attacks that need a majority of guardians to be malicious. The threat model
  assumes fewer than one third of guardians are faulty.
- Test and development setups, such as `devimint`.


## Public Gateway Federation Status

Configured gateways expose unauthenticated HTTP and Iroh `POST
/federation_status` queries for one exact federation ID. The response contains
only finite, detail-free connectivity, Lightning module capability, and
registration-health classes for that ID. It must not reveal the gateway's
federation inventory, guardian identities, balances, route hints, credentials,
or raw errors; `/info` remains authenticated. A gateway that has not completed
mnemonic setup exposes only its setup endpoints.

Registration observations are process-local and cleared when the gateway leaves
the federation. Concurrent results follow attempt begin order so stale work
cannot overwrite a newer logical attempt, and advertised TTL uses monotonic
elapsed time. Status assembly holds the federation-manager read lock only while
capturing one coherent snapshot; do not clone the client solely for this public
query because that would interfere with concurrent leave.

## Experimental Simplicity Contracts

The `experimental-simplicity` daemon feature adds an opt-in contract module that
is disabled by default. It is an unaudited prototype for development, with no
production fund-safety claim. Guardians execute untrusted redemption bytecode
through a pinned Simplicity runtime and custom C-frame jet adapters. Decoder,
type-expansion, static execution, and transaction limits are part of this trust
boundary; production use requires adversarial review of these limits and the
unsafe adapters, consensus test vectors, and measured fee/cost calibration.

Contract authorization binds the federation, module instance, spending references,
claim keys, nonce, and all outer outputs. Core funding checks and transaction
rollback enforce native bitcoin conservation. Bitcoin timelocks trust the
configured guardians' threshold-agreed backend observations, subject to the
backend trust model above. Session timelocks use core consensus ordering, not
wall time.

Contract values, states, revealed programs/witnesses, and recovery annotations
are public to guardians and retained transaction history. The unauthenticated
point-query API returns current contract records, including recovery bytes.
Wallets must encrypt sensitive annotations; deleting a spent live record cannot
erase its historical ciphertext. The persistent client encrypts versioned
recovery descriptors with mnemonic-derived keys scoped to federation and module.
It authenticates federation session history, verifies recovered policies against
output commitments, and reconstructs confirmed activity including terminal
spends. Recovery requires the original federation's retained history and wallet
software that still supports historical templates. It adds no ecash-like transfer
privacy: values, policies and public witnesses remain visible.

Local wallet databases contain decrypted descriptors, derived-key salts,
application secrets, and confirmed transaction history. Protect the local database
like other wallet material; federation annotation encryption does not encrypt
local storage. The database dump API intentionally omits these wallet records.
Receiving requires a sender to include the receiver's recovery annotation; low-level
builders do not automatically supply it. Repeated annotations or policies can
link outputs, so receive requests should be fresh. See the
[prototype documentation](modules/fedimint-simplicity-common/README.md) for exact
API, retention, and implementation limits.

Direct sends without an owned Simplicity input or output use bounded encrypted
sender receipts in non-spendable action outputs. Receipts identify confirmed
activity, not ownership. Their separate mnemonic-derived key and transaction
commitment bind funding inputs, nonce and outputs; copies on unrelated intents
are ignored. Receipt ciphertext and creation signatures are normalized across
instances to avoid circularity. Client finalization checks the commitment again
after authorization. Guardians interpret none of the receipt plaintext and
retain only the ordinary transaction history, with no receipt UTXO or index.


Execution version one adds public assets with guardian-enforced conservation and
unique issuance capabilities. Creation starts at zero supply; first issuance must
execute the authority contract. Fresh client creation keys authenticate immutable
asset origins but have no continuing issuance power. Namespace-use markers and
origin records are retained permanently to prevent resurrection after destruction.
The v1 intent excludes creation signatures across Simplicity instances to avoid
circularity, while committing
the creation parameters and all issuance/destruction operations. Contract programs
execute against one pre-mutation snapshot; final outer authorization and core
funding checks still gate database commitment.

The `asset` point-query endpoint exposes immutable origin records without
credentials; it adds no listing or wallet identifier. As with contract queries,
clients need normal federation consensus queries rather than trusting one server.
The binary-market SDK verifies both assets originated in the expected unresolved
vault; current-vault inspection alone cannot establish backing. Its oracle fixes
the market outcome, while position-owner programs authorize payout destinations.
Collateral operations share one vault and serialize; ordinary position transfers
remain public, independent UTXO spends. Oracle honesty, client descriptor retention,
and safe application covenant construction remain explicit trust boundaries.

Shared-contract retry handlers are trusted wallet software. They preserve an
immutable versioned request and may rebuild only after a definitive rejection
and authenticated evidence of a competing spend of a designated shared input.
Network uncertainty never authorizes another attempt. Submission, funding,
reservations and attempt identity persist atomically; cancellation still resolves
in-flight transactions. Attempt limits, a final funded per-attempt fee cap, and
optional preparation deadlines bound automation. New attempts require opt-in
primary funding reservations: owned notes return locally only after authenticated
permanent invalidity and definitive rejection of their bound transaction. The
originating wallet module is trusted to establish that proof; the mint client
checks the reservation's transaction and outcome, not Simplicity semantics.
Timeouts and cancellation cannot release pending notes. Unproven rejections retain
funding without an automatic paid reclaim. Previously persisted ordinary funding
operations keep their original module-dependent refund behavior. Local intent payloads may contain sensitive recipient metadata
and are omitted from database dumps. Mnemonic recovery must not restart abandoned
or unfinished intentions.

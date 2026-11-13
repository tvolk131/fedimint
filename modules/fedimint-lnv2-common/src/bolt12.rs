//! Experimental federated BOLT12 offline receives.
//!
//! See `docs/federated_bolt12.md`. Consensus pins opaque invoice terms by hash
//! and never parses BOLT12 messages; guardians validate them when signing.

use std::collections::BTreeMap;

use bitcoin::hashes::{Hash, sha256};
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::{Keypair, Message, PublicKey, SECP256K1};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{Amount, OutPoint, PeerId};
use serde::{Deserialize, Serialize};
use tpe::{
    AggregateDecryptionKey, AggregatePublicKey, CipherText, DecryptionKeyShare, PublicKeyShare,
    decrypt_preimage, encrypt_preimage, verify_agg_dk, verify_ciphertext, verify_dk_share,
};

use crate::config::FeeConsensus;
use crate::gateway_api::PaymentFee;

/// Seconds of consensus time a signed invoice, and its reservation, stay valid.
pub const INVOICE_LIFETIME: u64 = 600;
/// Live registrations the federation keeps at once.
pub const MAX_REGISTRATIONS: u64 = 10_000;
/// A registration may not expire further ahead than this.
pub const MAX_REGISTRATION_LIFETIME: u64 = 366 * 24 * 60 * 60;
/// Stock items ever uploaded for one registration.
pub const MAX_STOCK: u64 = 1024;
/// Stock items in one upload.
pub const MAX_STOCK_BATCH: usize = 64;
/// Unpaid, unexpired reservations per registration.
pub const MAX_PENDING_PER_OFFER: usize = 8;
/// Unpaid, unexpired reservations per gateway.
pub const MAX_PENDING_PER_GATEWAY: usize = 64;
/// Expired registrations deleted while processing one new registration.
pub const REGISTRATIONS_PRUNED_PER_REGISTER: usize = 4;

#[derive(
    Debug,
    Clone,
    Copy,
    Eq,
    PartialEq,
    Hash,
    Ord,
    PartialOrd,
    Serialize,
    Deserialize,
    Encodable,
    Decodable,
)]
pub struct RegistrationId(pub sha256::Hash);

#[derive(
    Debug,
    Clone,
    Copy,
    Eq,
    PartialEq,
    Hash,
    Ord,
    PartialOrd,
    Serialize,
    Deserialize,
    Encodable,
    Decodable,
)]
pub struct ReservationId(pub sha256::Hash);

/// What the recipient commits to when registering an offer.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct ReceivePolicy {
    /// Random routing handle embedded in the offer's metadata.
    pub handle: [u8; 32],
    /// Key that may claim receives for this offer. Unique per offer.
    pub claim_pk: PublicKey,
    /// Hash of the exact offer TLV bytes. Offers are unsigned, so guardians
    /// compare this against the offer fields echoed in each invoice request.
    pub offer_hash: sha256::Hash,
    /// Upper bound on what a gateway may keep from one payment.
    pub max_gateway_fee: PaymentFee,
    /// Consensus unix time after which no new invoices are issued.
    pub expires_at: u64,
    /// Whether invoices may fall back to federation-generated preimages once
    /// the recipient's stock is exhausted. Reserved; no pool exists yet.
    pub allow_pool: bool,
}

impl ReceivePolicy {
    pub fn id(&self) -> RegistrationId {
        RegistrationId(("fedimint/bolt12/registration/v1", self).consensus_hash())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct Registration {
    pub policy: ReceivePolicy,
    /// Stock items ever uploaded; also the index of the next upload.
    pub stock_len: u64,
    /// Stock items not yet consumed by a reservation.
    pub stock_unused: u64,
    /// Set once a stock item decrypted to something other than its preimage.
    pub voided: bool,
}

/// A recipient-supplied single-use payment hash with its preimage encrypted to
/// the federation.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct StockItem {
    pub payment_hash: [u8; 32],
    pub ciphertext: CipherText,
}

impl StockItem {
    pub fn new(
        agg_pk: &AggregatePublicKey,
        registration: RegistrationId,
        index: u64,
        preimage: &[u8; 32],
        encryption_seed: &[u8; 32],
    ) -> Self {
        let payment_hash = sha256::Hash::hash(preimage).to_byte_array();
        let binding = Source::Stock { index }.binding(registration, payment_hash);
        Self {
            payment_hash,
            ciphertext: encrypt_preimage(agg_pk, encryption_seed, preimage, &binding),
        }
    }

    pub fn verify(&self, registration: RegistrationId, index: u64) -> bool {
        let binding = Source::Stock { index }.binding(registration, self.payment_hash);
        verify_ciphertext(&self.ciphertext, &binding)
    }
}

/// Where a reservation's payment hash and encrypted preimage come from.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum Source {
    Stock { index: u64 },
}

impl Source {
    /// The commitment a preimage ciphertext is bound to.
    pub fn binding(self, registration: RegistrationId, payment_hash: [u8; 32]) -> sha256::Hash {
        match self {
            Source::Stock { index } => (
                "fedimint/bolt12/stock/v1",
                registration,
                index,
                payment_hash,
            )
                .consensus_hash(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct Reservation {
    pub registration: RegistrationId,
    pub source: Source,
    pub payment_hash: [u8; 32],
    pub ciphertext: CipherText,
    pub claim_pk: PublicKey,
    pub gateway: PublicKey,
    /// The invoice amount the payer will be asked for.
    pub amount: Amount,
    pub gateway_fee: Amount,
    /// Hash of the invoice request and payment path the invoice is built from.
    pub terms: sha256::Hash,
    pub created_at: u64,
}

impl Reservation {
    /// A source is single use, so it identifies its reservation.
    pub fn id(registration: RegistrationId, source: Source) -> ReservationId {
        ReservationId(("fedimint/bolt12/reservation/v1", registration, source).consensus_hash())
    }

    pub fn expires_at(&self) -> u64 {
        self.created_at.saturating_add(INVOICE_LIFETIME)
    }

    /// What the gateway funds and the recipient can claim.
    pub fn net_amount(&self) -> Amount {
        self.amount.saturating_sub(self.gateway_fee)
    }
}

/// Hash pinning the opaque BOLT12 bytes an invoice is built from.
pub fn terms_hash(invoice_request: &[u8], payment_path: &[u8]) -> sha256::Hash {
    (
        "fedimint/bolt12/terms/v1",
        invoice_request.to_vec(),
        payment_path.to_vec(),
    )
        .consensus_hash()
}

/// An entry in a bounded list of unpaid reservations.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct Pending {
    pub expires_at: u64,
    pub reservation: ReservationId,
}

/// A funded receive: claimable by the recipient if the encrypted preimage is
/// correct, refundable to the gateway if it is not.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct ReceiveContract {
    pub reservation: ReservationId,
    pub registration: RegistrationId,
    pub source: Source,
    pub payment_hash: [u8; 32],
    pub ciphertext: CipherText,
    /// Invoice amount minus the gateway fee.
    pub amount: Amount,
    pub gateway_fee: Amount,
    pub claim_pk: PublicKey,
    pub refund_pk: PublicKey,
}

impl ReceiveContract {
    pub fn binding(&self) -> sha256::Hash {
        self.source.binding(self.registration, self.payment_hash)
    }

    pub fn verify_decryption_share(&self, pk: &PublicKeyShare, share: &DecryptionKeyShare) -> bool {
        verify_dk_share(pk, share, &self.ciphertext, &self.binding())
    }

    pub fn verify_agg_decryption_key(
        &self,
        agg_pk: &AggregatePublicKey,
        key: &AggregateDecryptionKey,
    ) -> bool {
        verify_agg_dk(agg_pk, key, &self.ciphertext, &self.binding())
    }

    /// The Lightning preimage, or `None` if the recipient uploaded a
    /// ciphertext that does not contain it.
    pub fn decrypt_preimage(&self, key: &AggregateDecryptionKey) -> Option<[u8; 32]> {
        let preimage = decrypt_preimage(&self.ciphertext, key);
        (sha256::Hash::hash(&preimage).to_byte_array() == self.payment_hash).then_some(preimage)
    }
}

fn verify(message: Message, signature: &Signature, key: &PublicKey) -> bool {
    SECP256K1
        .verify_schnorr(signature, &message, &key.x_only_public_key().0)
        .is_ok()
}

fn message(hash: sha256::Hash) -> Message {
    Message::from_digest(hash.to_byte_array())
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct Register {
    pub policy: ReceivePolicy,
    pub signature: Signature,
}

impl Register {
    fn message(policy: &ReceivePolicy) -> Message {
        message(("fedimint/bolt12/register/v1", policy).consensus_hash())
    }

    pub fn new(policy: ReceivePolicy, claim_key: &Keypair) -> Self {
        let signature = claim_key.sign_schnorr(Self::message(&policy));
        Self { policy, signature }
    }

    pub fn verify(&self) -> bool {
        verify(
            Self::message(&self.policy),
            &self.signature,
            &self.policy.claim_pk,
        )
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct AddStock {
    pub registration: RegistrationId,
    /// Index of the first item; must equal the registration's `stock_len`.
    pub start: u64,
    pub items: Vec<StockItem>,
    pub signature: Signature,
}

impl AddStock {
    fn message(registration: RegistrationId, start: u64, items: &Vec<StockItem>) -> Message {
        message(("fedimint/bolt12/add-stock/v1", registration, start, items).consensus_hash())
    }

    pub fn new(
        registration: RegistrationId,
        start: u64,
        items: Vec<StockItem>,
        claim_key: &Keypair,
    ) -> Self {
        let signature = claim_key.sign_schnorr(Self::message(registration, start, &items));
        Self {
            registration,
            start,
            items,
            signature,
        }
    }

    pub fn verify(&self, claim_pk: &PublicKey) -> bool {
        verify(
            Self::message(self.registration, self.start, &self.items),
            &self.signature,
            claim_pk,
        )
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct Reserve {
    pub registration: RegistrationId,
    pub source: Source,
    pub gateway: PublicKey,
    pub amount: Amount,
    pub gateway_fee: Amount,
    pub terms: sha256::Hash,
    pub signature: Signature,
}

impl Reserve {
    fn message(
        registration: RegistrationId,
        source: Source,
        amount: Amount,
        gateway_fee: Amount,
        terms: sha256::Hash,
    ) -> Message {
        message(
            (
                "fedimint/bolt12/reserve/v1",
                registration,
                source,
                amount,
                gateway_fee,
                terms,
            )
                .consensus_hash(),
        )
    }

    pub fn new(
        registration: RegistrationId,
        source: Source,
        amount: Amount,
        gateway_fee: Amount,
        terms: sha256::Hash,
        gateway_key: &Keypair,
    ) -> Self {
        let signature = gateway_key.sign_schnorr(Self::message(
            registration,
            source,
            amount,
            gateway_fee,
            terms,
        ));
        Self {
            registration,
            source,
            gateway: gateway_key.public_key(),
            amount,
            gateway_fee,
            terms,
            signature,
        }
    }

    pub fn verify(&self) -> bool {
        verify(
            Self::message(
                self.registration,
                self.source,
                self.amount,
                self.gateway_fee,
                self.terms,
            ),
            &self.signature,
            &self.gateway,
        )
    }

    pub fn reservation_id(&self) -> ReservationId {
        Reservation::id(self.registration, self.source)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum Bolt12Output {
    Register(Register),
    AddStock(AddStock),
    Reserve(Reserve),
    /// Fund the receive for a reservation with its net amount.
    Receive(ReservationId),
}

/// Fees and keys of the experimental BOLT12 receive path.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct Bolt12Config {
    /// Serialized FROST public key package of the invoice signing key.
    pub public_package: Vec<u8>,
    /// Guardian identities for private guardian-to-guardian channels.
    pub transport_keys: BTreeMap<PeerId, PublicKey>,
    pub registration_fee: Amount,
    pub stock_item_fee: Amount,
    /// Charged on top of the ordinary fee when a receive is funded.
    pub receive_fee: Amount,
}

impl Bolt12Config {
    pub const DEFAULT_REGISTRATION_FEE: Amount = Amount::from_sats(100);
    pub const DEFAULT_STOCK_ITEM_FEE: Amount = Amount::from_sats(1);
    pub const DEFAULT_RECEIVE_FEE: Amount = Amount::ZERO;
}

/// The amount an output moves and the fee it costs. `None` if the output
/// cannot be priced, which callers treat as invalid.
///
/// Reservations are free: the gateway has not been paid yet, and the
/// federation bounds them with pending limits instead of prices.
pub fn output_amount_and_fee(
    fees: &FeeConsensus,
    config: &Bolt12Config,
    output: &Bolt12Output,
    receive_amount: Amount,
) -> Option<(Amount, Amount)> {
    match output {
        Bolt12Output::Register(..) => Some((Amount::ZERO, config.registration_fee)),
        Bolt12Output::AddStock(add) => Some((
            Amount::ZERO,
            Amount::from_msats(
                config
                    .stock_item_fee
                    .msats
                    .checked_mul(u64::try_from(add.items.len()).ok()?)?,
            ),
        )),
        Bolt12Output::Reserve(..) => Some((Amount::ZERO, Amount::ZERO)),
        Bolt12Output::Receive(..) => Some((
            receive_amount,
            fees.fee(receive_amount).checked_add(config.receive_fee)?,
        )),
    }
}

/// Whether a reservation leaves the recipient with something to claim: the
/// gateway fee is within policy and the net amount exceeds the fee the
/// recipient pays to claim it.
pub fn reservation_is_economical(
    fees: &FeeConsensus,
    policy: &ReceivePolicy,
    amount: Amount,
    gateway_fee: Amount,
) -> bool {
    if gateway_fee >= amount || gateway_fee > policy.max_gateway_fee.fee(amount.msats) {
        return false;
    }
    let net = amount.saturating_sub(gateway_fee);
    net > fees.fee(net)
}

/// Guardians needed to sign an invoice or release a preimage.
pub fn quorum(guardians: usize) -> usize {
    guardians - guardians.saturating_sub(1) / 3
}

/// A receive as listed in the public discovery stream.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct StreamedReceive {
    pub outpoint: OutPoint,
    pub contract: ReceiveContract,
}

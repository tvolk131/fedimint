//! Experimental federated BOLT12 offline receives.
//!
//! See `docs/federated_bolt12.md`. Consensus pins opaque invoice terms by hash
//! and never parses BOLT12 messages; guardians validate them when signing.

pub mod invoice;

use std::collections::BTreeMap;

use bitcoin::hashes::{Hash, sha256};
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::{Keypair, Message, PublicKey, SECP256K1};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{Amount, OutPoint, PeerId};
use serde::{Deserialize, Serialize};
use tpe::{
    AggregateDecryptionKey, AggregatePublicKey, CipherText, DecryptionKeyShare, PublicKeyShare,
    decrypt_preimage, encrypt_preimage, verify_agg_dk, verify_dk_share,
    verify_non_identity_ciphertext,
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
/// Unpaid, unexpired reservations backed by the pool, across all offers.
pub const MAX_PENDING_POOL: usize = 32;
/// Unpaid, unexpired reservations backed by the pool for a single offer.
pub const MAX_PENDING_POOL_PER_OFFER: usize = 4;
/// The most generated preimages the federation keeps ready.
pub const MAX_POOL_TARGET: u64 = 256;
/// The most preimages one generation run may produce, keeping individual MPC
/// round messages and Page-0 fault evidence strictly within transport RPC caps.
pub const MAX_POOL_BATCH: u64 = 32;
/// Largest MPC fault tolerance (`f = (N - 1) / 3`) supported for pool runs.
/// `f <= 7` (`N <= 24`, committee `2f + 1 <= 15`) bounds worst-case refund
/// subset search to `C(15, 8) = 6,435 <= mpc::direct::MAX_SUBSET_TRIALS`.
pub const MAX_POOL_DEGREE: usize = 7;
/// Seconds of consensus time a generation run may take before it is
/// abandoned.
pub const POOL_RUN_TIMEOUT: u64 = 300;
/// Seconds of consensus time after a run is abandoned in which its members
/// commit to their evidence.
pub const EVIDENCE_WINDOW: u64 = 90;
/// Seconds of consensus time after a run is abandoned after which it is no
/// longer judged.
pub const JUDGE_TIMEOUT: u64 = 600;
/// Runs a guardian or a disputed pair sits out after a first offence. Each
/// repeat doubles it, up to `MAX_BLAME_RUNS`.
pub const BLAME_RUNS: u64 = 8;
pub const MAX_BLAME_RUNS: u64 = 64;
/// Consecutive completed runs a blamed guardian (or disputed pair) must finish
/// cleanly to decay one offence level.
pub const BLAME_DECAY_RUNS: u32 = 16;
/// Consecutive runs a proven-good committee is reused before rotating.
pub const STICKY_COMMITTEE_RUNS: u64 = 32;

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
    /// the recipient's stock is exhausted. Such receives cost `pool_fee` more
    /// to claim.
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
        let binding = Source::stock_binding(registration, index, payment_hash);
        Self {
            payment_hash,
            ciphertext: encrypt_preimage(agg_pk, encryption_seed, preimage, &binding),
        }
    }

    pub fn verify(&self, registration: RegistrationId, index: u64) -> bool {
        let binding = Source::stock_binding(registration, index, self.payment_hash);
        verify_non_identity_ciphertext(&self.ciphertext, &binding)
    }
}

/// Where a reservation's payment hash and encrypted preimage come from.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum Source {
    /// The registration's own stock item at `index`.
    Stock { index: u64 },
    /// The federation's generated preimage at `index` in the pool.
    Pool { index: u64 },
}

impl Source {
    /// The commitment a stock ciphertext is bound to.
    pub fn stock_binding(
        registration: RegistrationId,
        index: u64,
        payment_hash: [u8; 32],
    ) -> sha256::Hash {
        (
            "fedimint/bolt12/stock/v1",
            registration,
            index,
            payment_hash,
        )
            .consensus_hash()
    }

    pub fn is_pool(self) -> bool {
        matches!(self, Source::Pool { .. })
    }
}

/// The commitment the encrypted share a committee member holds at `position`
/// of a generated preimage is bound to.
pub fn pool_share_binding(run: u64, position: u16, payment_hash: [u8; 32]) -> sha256::Hash {
    ("fedimint/bolt12/pool-share/v1", run, position, payment_hash).consensus_hash()
}

/// A preimage encrypted to the federation until its receive is funded.
// Stored and encoded, rarely moved; boxing the ciphertext buys nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum Sealed {
    /// The recipient's own preimage.
    Preimage(CipherText),
    /// Shares of a preimage a committee of guardians generated in generation
    /// run `run`; any `threshold` correct shares recover it.
    Shares {
        run: u64,
        threshold: u16,
        shares: Vec<SealedShare>,
    },
}

/// One committee member's share, encrypted to the federation. `position` is
/// the member's index in the run's committee and `peer` is its guardian ID so
/// consensus can blame peers that sealed invalid shares.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct SealedShare {
    pub position: u16,
    pub peer: PeerId,
    pub ciphertext: CipherText,
}

/// The aggregate decryption keys that spend a funded receive, one per
/// ciphertext of its contract. The variant must match the contract's source;
/// it is explicit so the input's fee is known without the contract.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum Bolt12Unlock {
    Stock(AggregateDecryptionKey),
    Pool {
        keys: Vec<AggregateDecryptionKey>,
        /// Optional `threshold`-sized witness of committee `position`s that
        /// reconstruct the preimage in `O(t^2)` time without subset search.
        subset: Option<Vec<u16>>,
    },
}

impl Bolt12Unlock {
    pub fn new(source: Source, keys: Vec<AggregateDecryptionKey>) -> Option<Self> {
        match source {
            Source::Stock { .. } => match keys.as_slice() {
                [key] => Some(Self::Stock(*key)),
                _ => None,
            },
            Source::Pool { .. } => Some(Self::Pool { keys, subset: None }),
        }
    }

    pub fn new_pool(keys: Vec<AggregateDecryptionKey>, subset: Option<Vec<u16>>) -> Self {
        Self::Pool { keys, subset }
    }

    pub fn keys(&self) -> &[AggregateDecryptionKey] {
        match self {
            Self::Stock(key) => std::slice::from_ref(key),
            Self::Pool { keys, .. } => keys,
        }
    }

    pub fn subset(&self) -> Option<&[u16]> {
        match self {
            Self::Stock(..) => None,
            Self::Pool { subset, .. } => subset.as_deref(),
        }
    }

    pub fn is_pool(&self) -> bool {
        matches!(self, Self::Pool { .. })
    }
}

/// A generated preimage waiting in the pool.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct PoolItem {
    pub payment_hash: [u8; 32],
    pub sealed: Sealed,
}

/// A committee member's share of one generated preimage, encrypted to the
/// federation, as submitted after a successful run.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct PoolShare {
    pub payment_hash: [u8; 32],
    pub ciphertext: CipherText,
}

/// A generation run that was abandoned and is being judged.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct AbandonedRun {
    pub run: PoolRun,
    pub abandoned_at: u64,
    /// Members that submitted shares before the run was abandoned.
    pub submitted: Vec<PeerId>,
    /// Each member's commitment to its evidence.
    pub evidence: BTreeMap<PeerId, sha256::Hash>,
}

impl AbandonedRun {
    /// Whether every committee member has already committed to its evidence.
    pub fn all_evidence_committed(&self) -> bool {
        self.evidence.len() >= self.run.committee.len()
    }

    /// Whether members may still commit to evidence at `now`.
    pub fn collecting_evidence(&self, now: u64) -> bool {
        !self.all_evidence_committed() && now < self.abandoned_at.saturating_add(EVIDENCE_WINDOW)
    }

    /// Whether the run may no longer be judged at `now`.
    pub fn is_stale(&self, now: u64) -> bool {
        now >= self.abandoned_at.saturating_add(JUDGE_TIMEOUT)
    }
}

/// A guardian's finding about an abandoned run.
#[derive(
    Debug, Clone, Default, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable,
)]
pub struct PoolVerdict {
    /// Members to keep off committees.
    pub culprits: Vec<PeerId>,
    /// Pairs, lower first, that should not share a committee.
    pub disputes: Vec<(PeerId, PeerId)>,
}

/// How long a guardian, or a pair of guardians, is kept off committees.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct Blame {
    /// Accumulated offence level (decays only after `BLAME_DECAY_RUNS` clean
    /// runs per level).
    pub offences: u32,
    /// The first run the blame no longer applies to.
    pub until_run: u64,
    /// Clean runs completed since the last offence or decay step.
    pub clean_runs: u32,
}

impl Blame {
    /// The blame after another offence found while starting run `next_run`.
    pub fn repeat(previous: Option<&Blame>, next_run: u64) -> Self {
        let offences = previous.map_or(1, |blame| blame.offences.saturating_add(1));
        let runs = BLAME_RUNS
            .checked_shl(offences - 1)
            .unwrap_or(MAX_BLAME_RUNS)
            .min(MAX_BLAME_RUNS);

        Self {
            offences,
            until_run: next_run.saturating_add(runs),
            clean_runs: 0,
        }
    }

    /// Record one completed clean run. Decays `offences` by one every
    /// `BLAME_DECAY_RUNS` clean runs, returning `None` once cleared.
    pub fn record_clean_run(&self) -> Option<Self> {
        let clean_runs = self.clean_runs.saturating_add(1);

        if clean_runs >= BLAME_DECAY_RUNS {
            let offences = self.offences.saturating_sub(1);
            (offences > 0).then_some(Self {
                offences,
                until_run: self.until_run,
                clean_runs: 0,
            })
        } else {
            Some(Self {
                offences: self.offences,
                until_run: self.until_run,
                clean_runs,
            })
        }
    }

    pub fn applies_to(&self, run: u64) -> bool {
        run < self.until_run
    }
}

/// A proven-good committee reused across consecutive runs to avoid dragging
/// blamed or sleeper peers back in on every run.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct StickyCommittee {
    pub committee: Vec<PeerId>,
    /// Remaining consecutive runs to reuse this committee before rotating.
    pub remaining: u64,
}

/// A generation run the federation has started.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct PoolRun {
    pub run: u64,
    /// Members in position order.
    pub committee: Vec<PeerId>,
    /// Preimages the run generates.
    pub batch: u64,
    pub started_at: u64,
}

impl PoolRun {
    /// The run's MPC degree: the most malicious guardians a federation of
    /// `guardians` tolerates.
    pub fn degree(guardians: usize) -> usize {
        guardians.saturating_sub(1) / 3
    }

    /// Committee size for a federation of `guardians`.
    pub fn committee_size(guardians: usize) -> usize {
        2 * Self::degree(guardians) + 1
    }

    /// Correct shares needed to recover a preimage.
    pub fn threshold(&self) -> usize {
        self.committee.len() / 2 + 1
    }

    pub fn position(&self, peer: PeerId) -> Option<u16> {
        self.committee
            .iter()
            .position(|member| *member == peer)
            .and_then(|position| u16::try_from(position).ok())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct Reservation {
    pub registration: RegistrationId,
    pub source: Source,
    pub payment_hash: [u8; 32],
    pub sealed: Sealed,
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

    /// The contract funding this reservation creates. Known before funding,
    /// so the gateway can verify decryption shares against it.
    pub fn contract(&self) -> ReceiveContract {
        ReceiveContract {
            reservation: Self::id(self.registration, self.source),
            registration: self.registration,
            source: self.source,
            payment_hash: self.payment_hash,
            sealed: self.sealed.clone(),
            amount: self.net_amount(),
            gateway_fee: self.gateway_fee,
            claim_pk: self.claim_pk,
            refund_pk: self.gateway,
        }
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
    pub sealed: Sealed,
    /// Invoice amount minus the gateway fee.
    pub amount: Amount,
    pub gateway_fee: Amount,
    pub claim_pk: PublicKey,
    pub refund_pk: PublicKey,
}

/// Result of releasing a receive contract's preimage.
pub struct ReleasedPreimage {
    pub preimage: [u8; 32],
    /// Committee members whose sealed share did not lie on the recovered
    /// polynomial (empty for stock contracts).
    pub rejected_peers: Vec<PeerId>,
    /// A `threshold`-sized subset of valid committee positions that witnesses
    /// the preimage in `O(t^2)` time (empty for stock contracts).
    pub valid_subset: Vec<u16>,
}

impl std::fmt::Debug for ReleasedPreimage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReleasedPreimage")
            .field("rejected_peers", &self.rejected_peers)
            .field("valid_subset", &self.valid_subset)
            .finish_non_exhaustive()
    }
}

impl ReceiveContract {
    /// Every ciphertext guardians release a decryption share for once the
    /// receive is funded, with the commitment it is bound to.
    pub fn ciphertexts(&self) -> Vec<(CipherText, sha256::Hash)> {
        match (&self.sealed, self.source) {
            (Sealed::Preimage(ciphertext), Source::Stock { index }) => vec![(
                *ciphertext,
                Source::stock_binding(self.registration, index, self.payment_hash),
            )],
            (Sealed::Shares { run, shares, .. }, Source::Pool { .. }) => shares
                .iter()
                .map(|share| {
                    (
                        share.ciphertext,
                        pool_share_binding(*run, share.position, self.payment_hash),
                    )
                })
                .collect(),
            // Consensus never pairs a source with the other kind of sealing.
            _ => vec![],
        }
    }

    /// Whether `shares` holds one valid decryption share per ciphertext.
    pub fn verify_decryption_shares(
        &self,
        pk: &PublicKeyShare,
        shares: &[DecryptionKeyShare],
    ) -> bool {
        let ciphertexts = self.ciphertexts();

        !ciphertexts.is_empty()
            && ciphertexts.len() == shares.len()
            && ciphertexts
                .iter()
                .zip(shares)
                .all(|((ciphertext, binding), share)| {
                    !bool::from(ciphertext.pk.0.is_identity())
                        && !bool::from(ciphertext.signature.0.is_identity())
                        && verify_dk_share(pk, share, ciphertext, binding)
                })
    }

    /// Whether `keys` holds one valid aggregate key per ciphertext.
    pub fn verify_agg_decryption_keys(
        &self,
        agg_pk: &AggregatePublicKey,
        keys: &[AggregateDecryptionKey],
    ) -> bool {
        let ciphertexts = self.ciphertexts();

        !ciphertexts.is_empty()
            && ciphertexts.len() == keys.len()
            && ciphertexts
                .iter()
                .zip(keys)
                .all(|((ciphertext, binding), key)| {
                    !bool::from(ciphertext.pk.0.is_identity())
                        && !bool::from(ciphertext.signature.0.is_identity())
                        && verify_agg_dk(agg_pk, key, ciphertext, binding)
                })
    }

    /// Release the Lightning preimage along with any committee peers whose
    /// sealed shares were invalid and a valid `threshold`-sized witness subset.
    ///
    /// When `subset` is `Some`, only that subset is interpolated (`O(t^2)`),
    /// returning `None` if the witness is invalid rather than falling back to
    /// subset search. `keys` must have passed
    /// [`Self::verify_agg_decryption_keys`].
    pub fn release_detailed(
        &self,
        keys: &[AggregateDecryptionKey],
        subset: Option<&[u16]>,
    ) -> Option<ReleasedPreimage> {
        match &self.sealed {
            Sealed::Preimage(ciphertext) => {
                if subset.is_some() {
                    return None;
                }
                let preimage = decrypt_preimage(ciphertext, keys.first()?);

                (sha256::Hash::hash(&preimage).to_byte_array() == self.payment_hash).then_some(
                    ReleasedPreimage {
                        preimage,
                        rejected_peers: vec![],
                        valid_subset: vec![],
                    },
                )
            }
            Sealed::Shares {
                threshold, shares, ..
            } => {
                let decrypted: Vec<_> = shares
                    .iter()
                    .zip(keys)
                    .map(|(share, key)| {
                        mpc::direct::Share::new(
                            usize::from(share.position),
                            decrypt_preimage(&share.ciphertext, key),
                        )
                    })
                    .collect();

                let recovered = if let Some(witness) = subset {
                    let witness_usize: Vec<usize> =
                        witness.iter().map(|&p| usize::from(p)).collect();
                    mpc::direct::reconstruct_with_subset(
                        &self.payment_hash,
                        usize::from(*threshold),
                        &decrypted,
                        &witness_usize,
                    )
                    .ok()?
                } else {
                    mpc::direct::reconstruct(
                        &self.payment_hash,
                        usize::from(*threshold),
                        &decrypted,
                    )
                    .ok()?
                };

                let rejected_peers = shares
                    .iter()
                    .filter(|s| recovered.rejected.contains(&usize::from(s.position)))
                    .map(|s| s.peer)
                    .collect();
                let valid_subset = shares
                    .iter()
                    .filter(|s| !recovered.rejected.contains(&usize::from(s.position)))
                    .take(usize::from(*threshold))
                    .map(|s| s.position)
                    .collect();

                Some(ReleasedPreimage {
                    preimage: recovered.preimage,
                    rejected_peers,
                    valid_subset,
                })
            }
        }
    }

    /// The Lightning preimage, or `None` if the decrypted values do not yield
    /// it: the recipient uploaded a wrong stock ciphertext, or too few
    /// committee members sealed correct shares. `keys` must have passed
    /// [`Self::verify_agg_decryption_keys`].
    pub fn release(&self, keys: &[AggregateDecryptionKey]) -> Option<[u8; 32]> {
        self.release_detailed(keys, None)
            .map(|released| released.preimage)
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
    /// The key offers are issued under and invoices are signed with.
    pub signing_key: PublicKey,
    /// Serialized FROST public key package behind `signing_key`.
    pub public_package: Vec<u8>,
    /// Guardian identities for private guardian-to-guardian channels.
    pub transport_keys: BTreeMap<PeerId, PublicKey>,
    pub registration_fee: Amount,
    pub stock_item_fee: Amount,
    /// Charged on top of the ordinary fee when a receive is funded.
    pub receive_fee: Amount,
    /// Charged on top of the ordinary fee when the recipient claims a receive
    /// backed by a generated preimage.
    pub pool_fee: Amount,
    /// Generated preimages to keep ready; zero disables generation.
    pub pool_target: u64,
    /// Preimages one generation run produces.
    pub pool_batch: u64,
}

impl Bolt12Config {
    pub const DEFAULT_REGISTRATION_FEE: Amount = Amount::from_sats(100);
    pub const DEFAULT_STOCK_ITEM_FEE: Amount = Amount::from_sats(1);
    pub const DEFAULT_RECEIVE_FEE: Amount = Amount::ZERO;
    pub const DEFAULT_POOL_FEE: Amount = Amount::from_sats(20);
    pub const DEFAULT_POOL_TARGET: u64 = 32;
    pub const DEFAULT_POOL_BATCH: u64 = 8;

    /// The extra fee spending a receive from `source` costs. Charged on the
    /// refund too, which only happens if guardians sealed bad shares.
    pub fn claim_premium(&self, source: Source) -> Amount {
        if source.is_pool() {
            self.pool_fee
        } else {
            Amount::ZERO
        }
    }

    /// The extra fee an input spending a receive with `unlock` costs.
    pub fn unlock_premium(&self, unlock: &Bolt12Unlock) -> Amount {
        if unlock.is_pool() {
            self.pool_fee
        } else {
            Amount::ZERO
        }
    }
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
    claim_premium: Amount,
) -> bool {
    if gateway_fee >= amount || gateway_fee > policy.max_gateway_fee.fee(amount.msats) {
        return false;
    }
    let net = amount.saturating_sub(gateway_fee);
    fees.fee(net)
        .checked_add(claim_premium)
        .is_some_and(|cost| net > cost)
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

/// Round one of invoice signing: ask a guardian to validate the terms of a
/// reservation and commit to a fresh nonce.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceRequest {
    pub reservation: ReservationId,
    /// Chosen by the gateway; a retry after a failed attempt uses a new one.
    pub attempt: [u8; 32],
    pub invoice_request: Vec<u8>,
    pub payment_path: Vec<u8>,
    pub signature: Signature,
}

impl NonceRequest {
    fn message(reservation: ReservationId, attempt: [u8; 32]) -> Message {
        // The reservation already pins the request and path by hash.
        message(("fedimint/bolt12/nonce-request/v1", reservation, attempt).consensus_hash())
    }

    pub fn new(
        reservation: ReservationId,
        attempt: [u8; 32],
        invoice_request: Vec<u8>,
        payment_path: Vec<u8>,
        gateway_key: &Keypair,
    ) -> Self {
        Self {
            reservation,
            attempt,
            invoice_request,
            payment_path,
            signature: gateway_key.sign_schnorr(Self::message(reservation, attempt)),
        }
    }

    pub fn verify(&self, gateway: &PublicKey) -> bool {
        verify(
            Self::message(self.reservation, self.attempt),
            &self.signature,
            gateway,
        )
    }
}

/// A guardian's serialized FROST nonce commitment for one attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceResponse {
    pub commitments: Vec<u8>,
}

/// Round two of invoice signing: the signing package assembled from a quorum
/// of nonce commitments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequest {
    pub reservation: ReservationId,
    pub attempt: [u8; 32],
    /// Serialized FROST signing package.
    pub package: Vec<u8>,
    pub signature: Signature,
}

impl SignRequest {
    fn message(reservation: ReservationId, attempt: [u8; 32], package: &Vec<u8>) -> Message {
        message(
            (
                "fedimint/bolt12/sign-request/v1",
                reservation,
                attempt,
                package,
            )
                .consensus_hash(),
        )
    }

    pub fn new(
        reservation: ReservationId,
        attempt: [u8; 32],
        package: Vec<u8>,
        gateway_key: &Keypair,
    ) -> Self {
        let signature = gateway_key.sign_schnorr(Self::message(reservation, attempt, &package));

        Self {
            reservation,
            attempt,
            package,
            signature,
        }
    }

    pub fn verify(&self, gateway: &PublicKey) -> bool {
        verify(
            Self::message(self.reservation, self.attempt, &self.package),
            &self.signature,
            gateway,
        )
    }
}

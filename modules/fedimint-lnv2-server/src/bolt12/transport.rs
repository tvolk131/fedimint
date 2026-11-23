//! Private, relay-capable channels between the committee members of a
//! generation run, carried over the guardians' module API.
//!
//! Each message is Schnorr-signed by its sender, split into chunks, and each
//! chunk is encrypted with ChaCha20-Poly1305 under an ephemeral ECDH key
//! derived deterministically from the sender's run seed (providing forward
//! secrecy while live, and deterministic ciphertext verification after an
//! abandoned run reveals the seed). Every packet also carries a Schnorr
//! `envelope_sig` so third-party committee relays can fetch and forward
//! stalled packets without learning plaintext or accepting forged bytes.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context as _, Result, bail, ensure};
use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use fedimint_api_client::api::{DynModuleApi, FederationApiExt as _};
use fedimint_core::PeerId;
use fedimint_core::bitcoin::hashes::{Hash as _, sha256};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::ApiRequestErased;
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_core::secp256k1::schnorr::Signature;
use fedimint_core::secp256k1::{Keypair, Message, PublicKey, SECP256K1, SecretKey};
use fedimint_core::task::sleep;
use fedimint_lnv2_common::endpoint_constants::{
    BOLT12_MPC_ENDPOINT, BOLT12_MPC_FETCH_ENDPOINT, BOLT12_MPC_RELAY_ENDPOINT,
};
use futures::future::{join_all, try_join_all};
use mpc::engine::Transport;
use tokio::sync::{Notify, Semaphore};

use super::keys::transport_key;
use crate::db::{BadPacket, RelayEvidence, SignedMessage, TransportFault};

/// Bytes of the signature appended to each message.
const SIGNATURE_LEN: usize = 64;

/// Plaintext bytes per chunk.
pub const CHUNK: usize = 256 * 1024;

/// The largest message a run sends: one peer's share of the double-random
/// batch (`<= MAX_TRIPLES / 2` bytes for a `2f + 1` committee).
pub const MAX_MESSAGE: usize = mpc::MAX_TRIPLES / 2;

/// The longest hex-encoded packet the endpoint accepts.
pub const MAX_PACKET_HEX: usize = 2 * (CHUNK + 1024);

/// Maximum ciphertext bytes allowed in a recorded [`BadPacket`].
pub const MAX_FAULT_CIPHERTEXT_LEN: usize = CHUNK + 1024;

/// Longest hex-encoded relay request accepted by the relay endpoint.
pub const MAX_RELAY_REQUEST_HEX: usize = 512;

/// Longest hex-encoded fetch request accepted by the fetch endpoint.
pub const MAX_FETCH_REQUEST_HEX: usize = 512;

/// Cap on recorded relay-missing witnesses per guardian per run.
pub const MAX_RELAY_WITNESSES: usize = 256;

/// Maximum concurrent upstream relay fetches performed on behalf of any single
/// committee peer, preventing colluding peers from starving honest victims.
const MAX_CONCURRENT_RELAY_FETCHES_PER_PEER: usize = 2;

/// Per-run wire and evidence size limits derived from `(committee_len, degree, batch)`.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ChannelLimits {
    /// Maximum honest plaintext message size for this run.
    pub message: usize,
    /// Maximum encrypted chunks per message accepted for this run.
    pub chunks: u32,
    /// Maximum total fault ciphertext bytes stored in one guardian's
    /// [`RelayEvidence`] for this run.
    pub fault_bytes: usize,
}

impl ChannelLimits {
    /// Compute tight per-run limits matching the largest honest message in
    /// `mpc::engine::run` for `(committee_len, degree, batch)`.
    #[must_use]
    pub fn for_run(committee_len: usize, degree: usize, batch: usize) -> Self {
        let triples = batch
            .saturating_mul(mpc::circuit::SHA256_AND_GATES)
            .saturating_add(1);
        let honest = committee_len.saturating_sub(degree).max(1);
        let blocks = triples.div_ceil(honest);
        // `gen_double_random` sends at most `blocks` bytes per peer when
        // `n = 2t + 1` (and `2 * blocks` when `n > 2t + 1`).
        let double_rand = if committee_len > degree.saturating_mul(2).saturating_add(1) {
            blocks.saturating_mul(2)
        } else {
            blocks
        };
        let inputs_or_outputs = batch.saturating_mul(256);
        let message = double_rand.max(inputs_or_outputs).clamp(4096, MAX_MESSAGE);
        let chunks = u32::try_from(message.saturating_add(SIGNATURE_LEN).div_ceil(CHUNK))
            .expect("bounded by MAX_MESSAGE");
        let per_sender_fault = usize::try_from(chunks)
            .expect("bounded by MAX_CHUNKS")
            .saturating_mul(CHUNK + 16)
            .max(2 * MAX_FAULT_CIPHERTEXT_LEN);
        let fault_bytes = per_sender_fault.saturating_mul(degree.saturating_add(1));

        Self {
            message,
            chunks,
            fault_bytes,
        }
    }
}

/// How long one delivery or relay fetch attempt may take before retry.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);

/// Wait this long for direct delivery before asking other committee members
/// to relay the missing packet.
const RELAY_TRIGGER: Duration = Duration::from_secs(10);

const RETRY_DELAY: Duration = Duration::from_millis(100);

/// What a member signs for each plaintext message it sends.
pub fn message_digest(
    run: u64,
    sender: PeerId,
    recipient: PeerId,
    round: u64,
    message: &[u8],
) -> Message {
    let hash: sha256::Hash = (
        "fedimint/bolt12/mpc-message/v1",
        run,
        sender,
        recipient,
        round,
        sha256::Hash::hash(message),
    )
        .consensus_hash();

    Message::from_digest(hash.to_byte_array())
}

/// Whether `signed` is `sender`'s message to `recipient` in `round`.
pub fn verify_message(
    run: u64,
    sender: (PeerId, &PublicKey),
    recipient: PeerId,
    round: u64,
    signed: &SignedMessage,
) -> bool {
    SECP256K1
        .verify_schnorr(
            &signed.signature,
            &message_digest(run, sender.0, recipient, round, &signed.message),
            &sender.1.x_only_public_key().0,
        )
        .is_ok()
}

/// Deterministic per-run, per-recipient ephemeral encryption secret derived
/// from the sender's run `seed`.
pub fn ephemeral_secret(seed: &[u8; 32], run: u64, sender: PeerId, recipient: PeerId) -> SecretKey {
    for counter in 0u64.. {
        let hash: sha256::Hash = (
            "fedimint/bolt12/ephemeral/v1",
            *seed,
            run,
            sender,
            recipient,
            counter,
        )
            .consensus_hash();

        if let Ok(secret) = SecretKey::from_slice(&hash.to_byte_array()) {
            return secret;
        }
    }

    unreachable!("secp256k1 scalar space covers nearly all 256-bit hashes")
}

/// What a sender signs on the outside of every encrypted packet chunk so
/// relays can authenticate chunks without holding the decryption key.
#[allow(clippy::too_many_arguments)]
pub(super) fn packet_digest(
    run: u64,
    sender: PeerId,
    recipient: PeerId,
    round: u64,
    chunk: u32,
    chunks: u32,
    ephemeral_pk: PublicKey,
    ciphertext: &[u8],
) -> Message {
    let hash: sha256::Hash = (
        "fedimint/bolt12/mpc-packet/v1",
        (run, sender, recipient),
        (round, chunk, chunks),
        ephemeral_pk,
        sha256::Hash::hash(ciphertext),
    )
        .consensus_hash();

    Message::from_digest(hash.to_byte_array())
}

/// Verify the outer Schnorr signature on an [`MpcPacket`].
pub fn verify_packet_envelope(
    run: u64,
    sender: (PeerId, &PublicKey),
    recipient: PeerId,
    packet: &MpcPacket,
) -> bool {
    packet.run == run
        && packet.sender == sender.0
        && SECP256K1
            .verify_schnorr(
                &packet.envelope_sig,
                &packet_digest(
                    run,
                    sender.0,
                    recipient,
                    packet.round,
                    packet.chunk,
                    packet.chunks,
                    packet.ephemeral_pk,
                    &packet.ciphertext,
                ),
                &sender.1.x_only_public_key().0,
            )
            .is_ok()
}

/// Verify the outer Schnorr signature on a recorded [`BadPacket`].
pub fn verify_bad_packet_envelope(
    run: u64,
    sender: (PeerId, &PublicKey),
    recipient: PeerId,
    bad: &BadPacket,
) -> bool {
    bad.sender == sender.0
        && SECP256K1
            .verify_schnorr(
                &bad.envelope_sig,
                &packet_digest(
                    run,
                    sender.0,
                    recipient,
                    bad.round,
                    bad.chunk,
                    bad.chunks,
                    bad.ephemeral_pk,
                    &bad.ciphertext,
                ),
                &sender.1.x_only_public_key().0,
            )
            .is_ok()
}

fn bad_packet(packet: &MpcPacket) -> BadPacket {
    BadPacket {
        sender: packet.sender,
        round: packet.round,
        chunk: packet.chunk,
        chunks: packet.chunks,
        ephemeral_pk: packet.ephemeral_pk,
        ciphertext: packet.ciphertext.clone(),
        envelope_sig: packet.envelope_sig,
    }
}

fn decrypt_bad_packet(
    run: u64,
    sender: PeerId,
    recipient: PeerId,
    sender_seed: &[u8; 32],
    recipient_pk: &PublicKey,
    bad: &BadPacket,
    max_chunks: u32,
) -> Option<Vec<u8>> {
    if !(1..=max_chunks).contains(&bad.chunks)
        || bad.chunk >= bad.chunks
        || bad.ciphertext.len() > MAX_FAULT_CIPHERTEXT_LEN
    {
        return None;
    }

    let eph = ephemeral_secret(sender_seed, run, sender, recipient);
    if eph.public_key(SECP256K1) != bad.ephemeral_pk {
        return None;
    }

    let key = transport_key(&eph, recipient_pk, &domain(run, sender, recipient));

    ChaCha20Poly1305::new((&key).into())
        .decrypt(
            Nonce::from_slice(&nonce(bad.round, bad.chunk)),
            Payload {
                msg: &bad.ciphertext,
                aad: &aad(run, sender, recipient, bad.round, bad.chunks),
            },
        )
        .ok()
        .filter(|plaintext| plaintext.len() <= CHUNK)
}

fn payload_has_valid_inner_sig(
    run: u64,
    sender: (PeerId, &PublicKey),
    recipient: PeerId,
    round: u64,
    mut payload: Vec<u8>,
) -> bool {
    if payload.len() < SIGNATURE_LEN {
        return false;
    }
    let Ok(signature) = Signature::from_slice(&payload.split_off(payload.len() - SIGNATURE_LEN))
    else {
        return false;
    };

    verify_message(
        run,
        sender,
        recipient,
        round,
        &SignedMessage {
            message: payload,
            signature,
        },
    )
}

/// Returns `true` iff `fault`, reported by `recipient`, cryptographically
/// proves that `sender` signed a corrupt, conflicting, or improperly-signed
/// packet for `recipient` in `run`.
///
/// Every branch verifies `sender`'s outer `envelope_sig` before testing the
/// fault condition, so a malicious `recipient` cannot frame an honest `sender`.
pub fn verify_transport_fault_convicts(
    run: u64,
    sender: (PeerId, &PublicKey),
    recipient: (PeerId, &PublicKey),
    sender_seed: &[u8; 32],
    fault: &TransportFault,
    max_chunks: u32,
) -> bool {
    match fault {
        TransportFault::BadPacket(bad) => {
            if !verify_bad_packet_envelope(run, sender, recipient.0, bad) {
                return false;
            }
            let Some(plaintext) = decrypt_bad_packet(
                run,
                sender.0,
                recipient.0,
                sender_seed,
                recipient.1,
                bad,
                max_chunks,
            ) else {
                return true;
            };
            // A single-chunk packet that decrypted cleanly still convicts
            // `sender` if its inner signed message is malformed or invalid.
            bad.chunks == 1
                && !payload_has_valid_inner_sig(run, sender, recipient.0, bad.round, plaintext)
        }
        TransportFault::ChunkCountConflict(a, b) => {
            a.round == b.round
                && a.chunks != b.chunks
                && verify_bad_packet_envelope(run, sender, recipient.0, a)
                && verify_bad_packet_envelope(run, sender, recipient.0, b)
        }
        TransportFault::BadMultiChunk(packets) => {
            let Some(first) = packets.first() else {
                return false;
            };
            let Ok(count) = u32::try_from(packets.len()) else {
                return false;
            };
            if !(2..=max_chunks).contains(&count) {
                return false;
            }

            let mut payload = Vec::new();
            for (index, pkt) in packets.iter().enumerate() {
                let expected_index = u32::try_from(index).expect("bounded by MAX_CHUNKS");
                if pkt.round != first.round
                    || pkt.chunks != count
                    || pkt.chunk != expected_index
                    || !verify_bad_packet_envelope(run, sender, recipient.0, pkt)
                {
                    return false;
                }
                let Some(plaintext) = decrypt_bad_packet(
                    run,
                    sender.0,
                    recipient.0,
                    sender_seed,
                    recipient.1,
                    pkt,
                    max_chunks,
                ) else {
                    return true;
                };
                payload.extend_from_slice(&plaintext);
            }

            !payload_has_valid_inner_sig(run, sender, recipient.0, first.round, payload)
        }
    }
}

/// One encrypted, envelope-signed chunk of a message from `sender` in `round`.
#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable)]
pub struct MpcPacket {
    pub run: u64,
    pub sender: PeerId,
    pub round: u64,
    pub chunk: u32,
    pub chunks: u32,
    pub ephemeral_pk: PublicKey,
    pub ciphertext: Vec<u8>,
    pub envelope_sig: Signature,
}

/// Authenticated request from a committee member `requester` asking a sender
/// for its cached encrypted packets addressed to `recipient` in `(run, round)`.
#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable)]
pub struct FetchRequest {
    pub run: u64,
    pub requester: PeerId,
    pub recipient: PeerId,
    pub round: u64,
    pub signature: Signature,
}

impl FetchRequest {
    fn digest(run: u64, requester: PeerId, recipient: PeerId, round: u64) -> Message {
        let hash: sha256::Hash = (
            "fedimint/bolt12/mpc-fetch/v1",
            run,
            requester,
            recipient,
            round,
        )
            .consensus_hash();

        Message::from_digest(hash.to_byte_array())
    }

    pub fn new(
        run: u64,
        requester: PeerId,
        recipient: PeerId,
        round: u64,
        signing_key: &Keypair,
    ) -> Self {
        let signature =
            SECP256K1.sign_schnorr(&Self::digest(run, requester, recipient, round), signing_key);

        Self {
            run,
            requester,
            recipient,
            round,
            signature,
        }
    }

    pub fn verify(&self, requester_pk: &PublicKey) -> bool {
        SECP256K1
            .verify_schnorr(
                &self.signature,
                &Self::digest(self.run, self.requester, self.recipient, self.round),
                &requester_pk.x_only_public_key().0,
            )
            .is_ok()
    }
}

/// Authenticated request from `recipient` asking another committee member to
/// fetch and relay `sender`'s packets for `(run, round)`.
#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable)]
pub struct RelayRequest {
    pub run: u64,
    pub sender: PeerId,
    pub recipient: PeerId,
    pub round: u64,
    pub signature: Signature,
}

impl RelayRequest {
    fn digest(run: u64, sender: PeerId, recipient: PeerId, round: u64) -> Message {
        let hash: sha256::Hash = (
            "fedimint/bolt12/mpc-relay/v1",
            run,
            sender,
            recipient,
            round,
        )
            .consensus_hash();

        Message::from_digest(hash.to_byte_array())
    }

    pub fn new(
        run: u64,
        sender: PeerId,
        recipient: PeerId,
        round: u64,
        signing_key: &Keypair,
    ) -> Self {
        let signature =
            SECP256K1.sign_schnorr(&Self::digest(run, sender, recipient, round), signing_key);

        Self {
            run,
            sender,
            recipient,
            round,
            signature,
        }
    }

    pub fn verify(&self, recipient_pk: &PublicKey) -> bool {
        SECP256K1
            .verify_schnorr(
                &self.signature,
                &Self::digest(self.run, self.sender, self.recipient, self.round),
                &recipient_pk.x_only_public_key().0,
            )
            .is_ok()
    }
}

fn domain(run: u64, sender: PeerId, recipient: PeerId) -> Vec<u8> {
    ("fedimint/bolt12/mpc-channel/v2", run, sender, recipient).consensus_encode_to_vec()
}

fn nonce(round: u64, chunk: u32) -> [u8; 12] {
    let mut nonce = [0; 12];

    nonce[..8].copy_from_slice(&round.to_be_bytes());
    nonce[8..].copy_from_slice(&chunk.to_be_bytes());

    nonce
}

fn aad(run: u64, sender: PeerId, recipient: PeerId, round: u64, chunks: u32) -> Vec<u8> {
    (domain(run, sender, recipient), round, chunks).consensus_encode_to_vec()
}

struct PartialMessage {
    first: BadPacket,
    chunks: Vec<Option<(BadPacket, Vec<u8>)>>,
}

#[derive(Default)]
struct Inbox {
    /// Rounds whose message has fully arrived.
    complete: BTreeMap<u64, Vec<u8>>,
    /// Rounds whose message has partly arrived, by chunk.
    partial: BTreeMap<u64, PartialMessage>,
}

struct State {
    /// The round this guardian is in. Peers are at most one round ahead.
    round: u64,
    inboxes: BTreeMap<PeerId, Inbox>,
    /// Recently sent encrypted packets (`round`, `round - 1`, `round - 2`) so
    /// peers or committee relays can pull them on demand without racing
    /// against selective-delivery round advancement.
    outbox: BTreeMap<(PeerId, u64), Vec<MpcPacket>>,
}

/// This guardian's channels in one run.
pub struct Channels {
    run: u64,
    me: PeerId,
    committee: Vec<PeerId>,
    limits: ChannelLimits,
    /// Per peer: our ephemeral public key and derived symmetric encryption key
    /// for outgoing packets to that peer.
    send_keys: BTreeMap<PeerId, (PublicKey, [u8; 32])>,
    transport_secret: SecretKey,
    signing_key: Keypair,
    public_keys: BTreeMap<PeerId, PublicKey>,
    state: Mutex<State>,
    /// Every message received, with its signature, by round and committee
    /// position.
    transcript: Mutex<Vec<Vec<Option<SignedMessage>>>>,
    /// `(sender, recipient, round)` triples where this guardian tried to relay
    /// and `sender` failed to serve valid envelope-signed chunks.
    relay_missing: Mutex<BTreeSet<(PeerId, PeerId, u64)>>,
    /// Verifiable transport faults observed from senders addressed to this
    /// guardian, keyed by `sender` (at most one per committee member).
    faults: Mutex<BTreeMap<PeerId, TransportFault>>,
    /// Per-recipient concurrency limits for upstream relay fetches so
    /// colluding peers cannot starve honest victims.
    relay_sems: BTreeMap<PeerId, Semaphore>,
    arrived: Notify,
}

impl Channels {
    pub fn new(
        run: u64,
        me: PeerId,
        committee: Vec<PeerId>,
        limits: ChannelLimits,
        seed: &[u8; 32],
        secret: &SecretKey,
        transport_keys: &BTreeMap<PeerId, PublicKey>,
    ) -> Result<Arc<Self>> {
        let mut send_keys = BTreeMap::new();
        let mut inboxes = BTreeMap::new();
        let mut public_keys = BTreeMap::new();
        let mut relay_sems = BTreeMap::new();

        for peer in committee.iter().filter(|peer| **peer != me) {
            let public = transport_keys
                .get(peer)
                .context("A committee member has no transport key")?;

            let eph = ephemeral_secret(seed, run, me, *peer);
            let eph_pk = eph.public_key(SECP256K1);
            let send_key = transport_key(&eph, public, &domain(run, me, *peer));

            send_keys.insert(*peer, (eph_pk, send_key));
            inboxes.insert(*peer, Inbox::default());
            public_keys.insert(*peer, *public);
            relay_sems.insert(*peer, Semaphore::new(MAX_CONCURRENT_RELAY_FETCHES_PER_PEER));
        }

        Ok(Arc::new(Self {
            run,
            me,
            committee,
            limits,
            send_keys,
            transport_secret: *secret,
            signing_key: Keypair::from_secret_key(SECP256K1, secret),
            public_keys,
            state: Mutex::new(State {
                round: 0,
                inboxes,
                outbox: BTreeMap::new(),
            }),
            transcript: Mutex::new(vec![]),
            relay_missing: Mutex::new(BTreeSet::new()),
            faults: Mutex::new(BTreeMap::new()),
            relay_sems,
            arrived: Notify::new(),
        }))
    }

    pub fn run(&self) -> u64 {
        self.run
    }

    /// Everything received so far, with signatures, by round and position.
    pub fn transcript(&self) -> Vec<Vec<Option<SignedMessage>>> {
        self.transcript.lock().expect("not poisoned").clone()
    }

    /// Whether this guardian has already received and verified a valid message
    /// from `sender` in `round`.
    fn has_received(&self, sender: PeerId, round: u64) -> bool {
        let Some(position) = self.committee.iter().position(|member| *member == sender) else {
            return false;
        };
        let Ok(round_index) = usize::try_from(round) else {
            return false;
        };

        self.transcript
            .lock()
            .expect("not poisoned")
            .get(round_index)
            .and_then(|row| row.get(position))
            .is_some_and(Option::is_some)
    }

    /// Relay witnesses and verifiable transport faults recorded during this
    /// run.
    pub fn relay_evidence(&self) -> RelayEvidence {
        RelayEvidence {
            relay_missing: self
                .relay_missing
                .lock()
                .expect("not poisoned")
                .iter()
                .copied()
                .collect(),
            faults: self
                .faults
                .lock()
                .expect("not poisoned")
                .values()
                .cloned()
                .collect(),
        }
    }

    /// Serve cached encrypted packets this guardian sent to `recipient` in
    /// `round`, after authenticating that `request.requester` is a committee
    /// member.
    pub fn serve_packets(&self, request: &FetchRequest) -> Result<Vec<MpcPacket>> {
        ensure!(request.run == self.run, "Wrong run");
        ensure!(
            request.requester != self.me && request.recipient != self.me,
            "Invalid fetch endpoints"
        );

        let requester_pk = self
            .public_keys
            .get(&request.requester)
            .context("Requester is not a committee peer")?;
        ensure!(
            self.public_keys.contains_key(&request.recipient),
            "Recipient is not a committee peer"
        );
        ensure!(
            request.verify(requester_pk),
            "Fetch request signature is invalid"
        );

        let state = self.state.lock().expect("not poisoned");
        ensure!(
            request.round <= state.round,
            "Fetch request is for a future round"
        );

        state
            .outbox
            .get(&(request.recipient, request.round))
            .cloned()
            .context("Packets for that round are not available")
    }

    /// Fetch `request.sender`'s encrypted packets for `request.recipient` in
    /// `request.round` and verify their outer signatures.
    ///
    /// A failed fetch is recorded in `relay_missing` only when this guardian
    /// has already received `sender`'s valid message for `round` (proving
    /// `sender` has already entered `round` and populated its outbox), and any
    /// later successful fetch clears a previously recorded witness.
    pub async fn relay_fetch(
        &self,
        api: &DynModuleApi,
        request: &RelayRequest,
    ) -> Result<Vec<MpcPacket>> {
        ensure!(request.run == self.run, "Wrong run");
        ensure!(
            request.sender != self.me
                && request.recipient != self.me
                && request.sender != request.recipient,
            "Invalid relay endpoints"
        );

        let sender_pk = *self
            .public_keys
            .get(&request.sender)
            .context("Sender is not a committee peer")?;
        let recipient_pk = *self
            .public_keys
            .get(&request.recipient)
            .context("Recipient is not a committee peer")?;

        ensure!(
            request.verify(&recipient_pk),
            "Relay request signature is invalid"
        );

        {
            let state = self.state.lock().expect("not poisoned");
            ensure!(
                request.round <= state.round && request.round >= state.round.saturating_sub(1),
                "Relay request is outside the active round window"
            );
        }

        let _permit = self
            .relay_sems
            .get(&request.recipient)
            .context("Recipient is not a committee peer")?
            .acquire()
            .await
            .map_err(|_| anyhow::anyhow!("Relay semaphore closed"))?;

        let fetch_req = FetchRequest::new(
            request.run,
            self.me,
            request.recipient,
            request.round,
            &self.signing_key,
        )
        .consensus_encode_to_hex();

        let fetched = fedimint_core::runtime::timeout(
            ATTEMPT_TIMEOUT,
            api.request_single_peer::<Vec<String>>(
                BOLT12_MPC_FETCH_ENDPOINT.to_owned(),
                ApiRequestErased::new(fetch_req),
                request.sender,
            ),
        )
        .await;

        let validated = match fetched {
            Ok(Ok(hex_packets)) => validate_relayed_packets(
                self.run,
                (request.sender, &sender_pk),
                request.recipient,
                request.round,
                self.limits.chunks,
                &hex_packets,
            ),
            Ok(Err(err)) => Err(err.into()),
            Err(_) => Err(anyhow::anyhow!("Relay fetch timed out")),
        };

        if validated.is_ok() {
            self.relay_missing.lock().expect("not poisoned").remove(&(
                request.sender,
                request.recipient,
                request.round,
            ));
        } else if self.has_received(request.sender, request.round) {
            let mut missing = self.relay_missing.lock().expect("not poisoned");
            if missing.len() < MAX_RELAY_WITNESSES {
                missing.insert((request.sender, request.recipient, request.round));
            }
        }

        validated
    }

    /// Check the sender's signature on a completed message and record it.
    fn accept(&self, sender: PeerId, round: u64, mut payload: Vec<u8>) -> Result<Vec<u8>> {
        ensure!(payload.len() >= SIGNATURE_LEN, "The message is unsigned");

        let signature = Signature::from_slice(&payload.split_off(payload.len() - SIGNATURE_LEN))?;

        let signed = SignedMessage {
            message: payload,
            signature,
        };

        ensure!(
            verify_message(
                self.run,
                (sender, &self.public_keys[&sender]),
                self.me,
                round,
                &signed
            ),
            "The message signature is invalid"
        );

        let position = self
            .committee
            .iter()
            .position(|member| *member == sender)
            .expect("only committee peers have inboxes");

        let mut transcript = self.transcript.lock().expect("not poisoned");
        let round_index = usize::try_from(round)?;

        while transcript.len() <= round_index {
            transcript.push(vec![None; self.committee.len()]);
        }

        transcript[round_index][position] = Some(signed.clone());

        Ok(signed.message)
    }

    /// Record at most one verifiable transport fault per sender while respecting
    /// the total ciphertext byte budget across all stored faults.
    fn record_fault(&self, sender: PeerId, fault: TransportFault) {
        let mut faults = self.faults.lock().expect("not poisoned");
        if faults.contains_key(&sender) {
            return;
        }
        let used: usize = faults
            .values()
            .fold(0usize, |acc, f| acc.saturating_add(f.ciphertext_bytes()));
        if used.saturating_add(fault.ciphertext_bytes()) <= self.limits.fault_bytes {
            faults.insert(sender, fault);
        }
    }

    fn decrypt_incoming(&self, packet: &MpcPacket) -> Result<Vec<u8>> {
        let key = transport_key(
            &self.transport_secret,
            &packet.ephemeral_pk,
            &domain(self.run, packet.sender, self.me),
        );

        let Ok(plaintext) = ChaCha20Poly1305::new((&key).into()).decrypt(
            Nonce::from_slice(&nonce(packet.round, packet.chunk)),
            Payload {
                msg: &packet.ciphertext,
                aad: &aad(
                    self.run,
                    packet.sender,
                    self.me,
                    packet.round,
                    packet.chunks,
                ),
            },
        ) else {
            self.record_fault(packet.sender, TransportFault::BadPacket(bad_packet(packet)));
            bail!("The packet failed authentication");
        };

        if plaintext.len() > CHUNK {
            self.record_fault(packet.sender, TransportFault::BadPacket(bad_packet(packet)));
            bail!("Oversized chunk");
        }

        Ok(plaintext)
    }

    /// Accept a packet a peer or relay delivered. An error tells the sender to
    /// retry later or give up; a duplicate is accepted again.
    pub fn receive(&self, packet: &MpcPacket) -> Result<()> {
        ensure!(packet.run == self.run, "Wrong run");

        let sender_pk = self
            .public_keys
            .get(&packet.sender)
            .context("Not a committee peer")?;

        ensure!(
            (1..=self.limits.chunks).contains(&packet.chunks) && packet.chunk < packet.chunks,
            "Invalid chunk index"
        );

        ensure!(
            verify_packet_envelope(self.run, (packet.sender, sender_pk), self.me, packet),
            "Packet envelope signature is invalid"
        );

        let mut state = self.state.lock().expect("not poisoned");

        if packet.round < state.round {
            return Ok(());
        }

        ensure!(
            packet.round <= state.round + 1,
            "The packet is for a later round"
        );

        let inbox = state
            .inboxes
            .get_mut(&packet.sender)
            .expect("every peer has an inbox");

        if inbox.complete.contains_key(&packet.round) {
            return Ok(());
        }

        let plaintext = self.decrypt_incoming(packet)?;

        let partial = inbox
            .partial
            .entry(packet.round)
            .or_insert_with(|| PartialMessage {
                first: bad_packet(packet),
                chunks: vec![None; packet.chunks as usize],
            });

        if partial.chunks.len() != packet.chunks as usize {
            let first = partial.first.clone();
            self.record_fault(
                packet.sender,
                TransportFault::ChunkCountConflict(first, bad_packet(packet)),
            );
            bail!("Chunk count changed within a message");
        }

        let slot = &mut partial.chunks[packet.chunk as usize];
        if slot.is_none() {
            *slot = Some((bad_packet(packet), plaintext));
        }

        if partial.chunks.iter().all(Option::is_some) {
            let completed = inbox.partial.remove(&packet.round).expect("just inserted");
            let mut raw_packets = Vec::with_capacity(completed.chunks.len());
            let mut payload = Vec::new();
            for (raw, chunk_plaintext) in completed.chunks.into_iter().flatten() {
                raw_packets.push(raw);
                payload.extend_from_slice(&chunk_plaintext);
            }

            let message = match self.accept(packet.sender, packet.round, payload) {
                Ok(message) => message,
                Err(err) => {
                    let fault = if raw_packets.len() == 1 {
                        TransportFault::BadPacket(raw_packets.pop().expect("single chunk"))
                    } else {
                        TransportFault::BadMultiChunk(raw_packets)
                    };
                    self.record_fault(packet.sender, fault);
                    return Err(err);
                }
            };

            state
                .inboxes
                .get_mut(&packet.sender)
                .expect("every peer has an inbox")
                .complete
                .insert(packet.round, message);

            drop(state);

            self.arrived.notify_waiters();
        }

        Ok(())
    }

    /// Wait for `sender`'s message in `round`.
    async fn take(&self, sender: PeerId, round: u64) -> Vec<u8> {
        loop {
            let arrived = self.arrived.notified();

            tokio::pin!(arrived);

            arrived.as_mut().enable();

            if let Some(message) = self
                .state
                .lock()
                .expect("not poisoned")
                .inboxes
                .get_mut(&sender)
                .and_then(|inbox| inbox.complete.remove(&round))
            {
                return message;
            }

            arrived.await;
        }
    }

    /// Build and envelope-sign outgoing packets for `(recipient, round)`
    /// without mutating `state`.
    fn build_packets(
        &self,
        recipient: PeerId,
        round: u64,
        message: &[u8],
    ) -> Result<Vec<MpcPacket>> {
        ensure!(message.len() <= self.limits.message, "Oversized message");

        let (ephemeral_pk, key) = self
            .send_keys
            .get(&recipient)
            .context("Not a committee peer")?;
        let cipher = ChaCha20Poly1305::new(key.into());

        let signature = SECP256K1.sign_schnorr(
            &message_digest(self.run, self.me, recipient, round, message),
            &self.signing_key,
        );

        let mut payload = message.to_vec();

        payload.extend_from_slice(signature.as_ref());

        let chunks: Vec<&[u8]> = payload.chunks(CHUNK).collect();

        let count = u32::try_from(chunks.len()).expect("bounded by MAX_MESSAGE");
        let aad = aad(self.run, self.me, recipient, round, count);

        chunks
            .into_iter()
            .enumerate()
            .map(|(i, chunk)| {
                let index = u32::try_from(i).expect("bounded by MAX_MESSAGE");

                let ciphertext = cipher
                    .encrypt(
                        Nonce::from_slice(&nonce(round, index)),
                        Payload {
                            msg: chunk,
                            aad: &aad,
                        },
                    )
                    .ok()
                    .context("Encryption failed")?;

                let envelope_sig = SECP256K1.sign_schnorr(
                    &packet_digest(
                        self.run,
                        self.me,
                        recipient,
                        round,
                        index,
                        count,
                        *ephemeral_pk,
                        &ciphertext,
                    ),
                    &self.signing_key,
                );

                Ok(MpcPacket {
                    run: self.run,
                    sender: self.me,
                    round,
                    chunk: index,
                    chunks: count,
                    ephemeral_pk: *ephemeral_pk,
                    ciphertext,
                    envelope_sig,
                })
            })
            .collect()
    }

    /// Build all outgoing packets for `round`, then atomically advance
    /// `state.round`, prune old inbox/outbox entries, and publish the new
    /// outbox packets under a single lock acquisition.
    ///
    /// Keeping `round`, `round - 1`, and `round - 2` in the outbox ensures an
    /// honest relay in `{round, round + 1}` can always fetch an honest
    /// sender's packets even if a malicious peer selectively advances the
    /// sender by one extra round.
    pub fn enter_with_outgoing(
        &self,
        round: u64,
        outgoing: &[Vec<u8>],
    ) -> Result<Vec<(PeerId, MpcPacket)>> {
        ensure!(
            outgoing.len() == self.committee.len(),
            "One message per committee member"
        );

        let mut per_peer = Vec::with_capacity(self.committee.len().saturating_sub(1));
        let mut packets_to_send = Vec::new();

        for (&peer, message) in self.committee.iter().zip(outgoing) {
            if peer != self.me {
                let built = self.build_packets(peer, round, message)?;
                for packet in &built {
                    packets_to_send.push((peer, packet.clone()));
                }
                per_peer.push((peer, built));
            }
        }

        let mut state = self.state.lock().expect("not poisoned");

        state.round = round;

        for inbox in state.inboxes.values_mut() {
            inbox.complete.retain(|r, _| *r >= round);
            inbox.partial.retain(|r, _| *r >= round);
        }

        state
            .outbox
            .retain(|&(_, r), _| r >= round.saturating_sub(2));

        for (peer, built) in per_peer {
            state.outbox.insert((peer, round), built);
        }

        Ok(packets_to_send)
    }

    /// Build, envelope-sign, and cache the outgoing packets for
    /// `(recipient, round)`.
    #[cfg(test)]
    pub fn packets(&self, recipient: PeerId, round: u64, message: &[u8]) -> Result<Vec<MpcPacket>> {
        let packets = self.build_packets(recipient, round, message)?;

        self.state
            .lock()
            .expect("not poisoned")
            .outbox
            .insert((recipient, round), packets.clone());

        Ok(packets)
    }

    fn relay_request(&self, sender: PeerId, round: u64) -> RelayRequest {
        RelayRequest::new(self.run, sender, self.me, round, &self.signing_key)
    }
}

fn validate_relayed_packets(
    run: u64,
    sender: (PeerId, &PublicKey),
    recipient: PeerId,
    round: u64,
    max_chunks: u32,
    hex_packets: &[String],
) -> Result<Vec<MpcPacket>> {
    ensure!(!hex_packets.is_empty(), "Relay returned no packets");
    ensure!(
        hex_packets.len() <= max_chunks as usize,
        "Relay returned too many chunks"
    );

    let mut packets = Vec::with_capacity(hex_packets.len());
    let expected_chunks = u32::try_from(hex_packets.len()).expect("bounded by MAX_CHUNKS");

    for (index, hex) in hex_packets.iter().enumerate() {
        let packet = decode_packet(hex)?;
        let expected_index = u32::try_from(index).expect("bounded by MAX_CHUNKS");

        ensure!(
            packet.run == run
                && packet.sender == sender.0
                && packet.round == round
                && packet.chunks == expected_chunks
                && packet.chunk == expected_index
                && verify_packet_envelope(run, sender, recipient, &packet),
            "Relayed packet failed validation"
        );

        packets.push(packet);
    }

    Ok(packets)
}

/// Deliver `packet` to `peer`, retrying until it is accepted.
async fn deliver(api: &DynModuleApi, peer: PeerId, packet: &MpcPacket) {
    let encoded = packet.consensus_encode_to_hex();

    loop {
        let attempt = fedimint_core::runtime::timeout(
            ATTEMPT_TIMEOUT,
            api.request_single_peer::<()>(
                BOLT12_MPC_ENDPOINT.to_owned(),
                ApiRequestErased::new(&encoded),
                peer,
            ),
        )
        .await;

        if matches!(attempt, Ok(Ok(()))) {
            return;
        }

        sleep(RETRY_DELAY).await;
    }
}

/// Ask every other committee peer to relay `sender`'s packets for `round`
/// once direct delivery has stalled past `relay_trigger`.
async fn relay_pull_loop(
    channels: &Channels,
    api: &DynModuleApi,
    sender: PeerId,
    round: u64,
    relay_trigger: Duration,
) {
    let relays: Vec<PeerId> = channels
        .committee
        .iter()
        .copied()
        .filter(|&peer| peer != channels.me && peer != sender)
        .collect();

    if relays.is_empty() {
        std::future::pending::<()>().await;
    }

    let request = channels
        .relay_request(sender, round)
        .consensus_encode_to_hex();

    loop {
        sleep(relay_trigger).await;

        let fetches = relays.iter().map(|&relay| {
            let request = request.clone();
            async move {
                let response = fedimint_core::runtime::timeout(
                    ATTEMPT_TIMEOUT,
                    api.request_single_peer::<Vec<String>>(
                        BOLT12_MPC_RELAY_ENDPOINT.to_owned(),
                        ApiRequestErased::new(request),
                        relay,
                    ),
                )
                .await;

                if let Ok(Ok(hex_packets)) = response {
                    for hex in &hex_packets {
                        if let Ok(packet) = decode_packet(hex) {
                            let _ = channels.receive(&packet);
                        }
                    }
                }
            }
        });

        join_all(fetches).await;
    }
}

/// Wait for `sender`'s message in `round`, falling back to committee relays if
/// direct delivery stalls.
async fn take_with_relay(
    channels: &Channels,
    api: &DynModuleApi,
    sender: PeerId,
    round: u64,
    relay_trigger: Duration,
) -> Vec<u8> {
    tokio::select! {
        message = channels.take(sender, round) => message,
        () = relay_pull_loop(channels, api, sender, round, relay_trigger) => unreachable!("relay loop never resolves"),
    }
}

/// The engine's view of the channels: committee positions are party indices.
///
/// Outgoing sends run in background tasks across at most two consecutive
/// rounds so an asymmetric direct-link failure never blocks this party from
/// advancing once the recipient pulls the cached outbox packets via relay.
pub struct ApiTransport {
    channels: Arc<Channels>,
    api: DynModuleApi,
    relay_trigger: Duration,
    pending_sends: Option<tokio::task::JoinHandle<()>>,
    prev_sends: Option<tokio::task::JoinHandle<()>>,
}

impl ApiTransport {
    pub fn new(channels: Arc<Channels>, api: DynModuleApi) -> Self {
        Self::with_relay_trigger(channels, api, RELAY_TRIGGER)
    }

    pub fn with_relay_trigger(
        channels: Arc<Channels>,
        api: DynModuleApi,
        relay_trigger: Duration,
    ) -> Self {
        Self {
            channels,
            api,
            relay_trigger,
            pending_sends: None,
            prev_sends: None,
        }
    }

    /// Wait briefly for any still-in-flight final-round deliveries before
    /// tearing down channels. Returns immediately when sends already finished.
    #[cfg(test)]
    pub async fn flush(&mut self) {
        if let Some(handle) = self.pending_sends.take() {
            let _ =
                fedimint_core::runtime::timeout(self.relay_trigger + ATTEMPT_TIMEOUT, handle).await;
        }
        if let Some(handle) = self.prev_sends.take() {
            handle.abort();
        }
    }
}

impl Drop for ApiTransport {
    fn drop(&mut self) {
        if let Some(handle) = self.pending_sends.take() {
            handle.abort();
        }
        if let Some(handle) = self.prev_sends.take() {
            handle.abort();
        }
    }
}

impl Transport for ApiTransport {
    async fn exchange(&mut self, round: u64, outgoing: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>> {
        let channels = &self.channels;
        let api = &self.api;
        let relay_trigger = self.relay_trigger;

        ensure!(
            outgoing.len() == channels.committee.len(),
            "One message per committee member"
        );

        // Two rounds ago is guaranteed received once everyone reached `round`.
        if let Some(old) = self.prev_sends.take() {
            old.abort();
        }
        self.prev_sends = self.pending_sends.take();

        let packets_to_send = channels.enter_with_outgoing(round, &outgoing)?;

        let send_api = api.clone();
        self.pending_sends = Some(tokio::spawn(async move {
            let sends = packets_to_send
                .iter()
                .map(|(peer, packet)| deliver(&send_api, *peer, packet));
            join_all(sends).await;
        }));

        let receives = channels.committee.iter().map(|peer| async move {
            if *peer == channels.me {
                Ok(Vec::new())
            } else {
                Ok::<_, anyhow::Error>(
                    take_with_relay(channels, api, *peer, round, relay_trigger).await,
                )
            }
        });

        try_join_all(receives).await
    }
}

/// Decode a packet from its hex form as the endpoint receives it.
pub fn decode_packet(hex: &str) -> Result<MpcPacket> {
    if hex.len() > MAX_PACKET_HEX {
        bail!("Oversized packet");
    }

    Ok(MpcPacket::consensus_decode_hex(
        hex,
        &ModuleRegistry::default(),
    )?)
}

/// Decode a relay request from its hex form as the relay endpoint receives it.
pub fn decode_relay_request(hex: &str) -> Result<RelayRequest> {
    if hex.len() > MAX_RELAY_REQUEST_HEX {
        bail!("Oversized relay request");
    }

    Ok(RelayRequest::consensus_decode_hex(
        hex,
        &ModuleRegistry::default(),
    )?)
}

/// Decode a fetch request from its hex form as the fetch endpoint receives it.
pub fn decode_fetch_request(hex: &str) -> Result<FetchRequest> {
    if hex.len() > MAX_FETCH_REQUEST_HEX {
        bail!("Oversized fetch request");
    }

    Ok(FetchRequest::consensus_decode_hex(
        hex,
        &ModuleRegistry::default(),
    )?)
}

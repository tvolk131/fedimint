//! Private, relay-capable channels between the committee members of a
//! generation run, carried over the guardians' module API.
//!
//! Each message is Schnorr-signed by its sender, split into 32 KiB chunks (so
//! every hex-encoded packet stays below Iroh's 100 KB RPC cap), and encrypted
//! with ChaCha20-Poly1305. Round 0 (public context echo) encrypts under
//! `(sender_eph_sk, recipient_static_pk)` and advertises each party's
//! deterministic `recv_ephemeral_pk`; all secret-bearing rounds `>= 1` encrypt
//! under mutual ephemeral-ephemeral ECDH `(sender_eph_sk, recipient_recv_eph_pk)`
//! so compromising long-term transport keys after a run ends reveals nothing
//! about past ciphertexts, while post-abandonment seed reveal remains fully
//! deterministic. Every packet also carries a Schnorr `envelope_sig` so
//! third-party committee relays can fetch and forward stalled packets in
//! bounded pages without learning plaintext or accepting forged bytes.

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
use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, Semaphore};

use super::keys::transport_key;
use crate::db::{BadPacket, RelayEvidence, SignedMessage, TransportFault};

/// Bytes of the signature appended to each message.
const SIGNATURE_LEN: usize = 64;

/// Plaintext bytes per chunk. Chosen so a hex-encoded [`MpcPacket`] (~66.5 KiB)
/// stays strictly below Iroh's 100 KB RPC request limit.
pub const CHUNK: usize = 32 * 1024;

/// The largest message a run sends: one peer's share of the double-random
/// batch (`<= MAX_TRIPLES / 2` bytes for a `2f + 1` committee).
pub const MAX_MESSAGE: usize = mpc::MAX_TRIPLES / 2;

/// The longest hex-encoded packet the endpoint accepts.
pub const MAX_PACKET_HEX: usize = 2 * (CHUNK + 1024);

/// Maximum ciphertext bytes allowed in a recorded [`BadPacket`].
pub const MAX_FAULT_CIPHERTEXT_LEN: usize = CHUNK + 1024;

/// Maximum chunks returned by one `bolt12_mpc_fetch` or `bolt12_mpc_relay`
/// RPC response (`32 * ~66.5 KiB ~= 2.1 MiB` hex, well below the 10 MiB
/// WebSocket response cap).
pub const MAX_CHUNKS_PER_FETCH: u32 = 32;

/// Longest hex-encoded relay request accepted by the relay endpoint.
pub const MAX_RELAY_REQUEST_HEX: usize = 512;

/// Longest hex-encoded fetch request accepted by the fetch endpoint.
pub const MAX_FETCH_REQUEST_HEX: usize = 512;

/// Cap on recorded relay-missing witnesses per guardian per run.
pub const MAX_RELAY_WITNESSES: usize = 256;

/// Maximum concurrent upstream relay fetches performed on behalf of any single
/// committee peer, preventing colluding peers from starving honest victims.
const MAX_CONCURRENT_RELAY_FETCHES_PER_PEER: usize = 2;

/// Minimum concurrent `serve_packets` permits per committee requester.
/// Actual permit count scales with `committee.len() * MAX_CONCURRENT_RELAY_FETCHES_PER_PEER`
/// so colluding recipients cannot trip rate-limit rejections between two honest
/// peers.
const MIN_CONCURRENT_FETCHES_PER_PEER: usize = 8;

/// Number of upstream fetch attempts a relay performs on transient RPC/timeout
/// failures before recording a `relay_missing` witness.
const RELAY_FETCH_ATTEMPTS: usize = 3;

const RELAY_FETCH_BACKOFF: Duration = Duration::from_millis(250);

/// Timeout for a recipient's `BOLT12_MPC_RELAY_ENDPOINT` RPC, covering the
/// relay's internal `RELAY_FETCH_ATTEMPTS * ATTEMPT_TIMEOUT` retry budget plus
/// slack.
const RELAY_PULL_TIMEOUT: Duration = Duration::from_secs(35);

/// One bounded page of hex-encoded encrypted packets returned by fetch/relay
/// endpoints.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PacketPage {
    pub total_chunks: u32,
    pub packets: Vec<String>,
}

/// Per-run wire and evidence size limits derived from `(committee_len, degree, batch)`.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ChannelLimits {
    /// Maximum honest plaintext message size for this run.
    pub message: usize,
    /// Maximum encrypted chunks per message accepted for this run.
    pub chunks: u32,
    /// Maximum total fault ciphertext/message bytes stored in one guardian's
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

/// Deterministic per-run, per-recipient sender ephemeral encryption secret
/// derived from the sender's run `seed`.
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

/// Deterministic per-run, per-sender recipient ephemeral decryption secret
/// derived from the recipient's run `seed` for mutual forward secrecy on
/// rounds `>= 1`.
pub fn recipient_ephemeral_secret(
    recipient_seed: &[u8; 32],
    run: u64,
    sender: PeerId,
    recipient: PeerId,
) -> SecretKey {
    for counter in 0u64.. {
        let hash: sha256::Hash = (
            "fedimint/bolt12/recv-ephemeral/v1",
            *recipient_seed,
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
    recv_ephemeral_pk: PublicKey,
    ciphertext: &[u8],
) -> Message {
    let hash: sha256::Hash = (
        "fedimint/bolt12/mpc-packet/v2",
        (run, sender, recipient),
        (round, chunk, chunks),
        (ephemeral_pk, recv_ephemeral_pk),
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
                    packet.recv_ephemeral_pk,
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
                    bad.recv_ephemeral_pk,
                    &bad.ciphertext,
                ),
                &sender.1.x_only_public_key().0,
            )
            .is_ok()
}

/// Returns `true` iff `r0` is a valid envelope-signed Round-0 chunk-0 packet
/// from `sender` to `recipient` whose advertised `recv_ephemeral_pk` does not
/// match `sender`'s revealed `sender_seed`.
pub fn verify_r0_ephemeral_fault(
    run: u64,
    sender: (PeerId, &PublicKey),
    recipient: PeerId,
    sender_seed: &[u8; 32],
    r0: &BadPacket,
) -> bool {
    if r0.round != 0 || r0.chunk != 0 || !verify_bad_packet_envelope(run, sender, recipient, r0) {
        return false;
    }

    let expected =
        recipient_ephemeral_secret(sender_seed, run, recipient, sender.0).public_key(SECP256K1);
    r0.recv_ephemeral_pk != expected
}

fn bad_packet(packet: &MpcPacket) -> BadPacket {
    BadPacket {
        sender: packet.sender,
        round: packet.round,
        chunk: packet.chunk,
        chunks: packet.chunks,
        ephemeral_pk: packet.ephemeral_pk,
        recv_ephemeral_pk: packet.recv_ephemeral_pk,
        ciphertext: packet.ciphertext.clone(),
        envelope_sig: packet.envelope_sig,
    }
}

#[allow(clippy::too_many_arguments)]
fn decrypt_bad_packet(
    run: u64,
    sender: PeerId,
    recipient: PeerId,
    sender_seed: &[u8; 32],
    recipient_seed: &[u8; 32],
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

    let (key, aad_bytes) = if bad.round == 0 {
        (
            transport_key(&eph, recipient_pk, &domain(run, sender, recipient)),
            aad(run, sender, recipient, bad.round, bad.chunks),
        )
    } else {
        let recv_eph_pk = recipient_ephemeral_secret(recipient_seed, run, sender, recipient)
            .public_key(SECP256K1);
        (
            transport_key(
                &eph,
                &recv_eph_pk,
                &ephemeral_domain(run, sender, recipient),
            ),
            ephemeral_aad(run, sender, recipient, bad.round, bad.chunks),
        )
    };

    ChaCha20Poly1305::new((&key).into())
        .decrypt(
            Nonce::from_slice(&nonce(bad.round, bad.chunk)),
            Payload {
                msg: &bad.ciphertext,
                aad: &aad_bytes,
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
/// packet or equivocated with conflicting signed messages in `run`.
///
/// Every branch verifies `sender`'s signature before testing the fault
/// condition, so a malicious `recipient` cannot frame an honest `sender`.
#[allow(clippy::too_many_arguments)]
pub fn verify_transport_fault_convicts(
    run: u64,
    sender: (PeerId, &PublicKey),
    recipient: (PeerId, &PublicKey),
    sender_seed: &[u8; 32],
    recipient_seed: &[u8; 32],
    fault: &TransportFault,
    max_chunks: u32,
    max_message: usize,
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
                recipient_seed,
                recipient.1,
                bad,
                max_chunks,
            ) else {
                return true;
            };
            // A single-chunk packet that decrypted cleanly still convicts
            // `sender` if its decrypted payload exceeds the per-run message
            // cap or its inner signed message is malformed or invalid.
            bad.chunks == 1
                && (plaintext.len() > max_message.saturating_add(SIGNATURE_LEN)
                    || !payload_has_valid_inner_sig(run, sender, recipient.0, bad.round, plaintext))
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
                    recipient_seed,
                    recipient.1,
                    pkt,
                    max_chunks,
                ) else {
                    return true;
                };
                payload.extend_from_slice(&plaintext);
            }

            payload.len() > max_message.saturating_add(SIGNATURE_LEN)
                || !payload_has_valid_inner_sig(run, sender, recipient.0, first.round, payload)
        }
        TransportFault::MessageEquivocation {
            round,
            sender: fault_sender,
            first,
            second,
        } => {
            *fault_sender == sender.0
                && first.message.len() <= max_message
                && second.message.len() <= max_message
                && first.message != second.message
                && verify_message(run, sender, recipient.0, *round, first)
                && verify_message(run, sender, recipient.0, *round, second)
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
    pub recv_ephemeral_pk: PublicKey,
    pub ciphertext: Vec<u8>,
    pub envelope_sig: Signature,
}

/// Authenticated request from a committee member `requester` asking `sender`
/// for a page of its cached encrypted packets addressed to `recipient` in
/// `(run, round)` starting at `start_chunk`.
#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable)]
pub struct FetchRequest {
    pub run: u64,
    pub sender: PeerId,
    pub requester: PeerId,
    pub recipient: PeerId,
    pub round: u64,
    pub start_chunk: u32,
    pub signature: Signature,
}

impl FetchRequest {
    fn digest(
        run: u64,
        sender: PeerId,
        requester: PeerId,
        recipient: PeerId,
        round: u64,
        start_chunk: u32,
    ) -> Message {
        let hash: sha256::Hash = (
            "fedimint/bolt12/mpc-fetch/v2",
            (run, sender, requester, recipient),
            (round, start_chunk),
        )
            .consensus_hash();

        Message::from_digest(hash.to_byte_array())
    }

    pub fn new(
        run: u64,
        sender: PeerId,
        requester: PeerId,
        recipient: PeerId,
        round: u64,
        start_chunk: u32,
        signing_key: &Keypair,
    ) -> Self {
        let signature = SECP256K1.sign_schnorr(
            &Self::digest(run, sender, requester, recipient, round, start_chunk),
            signing_key,
        );

        Self {
            run,
            sender,
            requester,
            recipient,
            round,
            start_chunk,
            signature,
        }
    }

    pub fn verify(&self, requester_pk: &PublicKey) -> bool {
        SECP256K1
            .verify_schnorr(
                &self.signature,
                &Self::digest(
                    self.run,
                    self.sender,
                    self.requester,
                    self.recipient,
                    self.round,
                    self.start_chunk,
                ),
                &requester_pk.x_only_public_key().0,
            )
            .is_ok()
    }
}

/// Authenticated request from `recipient` asking another committee member to
/// fetch and relay a page of `sender`'s packets for `(run, round)` starting at
/// `start_chunk`.
#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable)]
pub struct RelayRequest {
    pub run: u64,
    pub sender: PeerId,
    pub recipient: PeerId,
    pub round: u64,
    pub start_chunk: u32,
    pub signature: Signature,
}

impl RelayRequest {
    fn digest(
        run: u64,
        sender: PeerId,
        recipient: PeerId,
        round: u64,
        start_chunk: u32,
    ) -> Message {
        let hash: sha256::Hash = (
            "fedimint/bolt12/mpc-relay/v2",
            (run, sender, recipient),
            (round, start_chunk),
        )
            .consensus_hash();

        Message::from_digest(hash.to_byte_array())
    }

    pub fn new(
        run: u64,
        sender: PeerId,
        recipient: PeerId,
        round: u64,
        start_chunk: u32,
        signing_key: &Keypair,
    ) -> Self {
        let signature = SECP256K1.sign_schnorr(
            &Self::digest(run, sender, recipient, round, start_chunk),
            signing_key,
        );

        Self {
            run,
            sender,
            recipient,
            round,
            start_chunk,
            signature,
        }
    }

    pub fn verify(&self, recipient_pk: &PublicKey) -> bool {
        SECP256K1
            .verify_schnorr(
                &self.signature,
                &Self::digest(
                    self.run,
                    self.sender,
                    self.recipient,
                    self.round,
                    self.start_chunk,
                ),
                &recipient_pk.x_only_public_key().0,
            )
            .is_ok()
    }
}

fn domain(run: u64, sender: PeerId, recipient: PeerId) -> Vec<u8> {
    ("fedimint/bolt12/mpc-channel/v2", run, sender, recipient).consensus_encode_to_vec()
}

fn ephemeral_domain(run: u64, sender: PeerId, recipient: PeerId) -> Vec<u8> {
    ("fedimint/bolt12/mpc-channel-eph/v2", run, sender, recipient).consensus_encode_to_vec()
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

fn ephemeral_aad(run: u64, sender: PeerId, recipient: PeerId, round: u64, chunks: u32) -> Vec<u8> {
    (ephemeral_domain(run, sender, recipient), round, chunks).consensus_encode_to_vec()
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
    /// First accepted Round-0 chunk-0 packet per peer (immutable), binding
    /// each peer to its advertised `recv_ephemeral_pk`.
    r0_packets: BTreeMap<PeerId, BadPacket>,
}

/// This guardian's channels in one run.
pub struct Channels {
    run: u64,
    me: PeerId,
    committee: Vec<PeerId>,
    limits: ChannelLimits,
    /// Per peer: our sender ephemeral secret/public key and Round-0 static-ECDH
    /// symmetric key.
    send_keys: BTreeMap<PeerId, (SecretKey, PublicKey, [u8; 32])>,
    /// Per peer: our recipient ephemeral secret/public key for mutual forward
    /// secrecy on rounds `>= 1`.
    recv_ephemeral: BTreeMap<PeerId, (SecretKey, PublicKey)>,
    transport_secret: SecretKey,
    signing_key: Keypair,
    public_keys: BTreeMap<PeerId, PublicKey>,
    state: Mutex<State>,
    /// Every message received, with its signature, by round and committee
    /// position. Each slot is write-once (immutable after first valid accept).
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
    /// Per-requester concurrency limits for `serve_packets`.
    fetch_sems: BTreeMap<PeerId, Semaphore>,
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
        let mut recv_ephemeral = BTreeMap::new();
        let mut inboxes = BTreeMap::new();
        let mut public_keys = BTreeMap::new();
        let mut relay_sems = BTreeMap::new();
        let mut fetch_sems = BTreeMap::new();

        let fetch_permits = committee
            .len()
            .saturating_mul(MAX_CONCURRENT_RELAY_FETCHES_PER_PEER)
            .max(MIN_CONCURRENT_FETCHES_PER_PEER);

        for peer in committee.iter().filter(|peer| **peer != me) {
            let public = transport_keys
                .get(peer)
                .context("A committee member has no transport key")?;

            let eph = ephemeral_secret(seed, run, me, *peer);
            let eph_pk = eph.public_key(SECP256K1);
            let r0_send_key = transport_key(&eph, public, &domain(run, me, *peer));

            let recv_eph = recipient_ephemeral_secret(seed, run, *peer, me);
            let recv_eph_pk = recv_eph.public_key(SECP256K1);

            send_keys.insert(*peer, (eph, eph_pk, r0_send_key));
            recv_ephemeral.insert(*peer, (recv_eph, recv_eph_pk));
            inboxes.insert(*peer, Inbox::default());
            public_keys.insert(*peer, *public);
            relay_sems.insert(*peer, Semaphore::new(MAX_CONCURRENT_RELAY_FETCHES_PER_PEER));
            fetch_sems.insert(*peer, Semaphore::new(fetch_permits));
        }

        Ok(Arc::new(Self {
            run,
            me,
            committee,
            limits,
            send_keys,
            recv_ephemeral,
            transport_secret: *secret,
            signing_key: Keypair::from_secret_key(SECP256K1, secret),
            public_keys,
            state: Mutex::new(State {
                round: 0,
                inboxes,
                outbox: BTreeMap::new(),
                r0_packets: BTreeMap::new(),
            }),
            transcript: Mutex::new(vec![]),
            relay_missing: Mutex::new(BTreeSet::new()),
            faults: Mutex::new(BTreeMap::new()),
            relay_sems,
            fetch_sems,
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

    /// Relay witnesses, round-0 ephemeral-key proofs, and verifiable transport
    /// faults recorded during this run. Each lock is acquired and released
    /// independently to avoid any lock-order inversion with `receive()`.
    pub fn relay_evidence(&self) -> RelayEvidence {
        let relay_missing = self
            .relay_missing
            .lock()
            .expect("not poisoned")
            .iter()
            .copied()
            .collect();
        let faults = self
            .faults
            .lock()
            .expect("not poisoned")
            .values()
            .cloned()
            .collect();
        let r0_packets = self
            .state
            .lock()
            .expect("not poisoned")
            .r0_packets
            .values()
            .cloned()
            .collect();

        RelayEvidence {
            relay_missing,
            faults,
            r0_packets,
        }
    }

    /// Serve one bounded page of cached encrypted packets this guardian sent
    /// to `recipient` in `round`, after authenticating `request.requester` and
    /// verifying `request.sender == self.me`.
    ///
    /// If `request.start_chunk >= total_chunks`, returns chunk `0` so the
    /// requesting relay receives a cryptographically signed proof of
    /// `total_chunks` and does not mistake an out-of-range requester offset for
    /// sender withholding.
    pub fn serve_packets(&self, request: &FetchRequest) -> Result<(u32, Vec<MpcPacket>)> {
        ensure!(request.run == self.run, "Wrong run");
        ensure!(
            request.sender == self.me,
            "Fetch request is for another sender"
        );
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

        // Verify the requester's signature BEFORE consuming a rate-limit permit
        // so unauthenticated spoofed requests cannot starve an honest relay.
        ensure!(
            request.verify(requester_pk),
            "Fetch request signature is invalid"
        );

        let _permit = self
            .fetch_sems
            .get(&request.requester)
            .context("Requester is not a committee peer")?
            .try_acquire()
            .map_err(|_| anyhow::anyhow!("Fetch rate limit exceeded"))?;

        let state = self.state.lock().expect("not poisoned");
        ensure!(
            request.round <= state.round,
            "Fetch request is for a future round"
        );

        let packets = state
            .outbox
            .get(&(request.recipient, request.round))
            .context("Packets for that round are not available")?;

        let total_chunks = u32::try_from(packets.len()).expect("bounded by MAX_CHUNKS");
        ensure!(total_chunks > 0, "Empty packet cache");

        if request.start_chunk >= total_chunks {
            // Return chunk 0 as a signed proof that `total_chunks <= start_chunk`.
            return Ok((total_chunks, vec![packets[0].clone()]));
        }

        let start = request.start_chunk as usize;
        let end = request
            .start_chunk
            .saturating_add(MAX_CHUNKS_PER_FETCH)
            .min(total_chunks) as usize;

        Ok((total_chunks, packets[start..end].to_vec()))
    }

    fn in_active_round_window(&self, round: u64) -> bool {
        let state = self.state.lock().expect("not poisoned");
        round <= state.round && round >= state.round.saturating_sub(1)
    }

    fn validate_relay_request(&self, request: &RelayRequest) -> Result<PublicKey> {
        ensure!(request.run == self.run, "Wrong run");
        ensure!(
            request.sender != self.me
                && request.recipient != self.me
                && request.sender != request.recipient,
            "Invalid relay endpoints"
        );
        ensure!(
            request.start_chunk < self.limits.chunks,
            "Relay start_chunk exceeds per-run limit"
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

        ensure!(
            self.in_active_round_window(request.round),
            "Relay request is outside the active round window"
        );

        Ok(sender_pk)
    }

    /// Fetch one bounded page of `request.sender`'s encrypted packets for
    /// `request.recipient` in `request.round` and verify their outer
    /// signatures, retrying transient RPC/timeout failures before recording a
    /// `relay_missing` witness.
    pub async fn relay_fetch(
        &self,
        api: &DynModuleApi,
        request: &RelayRequest,
    ) -> Result<(u32, Vec<MpcPacket>)> {
        let sender_pk = self.validate_relay_request(request)?;

        let _permit = self
            .relay_sems
            .get(&request.recipient)
            .context("Recipient is not a committee peer")?
            .acquire()
            .await
            .map_err(|_| anyhow::anyhow!("Relay semaphore closed"))?;

        // Re-check the active round window after waiting on `relay_sems` so a
        // queued request whose round has since aged out of the sender's outbox
        // cannot produce a spurious `relay_missing` witness.
        ensure!(
            self.in_active_round_window(request.round),
            "Relay request aged outside the active round window"
        );

        let fetch_req = FetchRequest::new(
            request.run,
            request.sender,
            self.me,
            request.recipient,
            request.round,
            request.start_chunk,
            &self.signing_key,
        )
        .consensus_encode_to_hex();

        let mut last_err = anyhow::anyhow!("Relay fetch failed");
        let mut validated = Err(anyhow::anyhow!("Relay fetch failed"));

        for attempt in 0..RELAY_FETCH_ATTEMPTS {
            let fetched = fedimint_core::runtime::timeout(
                ATTEMPT_TIMEOUT,
                api.request_single_peer::<PacketPage>(
                    BOLT12_MPC_FETCH_ENDPOINT.to_owned(),
                    ApiRequestErased::new(fetch_req.clone()),
                    request.sender,
                ),
            )
            .await;

            match fetched {
                Ok(Ok(page)) => {
                    validated = validate_relayed_page(
                        self.run,
                        (request.sender, &sender_pk),
                        request.recipient,
                        request.round,
                        request.start_chunk,
                        self.limits.chunks,
                        &page,
                    );
                    break;
                }
                Ok(Err(err)) => last_err = err.into(),
                Err(_) => last_err = anyhow::anyhow!("Relay fetch timed out"),
            }

            if attempt + 1 < RELAY_FETCH_ATTEMPTS {
                sleep(RELAY_FETCH_BACKOFF).await;
            } else {
                validated = Err(last_err);
            }
        }

        match validated {
            Ok(RelayedPage::InRange(total_chunks, packets)) => {
                self.relay_missing.lock().expect("not poisoned").remove(&(
                    request.sender,
                    request.recipient,
                    request.round,
                ));
                Ok((total_chunks, packets))
            }
            Ok(RelayedPage::OutOfRangeProof(proof)) => {
                // Sender proved via a signed chunk-0 envelope that the actual
                // message has <= `request.start_chunk` chunks. Forward the
                // signed chunk-0 proof to the requester (so a recipient can
                // record `ChunkCountConflict` if the sender equivocated across
                // pages) WITHOUT recording `relay_missing`.
                Ok((proof.chunks, vec![*proof]))
            }
            Err(err) => {
                if self.in_active_round_window(request.round)
                    && self.has_received(request.sender, request.round)
                {
                    let mut missing = self.relay_missing.lock().expect("not poisoned");
                    if missing.len() < MAX_RELAY_WITNESSES {
                        missing.insert((request.sender, request.recipient, request.round));
                    }
                }
                Err(err)
            }
        }
    }

    /// Check the sender's signature on a completed message and record it
    /// immutably in `transcript`. Returns `Ok(None)` for an identical duplicate
    /// and records [`TransportFault::MessageEquivocation`] without overwriting
    /// `transcript` if a conflicting signed message arrives for the same round.
    fn accept(&self, sender: PeerId, round: u64, mut payload: Vec<u8>) -> Result<Option<Vec<u8>>> {
        ensure!(payload.len() >= SIGNATURE_LEN, "The message is unsigned");
        ensure!(
            payload.len() <= self.limits.message.saturating_add(SIGNATURE_LEN),
            "The message exceeds the per-run limit"
        );

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

        if let Some(existing) = &transcript[round_index][position] {
            if existing.message == signed.message {
                return Ok(None);
            }
            let first = existing.clone();
            drop(transcript);
            self.record_fault(
                sender,
                TransportFault::MessageEquivocation {
                    round,
                    sender,
                    first,
                    second: signed,
                },
            );
            bail!("Conflicting signed message for the same round");
        }

        transcript[round_index][position] = Some(signed.clone());

        Ok(Some(signed.message))
    }

    fn has_fault(&self, sender: PeerId) -> bool {
        self.faults
            .lock()
            .expect("not poisoned")
            .contains_key(&sender)
    }

    /// Record at most one verifiable transport fault per sender while respecting
    /// the total ciphertext/message byte budget across all stored faults.
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
        let (key, aad_bytes) = if packet.round == 0 {
            (
                transport_key(
                    &self.transport_secret,
                    &packet.ephemeral_pk,
                    &domain(self.run, packet.sender, self.me),
                ),
                aad(
                    self.run,
                    packet.sender,
                    self.me,
                    packet.round,
                    packet.chunks,
                ),
            )
        } else {
            let (recv_eph_sk, _) = self
                .recv_ephemeral
                .get(&packet.sender)
                .context("Not a committee peer")?;
            (
                transport_key(
                    recv_eph_sk,
                    &packet.ephemeral_pk,
                    &ephemeral_domain(self.run, packet.sender, self.me),
                ),
                ephemeral_aad(
                    self.run,
                    packet.sender,
                    self.me,
                    packet.round,
                    packet.chunks,
                ),
            )
        };

        let Ok(plaintext) = ChaCha20Poly1305::new((&key).into()).decrypt(
            Nonce::from_slice(&nonce(packet.round, packet.chunk)),
            Payload {
                msg: &packet.ciphertext,
                aad: &aad_bytes,
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
    /// retry later or give up; duplicates for an already-accepted round are
    /// ignored without mutating `transcript`.
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

        let already_received = self.has_received(packet.sender, packet.round);
        if already_received && self.has_fault(packet.sender) {
            return Ok(());
        }

        if packet.round == 0 && packet.chunk == 0 {
            state
                .r0_packets
                .entry(packet.sender)
                .or_insert_with(|| bad_packet(packet));
        }

        let inbox = state
            .inboxes
            .get_mut(&packet.sender)
            .expect("every peer has an inbox");

        if inbox.complete.contains_key(&packet.round) && self.has_fault(packet.sender) {
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

            let maybe_message = match self.accept(packet.sender, packet.round, payload) {
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

            if let Some(message) = maybe_message {
                state
                    .inboxes
                    .get_mut(&packet.sender)
                    .expect("every peer has an inbox")
                    .complete
                    .insert(packet.round, message);

                drop(state);

                self.arrived.notify_waiters();
            }
        }

        Ok(())
    }

    /// Wait for `sender`'s message in `round`.
    pub(super) async fn take(&self, sender: PeerId, round: u64) -> Vec<u8> {
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
        peer_recv_eph_pk: Option<PublicKey>,
    ) -> Result<Vec<MpcPacket>> {
        ensure!(message.len() <= self.limits.message, "Oversized message");

        let (eph_sk, ephemeral_pk, r0_key) = self
            .send_keys
            .get(&recipient)
            .context("Not a committee peer")?;
        let &(_, our_recv_eph_pk) = self
            .recv_ephemeral
            .get(&recipient)
            .context("Not a committee peer")?;

        let (key, aad_bytes) = if round == 0 {
            (*r0_key, None)
        } else {
            let peer_recv_pk = peer_recv_eph_pk
                .context("Missing peer round-0 ephemeral key for encrypted round >= 1")?;
            (
                transport_key(
                    eph_sk,
                    &peer_recv_pk,
                    &ephemeral_domain(self.run, self.me, recipient),
                ),
                Some(()),
            )
        };
        let cipher = ChaCha20Poly1305::new((&key).into());

        let signature = SECP256K1.sign_schnorr(
            &message_digest(self.run, self.me, recipient, round, message),
            &self.signing_key,
        );

        let mut payload = message.to_vec();

        payload.extend_from_slice(signature.as_ref());

        let chunks: Vec<&[u8]> = payload.chunks(CHUNK).collect();

        let count = u32::try_from(chunks.len()).expect("bounded by MAX_MESSAGE");
        let aad = if aad_bytes.is_some() {
            ephemeral_aad(self.run, self.me, recipient, round, count)
        } else {
            aad(self.run, self.me, recipient, round, count)
        };

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
                        our_recv_eph_pk,
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
                    recv_ephemeral_pk: our_recv_eph_pk,
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

        let peer_recv_pks: BTreeMap<PeerId, PublicKey> = if round == 0 {
            BTreeMap::new()
        } else {
            self.state
                .lock()
                .expect("not poisoned")
                .r0_packets
                .iter()
                .map(|(&peer, pkt)| (peer, pkt.recv_ephemeral_pk))
                .collect()
        };

        let mut per_peer = Vec::with_capacity(self.committee.len().saturating_sub(1));
        let mut packets_to_send = Vec::new();

        for (&peer, message) in self.committee.iter().zip(outgoing) {
            if peer != self.me {
                let built =
                    self.build_packets(peer, round, message, peer_recv_pks.get(&peer).copied())?;
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
        let peer_recv_pk = if round == 0 {
            None
        } else {
            self.state
                .lock()
                .expect("not poisoned")
                .r0_packets
                .get(&recipient)
                .map(|pkt| pkt.recv_ephemeral_pk)
        };
        let packets = self.build_packets(recipient, round, message, peer_recv_pk)?;

        self.state
            .lock()
            .expect("not poisoned")
            .outbox
            .insert((recipient, round), packets.clone());

        Ok(packets)
    }

    fn relay_request(&self, sender: PeerId, round: u64, start_chunk: u32) -> RelayRequest {
        RelayRequest::new(
            self.run,
            sender,
            self.me,
            round,
            start_chunk,
            &self.signing_key,
        )
    }
}

enum RelayedPage {
    InRange(u32, Vec<MpcPacket>),
    /// Sender returned a validly envelope-signed chunk 0 whose `chunks` field
    /// proves `start_chunk >= total_chunks`.
    OutOfRangeProof(Box<MpcPacket>),
}

fn validate_relayed_page(
    run: u64,
    sender: (PeerId, &PublicKey),
    recipient: PeerId,
    round: u64,
    start_chunk: u32,
    max_chunks: u32,
    page: &PacketPage,
) -> Result<RelayedPage> {
    ensure!(
        (1..=max_chunks).contains(&page.total_chunks),
        "Relay returned invalid total_chunks"
    );

    if start_chunk >= page.total_chunks {
        ensure!(
            page.packets.len() == 1,
            "Relay out-of-range proof must carry chunk 0"
        );
        let proof = decode_packet(&page.packets[0])?;
        ensure!(
            proof.run == run
                && proof.sender == sender.0
                && proof.round == round
                && proof.chunk == 0
                && proof.chunks == page.total_chunks
                && verify_packet_envelope(run, sender, recipient, &proof),
            "Relay out-of-range proof failed verification"
        );
        return Ok(RelayedPage::OutOfRangeProof(Box::new(proof)));
    }

    let expected_len = page
        .total_chunks
        .saturating_sub(start_chunk)
        .min(MAX_CHUNKS_PER_FETCH) as usize;
    ensure!(
        page.packets.len() == expected_len,
        "Relay returned unexpected page length"
    );

    let mut packets = Vec::with_capacity(page.packets.len());

    for (offset, hex) in page.packets.iter().enumerate() {
        let packet = decode_packet(hex)?;
        let expected_index =
            start_chunk.saturating_add(u32::try_from(offset).expect("bounded by MAX_CHUNKS"));

        ensure!(
            packet.run == run
                && packet.sender == sender.0
                && packet.round == round
                && packet.chunks == page.total_chunks
                && packet.chunk == expected_index
                && verify_packet_envelope(run, sender, recipient, &packet),
            "Relayed packet failed validation"
        );

        packets.push(packet);
    }

    Ok(RelayedPage::InRange(page.total_chunks, packets))
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

/// Pull all pages of `sender`'s packets for `round` from one relay peer,
/// strictly validating each page before advancing so a malicious relay cannot
/// tarpit the loop with garbage or undersized pages.
async fn pull_from_relay(
    channels: &Channels,
    api: &DynModuleApi,
    relay: PeerId,
    sender: PeerId,
    round: u64,
) {
    let Some(sender_pk) = channels.public_keys.get(&sender) else {
        return;
    };
    let mut start_chunk = 0u32;

    loop {
        let request = channels
            .relay_request(sender, round, start_chunk)
            .consensus_encode_to_hex();

        let response = fedimint_core::runtime::timeout(
            RELAY_PULL_TIMEOUT,
            api.request_single_peer::<PacketPage>(
                BOLT12_MPC_RELAY_ENDPOINT.to_owned(),
                ApiRequestErased::new(request),
                relay,
            ),
        )
        .await;

        let Ok(Ok(page)) = response else {
            return;
        };

        let validated = validate_relayed_page(
            channels.run,
            (sender, sender_pk),
            channels.me,
            round,
            start_chunk,
            channels.limits.chunks,
            &page,
        );

        match validated {
            Ok(RelayedPage::InRange(total_chunks, packets)) => {
                let advanced = u32::try_from(packets.len()).unwrap_or(u32::MAX);
                for packet in &packets {
                    let _ = channels.receive(packet);
                }
                start_chunk = start_chunk.saturating_add(advanced);
                if start_chunk >= total_chunks || channels.has_received(sender, round) {
                    return;
                }
            }
            Ok(RelayedPage::OutOfRangeProof(proof)) => {
                // Feed the signed chunk-0 proof into `channels.receive` so
                // chunk-count equivocation across pages records a fault, then
                // stop pulling from this relay.
                let _ = channels.receive(&proof);
                return;
            }
            Err(_) => {
                // Abort immediately on malformed, unsigned, or undersized
                // pages so a malicious relay cannot tarpit retries.
                return;
            }
        }
    }
}

/// Ask every other committee peer to relay `sender`'s packets for `round`
/// once direct delivery has stalled past `relay_trigger`. Each relay runs its
/// own independent retry loop so one slow or malicious relay cannot block
/// retrying honest relays.
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

    let loops = relays.into_iter().map(|relay| async move {
        loop {
            sleep(relay_trigger).await;
            pull_from_relay(channels, api, relay, sender, round).await;
        }
    });

    join_all(loops).await;
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

//! Private channels between the committee members of a generation run,
//! carried over the guardians' module API.
//!
//! Each message is signed by its sender, so a recipient can later prove what
//! it was sent, then split into chunks, and each chunk is encrypted and
//! authenticated with a key derived from the two guardians' transport keys and
//! bound to the run, the direction, the round and the chunk. Senders retry
//! until the recipient accepts, so a message is delivered once the recipient
//! has reached its round. Recipients keep every message with its signature as
//! evidence in case the run fails.

use std::collections::BTreeMap;
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
use fedimint_lnv2_common::endpoint_constants::BOLT12_MPC_ENDPOINT;
use futures::future::{join_all, try_join_all};
use mpc::engine::Transport;
use tokio::sync::Notify;

use super::keys::transport_key;
use crate::db::SignedMessage;

/// Bytes of the signature appended to each message.
const SIGNATURE_LEN: usize = 64;

/// What a member signs for each message it sends.
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

/// Plaintext bytes per chunk.
pub const CHUNK: usize = 256 * 1024;

/// The largest message a run sends: one peer's share of the double-random
/// batch (`<= MAX_TRIPLES / 2` bytes for a `2f + 1` committee).
const MAX_MESSAGE: usize = mpc::MAX_TRIPLES / 2;

/// The most chunks one message may have.
#[allow(clippy::cast_possible_truncation)] // A small constant.
const MAX_CHUNKS: u32 = (MAX_MESSAGE + SIGNATURE_LEN).div_ceil(CHUNK) as u32;

/// The longest hex-encoded packet the endpoint accepts.
pub const MAX_PACKET_HEX: usize = 2 * (CHUNK + 1024);

/// How long one delivery attempt may take before it is retried.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);

const RETRY_DELAY: Duration = Duration::from_millis(100);

/// One encrypted chunk of a message from `sender` in round `round`.
#[derive(Debug, Clone, Encodable, Decodable)]
pub struct MpcPacket {
    pub run: u64,
    pub sender: PeerId,
    pub round: u64,
    pub chunk: u32,
    pub chunks: u32,
    pub ciphertext: Vec<u8>,
}

fn domain(run: u64, sender: PeerId, recipient: PeerId) -> Vec<u8> {
    ("fedimint/bolt12/mpc-channel/v1", run, sender, recipient).consensus_encode_to_vec()
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

#[derive(Default)]
struct Inbox {
    /// Rounds whose message has fully arrived.
    complete: BTreeMap<u64, Vec<u8>>,
    /// Rounds whose message has partly arrived, by chunk.
    partial: BTreeMap<u64, Vec<Option<Vec<u8>>>>,
}

struct State {
    /// The round this guardian is in. Peers are at most one round ahead.
    round: u64,
    inboxes: BTreeMap<PeerId, Inbox>,
}

/// This guardian's channels in one run.
pub struct Channels {
    run: u64,
    me: PeerId,
    committee: Vec<PeerId>,
    /// Per peer: the key for what we send and the key for what we receive.
    keys: BTreeMap<PeerId, ([u8; 32], [u8; 32])>,
    signing_key: Keypair,
    public_keys: BTreeMap<PeerId, PublicKey>,
    state: Mutex<State>,
    /// Every message received, with its signature, by round and committee
    /// position.
    transcript: Mutex<Vec<Vec<Option<SignedMessage>>>>,
    arrived: Notify,
}

impl Channels {
    pub fn new(
        run: u64,
        me: PeerId,
        committee: Vec<PeerId>,
        secret: &SecretKey,
        transport_keys: &BTreeMap<PeerId, PublicKey>,
    ) -> Result<Arc<Self>> {
        let mut keys = BTreeMap::new();
        let mut inboxes = BTreeMap::new();
        let mut public_keys = BTreeMap::new();

        for peer in committee.iter().filter(|peer| **peer != me) {
            let public = transport_keys
                .get(peer)
                .context("A committee member has no transport key")?;

            keys.insert(
                *peer,
                (
                    transport_key(secret, public, &domain(run, me, *peer)),
                    transport_key(secret, public, &domain(run, *peer, me)),
                ),
            );
            inboxes.insert(*peer, Inbox::default());
            public_keys.insert(*peer, *public);
        }

        Ok(Arc::new(Self {
            run,
            me,
            committee,
            keys,
            signing_key: Keypair::from_secret_key(SECP256K1, secret),
            public_keys,
            state: Mutex::new(State { round: 0, inboxes }),
            transcript: Mutex::new(vec![]),
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

    /// Accept a packet a peer delivered. An error tells the sender to retry
    /// later or give up; a duplicate is accepted again.
    pub fn receive(&self, packet: &MpcPacket) -> Result<()> {
        ensure!(packet.run == self.run, "Wrong run");

        let (_, key) = self
            .keys
            .get(&packet.sender)
            .context("Not a committee peer")?;

        ensure!(
            (1..=MAX_CHUNKS).contains(&packet.chunks) && packet.chunk < packet.chunks,
            "Invalid chunk index"
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

        let plaintext = ChaCha20Poly1305::new(key.into())
            .decrypt(
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
            )
            .ok()
            .context("The packet failed authentication")?;

        ensure!(plaintext.len() <= CHUNK, "Oversized chunk");

        let chunks = inbox
            .partial
            .entry(packet.round)
            .or_insert_with(|| vec![None; packet.chunks as usize]);

        ensure!(
            chunks.len() == packet.chunks as usize,
            "Chunk count changed within a message"
        );

        chunks[packet.chunk as usize] = Some(plaintext);

        if chunks.iter().all(Option::is_some) {
            let payload = inbox
                .partial
                .remove(&packet.round)
                .expect("just inserted")
                .into_iter()
                .flatten()
                .flatten()
                .collect();

            let message = self.accept(packet.sender, packet.round, payload)?;

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

    /// Move to `round`, dropping anything left from earlier rounds.
    fn enter(&self, round: u64) {
        let mut state = self.state.lock().expect("not poisoned");

        state.round = round;

        for inbox in state.inboxes.values_mut() {
            inbox.complete.retain(|r, _| *r >= round);
            inbox.partial.retain(|r, _| *r >= round);
        }
    }

    fn packets(&self, recipient: PeerId, round: u64, message: &[u8]) -> Result<Vec<MpcPacket>> {
        ensure!(message.len() <= MAX_MESSAGE, "Oversized message");

        let (key, _) = self.keys.get(&recipient).context("Not a committee peer")?;
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

                Ok(MpcPacket {
                    run: self.run,
                    sender: self.me,
                    round,
                    chunk: index,
                    chunks: count,
                    ciphertext,
                })
            })
            .collect()
    }
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

/// The engine's view of the channels: committee positions are party indices.
pub struct ApiTransport {
    channels: Arc<Channels>,
    api: DynModuleApi,
}

impl ApiTransport {
    pub fn new(channels: Arc<Channels>, api: DynModuleApi) -> Self {
        Self { channels, api }
    }
}

impl Transport for ApiTransport {
    async fn exchange(&mut self, round: u64, outgoing: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>> {
        let channels = &self.channels;
        let api = &self.api;

        ensure!(
            outgoing.len() == channels.committee.len(),
            "One message per committee member"
        );

        channels.enter(round);

        let mut sends = vec![];

        for (peer, message) in channels.committee.iter().zip(&outgoing) {
            if *peer != channels.me {
                for packet in channels.packets(*peer, round, message)? {
                    sends.push(async move { deliver(api, *peer, &packet).await });
                }
            }
        }

        let receives = channels.committee.iter().map(|peer| async move {
            if *peer == channels.me {
                Ok(Vec::new())
            } else {
                Ok::<_, anyhow::Error>(channels.take(*peer, round).await)
            }
        });

        let (_, incoming) = futures::join!(join_all(sends), try_join_all(receives));

        incoming
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

//! End-to-end tests of `ApiTransport` + `Channels` relay fallback, signed
//! `FetchRequest` / `RelayRequest` endpoints, and relay-witness conviction
//! through `mpc::replay::judge`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::Result;
use fedimint_api_client::api::{
    DynModuleApi, IModuleFederationApi, IRawFederationApi, ServerError, ServerResult,
};
use fedimint_bolt12_common::endpoint_constants::{
    MPC_ENDPOINT, MPC_FETCH_ENDPOINT, MPC_RELAY_ENDPOINT,
};
use fedimint_connectors::{DynGuaridianConnection, PeerStatus};
use fedimint_core::bitcoin::hashes::{Hash as _, sha256};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::encoding::Encodable as _;
use fedimint_core::module::ApiRequestErased;
use fedimint_core::secp256k1::{PublicKey, SECP256K1, SecretKey};
use fedimint_core::util::BoxStream;
use fedimint_core::{PeerId, apply, async_trait_maybe_send};
use mpc::direct;
use mpc::engine::Params;
use mpc::replay::{Evidence, judge};
use rand::rngs::OsRng;

use crate::transport::{
    ApiTransport, ChannelLimits, Channels, PacketPage, decode_fetch_request, decode_packet,
    decode_relay_request,
};

#[derive(Clone)]
struct FaultConfig {
    /// Drop direct `bolt12_mpc` deliveries from `from` to `to`.
    block_direct: Option<(PeerId, PeerId)>,
    /// Refuse `bolt12_mpc_fetch` on `sender` when asked for `recipient`'s
    /// packets (simulating a malicious silent 1-on-1 attacker refusing relays).
    refuse_fetch: Option<(PeerId, PeerId)>,
}

struct RelayMeshApi {
    peers: BTreeSet<PeerId>,
    channels: BTreeMap<PeerId, Arc<Channels>>,
    fault: FaultConfig,
    relay_hits: Arc<AtomicU64>,
    fetch_hits: Arc<AtomicU64>,
}

impl std::fmt::Debug for RelayMeshApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayMeshApi").finish_non_exhaustive()
    }
}

#[allow(clippy::needless_pass_by_value)]
fn api_err(msg: impl std::fmt::Display) -> ServerError {
    ServerError::Connection(Box::new(std::io::Error::other(msg.to_string())))
}

#[apply(async_trait_maybe_send!)]
impl IRawFederationApi for RelayMeshApi {
    fn all_peers(&self) -> &BTreeSet<PeerId> {
        &self.peers
    }

    fn self_peer(&self) -> Option<PeerId> {
        None
    }

    fn with_module(&self, _id: ModuleInstanceId) -> DynModuleApi {
        unreachable!("already a module api")
    }

    async fn request_raw(
        &self,
        peer_id: PeerId,
        method: &str,
        params: &ApiRequestErased,
    ) -> ServerResult<serde_json::Value> {
        let target = self
            .channels
            .get(&peer_id)
            .ok_or(ServerError::InvalidPeerId { peer_id })?;

        let hex: String = serde_json::from_value(params.params.clone()).map_err(api_err)?;

        match method {
            MPC_ENDPOINT => {
                let packet = decode_packet(&hex).map_err(api_err)?;
                if self.fault.block_direct == Some((packet.sender, peer_id)) {
                    return Err(api_err("direct link blocked"));
                }
                target.receive(&packet).map_err(api_err)?;
                Ok(serde_json::Value::Null)
            }
            MPC_FETCH_ENDPOINT => {
                self.fetch_hits.fetch_add(1, Ordering::Relaxed);
                let req = decode_fetch_request(&hex).map_err(api_err)?;
                if self.fault.refuse_fetch == Some((peer_id, req.recipient)) {
                    return Err(api_err("malicious sender refused relay fetch"));
                }
                let (total_chunks, packets) = target.serve_packets(&req).map_err(api_err)?;
                let encoded = PacketPage {
                    total_chunks,
                    packets: packets
                        .into_iter()
                        .map(|p| p.consensus_encode_to_hex())
                        .collect(),
                };
                serde_json::to_value(encoded).map_err(api_err)
            }
            MPC_RELAY_ENDPOINT => {
                self.relay_hits.fetch_add(1, Ordering::Relaxed);
                let req = decode_relay_request(&hex).map_err(api_err)?;
                let self_api: DynModuleApi = Self {
                    peers: self.peers.clone(),
                    channels: self.channels.clone(),
                    fault: self.fault.clone(),
                    relay_hits: self.relay_hits.clone(),
                    fetch_hits: self.fetch_hits.clone(),
                }
                .into();
                let (total_chunks, packets) =
                    target.relay_fetch(&self_api, &req).await.map_err(api_err)?;
                let encoded = PacketPage {
                    total_chunks,
                    packets: packets
                        .into_iter()
                        .map(|p| p.consensus_encode_to_hex())
                        .collect(),
                };
                serde_json::to_value(encoded).map_err(api_err)
            }
            other => Err(api_err(format!("unexpected method {other}"))),
        }
    }

    fn connection_status_stream(&self) -> BoxStream<'static, BTreeMap<PeerId, PeerStatus>> {
        Box::pin(futures::stream::empty())
    }

    async fn wait_for_initialized_connections(&self) {}

    async fn get_peer_connection(&self, peer_id: PeerId) -> ServerResult<DynGuaridianConnection> {
        Err(ServerError::InvalidPeerId { peer_id })
    }
}

impl IModuleFederationApi for RelayMeshApi {}

struct Setup {
    committee: Vec<PeerId>,
    seeds: Vec<[u8; 32]>,
    channels: BTreeMap<PeerId, Arc<Channels>>,
    api: DynModuleApi,
    relay_hits: Arc<AtomicU64>,
    fetch_hits: Arc<AtomicU64>,
}

fn setup_mesh(fault: FaultConfig) -> Result<Setup> {
    let committee: Vec<PeerId> = (0..3u16).map(PeerId::from).collect();
    let secrets: Vec<SecretKey> = (0..3).map(|_| SecretKey::new(&mut OsRng)).collect();
    let keys: BTreeMap<PeerId, PublicKey> = (0..3u16)
        .map(|p| {
            (
                PeerId::from(p),
                secrets[usize::from(p)].public_key(SECP256K1),
            )
        })
        .collect();
    let seeds = vec![[1u8; 32], [2u8; 32], [3u8; 32]];

    let limits = ChannelLimits::for_run(3, 1, 1);
    let mut channels = BTreeMap::new();
    for (idx, &peer) in committee.iter().enumerate() {
        channels.insert(
            peer,
            Channels::new(
                0,
                peer,
                committee.clone(),
                limits,
                &seeds[idx],
                &secrets[idx],
                &keys,
            )?,
        );
    }

    let relay_hits = Arc::new(AtomicU64::new(0));
    let fetch_hits = Arc::new(AtomicU64::new(0));
    let api: DynModuleApi = RelayMeshApi {
        peers: committee.iter().copied().collect(),
        channels: channels.clone(),
        fault,
        relay_hits: relay_hits.clone(),
        fetch_hits: fetch_hits.clone(),
    }
    .into();

    Ok(Setup {
        committee,
        seeds,
        channels,
        api,
        relay_hits,
        fetch_hits,
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn api_transport_relay_recovers_blocked_direct_link_for_full_mpc_run() -> Result<()> {
    // Permanently block direct delivery 0 -> 1 across all 989 rounds.
    // Peer 1 must pull every packet from Peer 0 via Peer 2's authenticated
    // relay -> fetch path, and all 3 parties must complete the full SHA-256
    // MPC run and produce a valid recoverable preimage.
    let setup = setup_mesh(FaultConfig {
        block_direct: Some((PeerId::from(0), PeerId::from(1))),
        refuse_fetch: None,
    })?;

    let params = Params::new(3, 1)?;
    let circuit = Arc::new(direct::circuit(params, 1)?);
    let context = b"relay-recovery-e2e";

    let tasks: Vec<_> = setup
        .committee
        .iter()
        .enumerate()
        .map(|(party, &peer)| {
            let ch = setup.channels[&peer].clone();
            let api = setup.api.clone();
            let circuit = circuit.clone();
            let seed = setup.seeds[party];

            tokio::spawn(async move {
                let mut transport =
                    ApiTransport::with_relay_trigger(ch, api, Duration::from_millis(20));
                let out =
                    direct::generate(&mut transport, params, party, 1, &circuit, &seed, context)
                        .await?;
                transport.flush().await;
                Ok::<_, anyhow::Error>(out)
            })
        })
        .collect();

    let mut generated = Vec::with_capacity(3);
    for task in tasks {
        generated.push(task.await??);
    }

    let payment_hash = generated[0][0].payment_hash;
    assert_eq!(generated[1][0].payment_hash, payment_hash);
    assert_eq!(generated[2][0].payment_hash, payment_hash);

    let shares: Vec<_> = generated
        .iter()
        .map(|g| direct::Share::new(g[0].share.party(), *g[0].share.value()))
        .collect();
    let recovered = direct::reconstruct(&payment_hash, 2, &shares)?;
    assert_eq!(
        sha256::Hash::hash(&recovered.preimage).to_byte_array(),
        payment_hash
    );
    assert_eq!(recovered.rejected, Vec::<usize>::new());

    assert!(setup.relay_hits.load(Ordering::Relaxed) > 0);
    assert!(setup.fetch_hits.load(Ordering::Relaxed) > 0);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn api_transport_relay_witnesses_convict_silent_sender_end_to_end() -> Result<()> {
    // Peer 0 silently drops direct packets to Peer 1 AND refuses relay fetch
    // requests for Peer 1. Peer 2 witnesses `(0, 1, 0)` missing, and
    // `mpc::replay::judge` convicts Peer 0 as a culprit with zero disputes.
    let setup = setup_mesh(FaultConfig {
        block_direct: Some((PeerId::from(0), PeerId::from(1))),
        refuse_fetch: Some((PeerId::from(0), PeerId::from(1))),
    })?;

    let params = Params::new(3, 1)?;
    let circuit = Arc::new(direct::circuit(params, 1)?);
    let context = b"relay-convict-e2e";

    let tasks: Vec<_> = setup
        .committee
        .iter()
        .enumerate()
        .map(|(party, &peer)| {
            let ch = setup.channels[&peer].clone();
            let api = setup.api.clone();
            let circuit = circuit.clone();
            let seed = setup.seeds[party];

            tokio::spawn(async move {
                let mut transport =
                    ApiTransport::with_relay_trigger(ch, api, Duration::from_millis(20));
                let _ =
                    direct::generate(&mut transport, params, party, 1, &circuit, &seed, context)
                        .await;
            })
        })
        .collect();

    // Wait until all honest round-0 deliveries have settled, Peer 1 is stalled
    // solely on Peer 0, and Peer 2 has witnessed Peer 0 refusing the relay
    // fetch (robust against slow debug CPU contention).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let ch0 = &setup.channels[&PeerId::from(0)];
    let ch1 = &setup.channels[&PeerId::from(1)];
    let ch2 = &setup.channels[&PeerId::from(2)];
    let has_round0 = |ch: &Arc<Channels>, sender: usize| {
        ch.transcript()
            .first()
            .and_then(|row| row.get(sender))
            .is_some_and(Option::is_some)
    };
    while setup.fetch_hits.load(Ordering::Relaxed) == 0
        || ch2.relay_evidence().relay_missing.is_empty()
        || !has_round0(ch0, 1)
        || !has_round0(ch0, 2)
        || !has_round0(ch1, 2)
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for relay witness"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    for task in tasks {
        task.abort();
        let _ = task.await;
    }

    assert!(setup.relay_hits.load(Ordering::Relaxed) > 0);
    assert!(setup.fetch_hits.load(Ordering::Relaxed) > 0);

    // Build `mpc::replay::Evidence` from each member's real Channels transcript
    // and relay_evidence, just as `worker::verdict` does.
    let evidence: Vec<Option<Evidence>> = setup
        .committee
        .iter()
        .enumerate()
        .map(|(idx, &peer)| {
            let ch = &setup.channels[&peer];
            let received = ch
                .transcript()
                .into_iter()
                .map(|row| {
                    row.into_iter()
                        .map(|opt| opt.map(|signed| signed.message))
                        .collect()
                })
                .collect();
            let relay_missing = ch
                .relay_evidence()
                .relay_missing
                .into_iter()
                .map(|(s, r, round)| (usize::from(u16::from(s)), usize::from(u16::from(r)), round))
                .collect();
            Some(Evidence {
                seed: setup.seeds[idx],
                received,
                relay_missing,
            })
        })
        .collect();

    let verdict = judge(params, 1, &circuit, context, &evidence, &[false; 3]).await?;
    assert_eq!(verdict.culprits.into_iter().collect::<Vec<_>>(), vec![0]);
    assert!(verdict.disputes.is_empty());

    Ok(())
}

#[tokio::test]
async fn relay_fetch_rejects_premature_framing_and_clears_recovered_witness() -> Result<()> {
    use fedimint_core::secp256k1::Keypair;

    use crate::transport::RelayRequest;

    let committee: Vec<PeerId> = (0..3u16).map(PeerId::from).collect();
    let secrets: Vec<SecretKey> = (0..3).map(|_| SecretKey::new(&mut OsRng)).collect();
    let keys: BTreeMap<PeerId, PublicKey> = (0..3u16)
        .map(|p| {
            (
                PeerId::from(p),
                secrets[usize::from(p)].public_key(SECP256K1),
            )
        })
        .collect();
    let seeds = [[1u8; 32], [2u8; 32], [3u8; 32]];

    let limits = ChannelLimits::for_run(3, 1, 4);
    let ch0 = Channels::new(
        0,
        PeerId::from(0),
        committee.clone(),
        limits,
        &seeds[0],
        &secrets[0],
        &keys,
    )?;
    let ch1 = Channels::new(
        0,
        PeerId::from(1),
        committee.clone(),
        limits,
        &seeds[1],
        &secrets[1],
        &keys,
    )?;
    let ch2 = Channels::new(
        0,
        PeerId::from(2),
        committee.clone(),
        limits,
        &seeds[2],
        &secrets[2],
        &keys,
    )?;

    let mut channels = BTreeMap::new();
    channels.insert(PeerId::from(0), ch0.clone());
    channels.insert(PeerId::from(1), ch1);
    channels.insert(PeerId::from(2), ch2.clone());

    let failing_api: DynModuleApi = RelayMeshApi {
        peers: committee.iter().copied().collect(),
        channels: channels.clone(),
        fault: FaultConfig {
            block_direct: None,
            refuse_fetch: Some((PeerId::from(0), PeerId::from(1))),
        },
        relay_hits: Arc::new(AtomicU64::new(0)),
        fetch_hits: Arc::new(AtomicU64::new(0)),
    }
    .into();

    let signer1 = Keypair::from_secret_key(SECP256K1, &secrets[1]);

    // 1. Future round (round 1 while relay ch2 is on round 0) is rejected
    // without recording a witness.
    let future_req = RelayRequest::new(0, PeerId::from(0), PeerId::from(1), 1, 0, &signer1);
    assert!(ch2.relay_fetch(&failing_api, &future_req).await.is_err());
    assert_eq!(ch2.relay_evidence().relay_missing, vec![]);

    // 2. Round 0 BEFORE relay ch2 has received peer 0's round-0 message does
    // NOT record a witness (prevents rushing-adversary framing).
    let req0 = RelayRequest::new(0, PeerId::from(0), PeerId::from(1), 0, 0, &signer1);
    assert!(ch2.relay_fetch(&failing_api, &req0).await.is_err());
    assert_eq!(ch2.relay_evidence().relay_missing, vec![]);

    // 3. Once ch0 has published round 0 and ch2 has received ch0's round-0
    // message, a refused fetch DOES record `(0, 1, 0)`.
    let sent = ch0.enter_with_outgoing(0, &[vec![], b"to-1".to_vec(), b"to-2".to_vec()])?;
    for (peer, pkt) in &sent {
        if *peer == PeerId::from(2) {
            ch2.receive(pkt)?;
        }
    }
    assert!(ch2.relay_fetch(&failing_api, &req0).await.is_err());
    assert_eq!(
        ch2.relay_evidence().relay_missing,
        vec![(PeerId::from(0), PeerId::from(1), 0)]
    );

    // 4. A subsequent successful fetch clears the stale `relay_missing` entry.
    let healthy_api: DynModuleApi = RelayMeshApi {
        peers: committee.iter().copied().collect(),
        channels,
        fault: FaultConfig {
            block_direct: None,
            refuse_fetch: None,
        },
        relay_hits: Arc::new(AtomicU64::new(0)),
        fetch_hits: Arc::new(AtomicU64::new(0)),
    }
    .into();
    assert!(ch2.relay_fetch(&healthy_api, &req0).await.is_ok());
    assert_eq!(ch2.relay_evidence().relay_missing, vec![]);

    // 5. An out-of-range `start_chunk` (within `limits.chunks` but >= actual
    // `total_chunks = 1`) must return the sender's signed chunk-0 proof
    // WITHOUT recording `relay_missing` against honest sender 0 (preventing
    // f = 1 framing while still surfacing any chunk-count equivocation).
    let oob_req = RelayRequest::new(0, PeerId::from(0), PeerId::from(1), 0, 1, &signer1);
    let (proof_total, proof_packets) = ch2.relay_fetch(&healthy_api, &oob_req).await?;
    assert_eq!(proof_total, 1);
    assert_eq!(proof_packets.len(), 1);
    assert_eq!(proof_packets[0].chunk, 0);
    assert_eq!(proof_packets[0].chunks, 1);
    assert_eq!(
        ch2.relay_evidence().relay_missing,
        vec![],
        "out-of-range start_chunk must never frame an honest sender"
    );

    Ok(())
}

struct TarpitMeshApi {
    peers: BTreeSet<PeerId>,
    channels: BTreeMap<PeerId, Arc<Channels>>,
    honest_relay_calls: Arc<AtomicU64>,
}

impl std::fmt::Debug for TarpitMeshApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TarpitMeshApi").finish_non_exhaustive()
    }
}

#[apply(async_trait_maybe_send!)]
impl IRawFederationApi for TarpitMeshApi {
    fn all_peers(&self) -> &BTreeSet<PeerId> {
        &self.peers
    }

    fn self_peer(&self) -> Option<PeerId> {
        None
    }

    fn with_module(&self, _id: ModuleInstanceId) -> DynModuleApi {
        unreachable!("already a module api")
    }

    async fn request_raw(
        &self,
        peer_id: PeerId,
        method: &str,
        params: &ApiRequestErased,
    ) -> ServerResult<serde_json::Value> {
        let target = self
            .channels
            .get(&peer_id)
            .ok_or(ServerError::InvalidPeerId { peer_id })?;
        let hex: String = serde_json::from_value(params.params.clone()).map_err(api_err)?;

        match method {
            MPC_ENDPOINT => {
                let packet = decode_packet(&hex).map_err(api_err)?;
                if packet.sender == PeerId::from(0) && peer_id == PeerId::from(1) {
                    return Err(api_err("direct 0 -> 1 blocked"));
                }
                target.receive(&packet).map_err(api_err)?;
                Ok(serde_json::Value::Null)
            }
            MPC_FETCH_ENDPOINT => {
                let req = decode_fetch_request(&hex).map_err(api_err)?;
                let (total_chunks, packets) = target.serve_packets(&req).map_err(api_err)?;
                let encoded = PacketPage {
                    total_chunks,
                    packets: packets
                        .into_iter()
                        .map(|p| p.consensus_encode_to_hex())
                        .collect(),
                };
                serde_json::to_value(encoded).map_err(api_err)
            }
            MPC_RELAY_ENDPOINT => {
                if peer_id == PeerId::from(2) {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    let garbage = PacketPage {
                        total_chunks: 10,
                        packets: vec![String::new()],
                    };
                    return serde_json::to_value(garbage).map_err(api_err);
                }
                if peer_id == PeerId::from(3)
                    && self.honest_relay_calls.fetch_add(1, Ordering::Relaxed) == 0
                {
                    return Err(api_err("honest relay not yet in round"));
                }
                let req = decode_relay_request(&hex).map_err(api_err)?;
                let self_api: DynModuleApi = Self {
                    peers: self.peers.clone(),
                    channels: self.channels.clone(),
                    honest_relay_calls: self.honest_relay_calls.clone(),
                }
                .into();
                let (total_chunks, packets) =
                    target.relay_fetch(&self_api, &req).await.map_err(api_err)?;
                let encoded = PacketPage {
                    total_chunks,
                    packets: packets
                        .into_iter()
                        .map(|p| p.consensus_encode_to_hex())
                        .collect(),
                };
                serde_json::to_value(encoded).map_err(api_err)
            }
            other => Err(api_err(format!("unexpected method {other}"))),
        }
    }

    fn connection_status_stream(&self) -> BoxStream<'static, BTreeMap<PeerId, PeerStatus>> {
        Box::pin(futures::stream::empty())
    }

    async fn wait_for_initialized_connections(&self) {}

    async fn get_peer_connection(&self, peer_id: PeerId) -> ServerResult<DynGuaridianConnection> {
        Err(ServerError::InvalidPeerId { peer_id })
    }
}

impl IModuleFederationApi for TarpitMeshApi {}

#[tokio::test(flavor = "multi_thread")]
async fn tarpitting_relay_does_not_block_honest_relay_recovery() -> Result<()> {
    // 4-peer committee [0, 1, 2, 3]: direct 0 -> 1 is blocked, leaving relays
    // 2 and 3. Malicious relay 2 sleeps 2s and returns a malformed undersized
    // PacketPage on every call; honest relay 3 rejects the first call (as if
    // still one round behind) and succeeds on the second. Independent per-relay
    // loops must let Peer 1 recover via relay 3 in well under 1s instead of
    // blocking behind relay 2's tarpit.
    use mpc::engine::Transport as _;

    let committee: Vec<PeerId> = (0..4u16).map(PeerId::from).collect();
    let secrets: Vec<SecretKey> = (0..4).map(|_| SecretKey::new(&mut OsRng)).collect();
    let keys: BTreeMap<PeerId, PublicKey> = (0..4u16)
        .map(|p| {
            (
                PeerId::from(p),
                secrets[usize::from(p)].public_key(SECP256K1),
            )
        })
        .collect();
    let limits = ChannelLimits {
        message: 4096,
        chunks: 16,
        fault_bytes: 65_536,
    };
    let channels: BTreeMap<PeerId, Arc<Channels>> = committee
        .iter()
        .enumerate()
        .map(|(i, &peer)| {
            Ok((
                peer,
                Channels::new(
                    0,
                    peer,
                    committee.clone(),
                    limits,
                    &[u8::try_from(i)?; 32],
                    &secrets[i],
                    &keys,
                )?,
            ))
        })
        .collect::<Result<_>>()?;
    let honest_relay_calls = Arc::new(AtomicU64::new(0));
    let api: DynModuleApi = TarpitMeshApi {
        peers: committee.iter().copied().collect(),
        channels: channels.clone(),
        honest_relay_calls: honest_relay_calls.clone(),
    }
    .into();

    let start = tokio::time::Instant::now();
    let tasks: Vec<_> = committee
        .iter()
        .enumerate()
        .map(|(i, &peer)| {
            let ch = channels[&peer].clone();
            let api = api.clone();
            tokio::spawn(async move {
                let mut transport =
                    ApiTransport::with_relay_trigger(ch, api, Duration::from_millis(20));
                let outgoing: Vec<Vec<u8>> = (0..4)
                    .map(|j| {
                        if j == i {
                            vec![]
                        } else {
                            format!("m-{i}-{j}").into_bytes()
                        }
                    })
                    .collect();
                let incoming = transport.exchange(0, outgoing).await?;
                Ok::<_, anyhow::Error>(incoming)
            })
        })
        .collect();

    let results = tokio::time::timeout(Duration::from_secs(1), async {
        let mut out = Vec::with_capacity(4);
        for task in tasks {
            out.push(task.await??);
        }
        Ok::<_, anyhow::Error>(out)
    })
    .await
    .map_err(|_| anyhow::anyhow!("tarpitting relay blocked honest relay recovery past 1s"))??;

    assert_eq!(results[1][0], b"m-0-1");
    assert!(
        honest_relay_calls.load(Ordering::Relaxed) >= 2,
        "honest relay 3 must have been retried independently of relay 2"
    );
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "recovery took {:?}",
        start.elapsed()
    );

    Ok(())
}

struct DeliverOnFinalAttemptApi {
    peers: BTreeSet<PeerId>,
    ch0: Arc<Channels>,
    ch2: Arc<Channels>,
    attempts: Arc<AtomicU64>,
}

impl std::fmt::Debug for DeliverOnFinalAttemptApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeliverOnFinalAttemptApi")
            .finish_non_exhaustive()
    }
}

#[apply(async_trait_maybe_send!)]
impl IRawFederationApi for DeliverOnFinalAttemptApi {
    fn all_peers(&self) -> &BTreeSet<PeerId> {
        &self.peers
    }

    fn self_peer(&self) -> Option<PeerId> {
        None
    }

    fn with_module(&self, _id: ModuleInstanceId) -> DynModuleApi {
        unreachable!("already a module api")
    }

    async fn request_raw(
        &self,
        _peer_id: PeerId,
        method: &str,
        _params: &ApiRequestErased,
    ) -> ServerResult<serde_json::Value> {
        if method == MPC_FETCH_ENDPOINT
            && self.attempts.fetch_add(1, Ordering::Relaxed) == 2
            && let Ok(sent) = self
                .ch0
                .enter_with_outgoing(0, &[vec![], b"to-1".to_vec(), b"to-2".to_vec()])
        {
            for (peer, pkt) in &sent {
                if *peer == PeerId::from(2) {
                    let _ = self.ch2.receive(pkt);
                }
            }
        }
        Err(api_err("sender had not published yet"))
    }

    fn connection_status_stream(&self) -> BoxStream<'static, BTreeMap<PeerId, PeerStatus>> {
        Box::pin(futures::stream::empty())
    }

    async fn wait_for_initialized_connections(&self) {}

    async fn get_peer_connection(&self, peer_id: PeerId) -> ServerResult<DynGuaridianConnection> {
        Err(ServerError::InvalidPeerId { peer_id })
    }
}

impl IModuleFederationApi for DeliverOnFinalAttemptApi {}

#[tokio::test(flavor = "multi_thread")]
async fn pre_publication_relay_fetch_failure_never_records_witness() -> Result<()> {
    // Regression: if `sender` publishes and delivers round 0 to relay `ch2`
    // *during* the final failing pre-publication upstream fetch, `ch2` MUST NOT
    // record a `relay_missing` witness because `observed_before_attempt` was
    // false when that attempt was initiated.
    let committee: Vec<PeerId> = (0..3u16).map(PeerId::from).collect();
    let secrets: Vec<SecretKey> = (0..3).map(|_| SecretKey::new(&mut OsRng)).collect();
    let keys: BTreeMap<PeerId, PublicKey> = (0..3u16)
        .map(|p| {
            (
                PeerId::from(p),
                secrets[usize::from(p)].public_key(SECP256K1),
            )
        })
        .collect();
    let limits = ChannelLimits {
        message: 4096,
        chunks: 8,
        fault_bytes: 65_536,
    };
    let ch0 = Channels::new(
        0,
        PeerId::from(0),
        committee.clone(),
        limits,
        &[0; 32],
        &secrets[0],
        &keys,
    )?;
    let ch2 = Channels::new(
        0,
        PeerId::from(2),
        committee.clone(),
        limits,
        &[2; 32],
        &secrets[2],
        &keys,
    )?;
    let signer1 = fedimint_core::secp256k1::Keypair::from_secret_key(SECP256K1, &secrets[1]);
    let req0 =
        crate::transport::RelayRequest::new(0, PeerId::from(0), PeerId::from(1), 0, 0, &signer1);

    let api: DynModuleApi = DeliverOnFinalAttemptApi {
        peers: committee.iter().copied().collect(),
        ch0,
        ch2: ch2.clone(),
        attempts: Arc::new(AtomicU64::new(0)),
    }
    .into();

    assert!(ch2.relay_fetch(&api, &req0).await.is_err());
    assert!(
        ch2.has_received(PeerId::from(0), 0),
        "sender delivered during the final pre-publication attempt"
    );
    assert_eq!(
        ch2.relay_evidence().relay_missing,
        vec![],
        "pre-publication fetch failure must never record a withholding witness"
    );

    Ok(())
}

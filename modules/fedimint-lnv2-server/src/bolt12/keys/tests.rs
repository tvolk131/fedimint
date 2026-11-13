use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use bls12_381::{G1Projective, G2Projective, Scalar};
use fedimint_core::{NumPeers, PeerId};
use fedimint_lnv2_common::bolt12::quorum;
use fedimint_server_core::config::PeerHandleOps;
use frost_secp256k1_tr as frost;
use tokio::sync::{Mutex, Notify};

use super::{fixture, generate, signing_key};

/// The exchange round carrying encrypted round-two packages: transport keys,
/// their echo, round one, its echo, then round two.
const ROUND_TWO: u64 = 4;

/// An in-memory stand-in for the setup ceremony's all-to-all exchange. It
/// keeps every byte that crossed the wire.
struct Exchange {
    guardians: usize,
    wire: Mutex<BTreeMap<(u64, PeerId), Vec<u8>>>,
    notify: Notify,
}

struct Peer {
    id: PeerId,
    round: AtomicU64,
    exchange: Arc<Exchange>,
}

#[async_trait::async_trait]
impl PeerHandleOps for Peer {
    fn num_peers(&self) -> NumPeers {
        NumPeers::from(self.exchange.guardians)
    }

    async fn run_dkg_g1(&self) -> Result<(Vec<G1Projective>, Scalar)> {
        anyhow::bail!("unused")
    }

    async fn run_dkg_g2(&self) -> Result<(Vec<G2Projective>, Scalar)> {
        anyhow::bail!("unused")
    }

    async fn exchange_bytes(&self, bytes: Vec<u8>) -> Result<BTreeMap<PeerId, Vec<u8>>> {
        let round = self.round.fetch_add(1, Ordering::SeqCst);

        self.exchange
            .wire
            .lock()
            .await
            .insert((round, self.id), bytes);
        self.exchange.notify.notify_waiters();

        loop {
            let notified = self.exchange.notify.notified();

            let received = self
                .exchange
                .wire
                .lock()
                .await
                .iter()
                .filter(|((r, _), _)| *r == round)
                .map(|((_, peer), bytes)| (*peer, bytes.clone()))
                .collect::<BTreeMap<_, _>>();

            if received.len() == self.exchange.guardians {
                return Ok(received);
            }

            notified.await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn distributed_generation_agrees_on_a_quorum_key_and_encrypts_secret_shares() -> Result<()> {
    for guardians in [4, 7, 10] {
        let exchange = Arc::new(Exchange {
            guardians,
            wire: Mutex::new(BTreeMap::new()),
            notify: Notify::new(),
        });

        let mut jobs = tokio::task::JoinSet::new();

        for peer in 0..guardians {
            let peer = Peer {
                id: PeerId::from(u16::try_from(peer)?),
                round: AtomicU64::new(0),
                exchange: exchange.clone(),
            };

            jobs.spawn(async move { generate(&peer).await });
        }

        let mut configs = Vec::new();

        while let Some(result) = jobs.join_next().await {
            configs.push(result??);
        }

        assert_eq!(configs.len(), guardians);
        assert!(configs.iter().all(|(public, _)| *public == configs[0].0));

        let public = frost::keys::PublicKeyPackage::deserialize(&configs[0].0.public_package)?;

        assert_eq!(configs[0].0.transport_keys.len(), guardians);
        assert!(signing_key(&configs[0].0).is_ok());

        for (_, private) in &configs {
            let key = frost::keys::KeyPackage::deserialize(&private.key_package)?;

            assert_eq!(key.verifying_key(), public.verifying_key());
            assert_eq!(usize::from(*key.min_signers()), quorum(guardians));
        }

        // Secret shares only ever cross the wire as authenticated ciphertexts.
        for ((round, _), wire) in exchange.wire.lock().await.iter() {
            if *round == ROUND_TWO {
                let packages: Vec<serde_json::Value> = serde_json::from_slice(wire)?;

                assert_eq!(packages.len(), guardians - 1);
                assert!(packages.iter().all(|package| {
                    package.get("ciphertext").is_some() && package.get("nonce").is_some()
                }));
                assert!(frost::keys::dkg::round2::Package::deserialize(wire).is_err());
            }
        }
    }

    Ok(())
}

#[test]
fn fewer_than_four_guardians_are_rejected() {
    let peers: Vec<PeerId> = (0..3).map(PeerId::from).collect();

    assert!(fixture(&peers).is_err());
}

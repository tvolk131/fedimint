//! Federated BOLT12 receives against a real four-guardian test federation.
//!
//! The test plays the gateway by hand: it reserves, coordinates signing and
//! funds through the same consensus and guardian APIs a gateway uses. No
//! Lightning node is involved; the gateway's Lightning integration is covered
//! separately.

use std::sync::Once;
use std::time::Duration;

use anyhow::{Context as _, Result, ensure};
use bitcoin::hashes::{Hash as _, sha256};
use fedimint_api_client::api::{DynModuleApi, FederationApiExt as _};
use fedimint_bolt12_client::api::Bolt12FederationApi as _;
use fedimint_bolt12_client::offers::Bolt12OfferParams;
use fedimint_bolt12_client::{Bolt12ClientInit, Bolt12ClientModule};
use fedimint_bolt12_common::Bolt12Output;
use fedimint_bolt12_common::endpoint_constants::{
    DECRYPTION_SHARES_ENDPOINT, MPC_FETCH_ENDPOINT, MPC_RELAY_ENDPOINT, NEXT_POOL_ENDPOINT,
    SET_GATEWAY_VOTE_ENDPOINT,
};
use fedimint_bolt12_common::gateway_api::PaymentFee;
use fedimint_bolt12_common::invoice::{encode_payment_path, parse_routing_metadata};
use fedimint_bolt12_common::protocol::{
    Bolt12OutputV0, INVOICE_LIFETIME, Registration, RegistrationId, Reservation, Reserve, Source,
    terms_hash,
};
use fedimint_bolt12_server::Bolt12Init;
use fedimint_client::secret::{PlainRootSecretStrategy, RootSecretStrategy as _};
use fedimint_client::transaction::{ClientOutput, ClientOutputBundle, TransactionBuilder};
use fedimint_client::{ClientHandleArc, RootSecret};
use fedimint_client_module::module::ClientModule as _;
use fedimint_core::core::{IntoDynInstance as _, OperationId};
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::module::{AmountUnit, Amounts, ApiAuth, ApiRequestErased};
use fedimint_core::secp256k1::{Keypair, PublicKey, SECP256K1, SecretKey};
use fedimint_core::time::duration_since_epoch;
use fedimint_core::util::{backoff_util, retry};
use fedimint_core::{Amount, OutPoint, PeerId, sats};
use fedimint_dummy_client::{DummyClientInit, DummyClientModule};
use fedimint_dummy_server::DummyInit;
use fedimint_gw_bolt12_client::signing::{SigningJob, sign_invoice};
use fedimint_testing::federation::FederationTest;
use fedimint_testing::fixtures::Fixtures;
use lightning::blinded_path::message::{BlindedMessagePath, MessageContext, OffersContext};
use lightning::blinded_path::payment::{
    BlindedPaymentPath, Bolt12OfferContext, PaymentConstraints, PaymentContext,
    UnauthenticatedReceiveTlvs,
};
use lightning::ln::channelmanager::PaymentId;
use lightning::ln::inbound_payment::ExpandedKey;
use lightning::offers::invoice::Bolt12Invoice;
use lightning::offers::invoice_request::{InvoiceRequest, InvoiceRequestFields};
use lightning::offers::nonce::Nonce;
use lightning::offers::offer::Offer;
use lightning::sign::{EntropySource, ReceiveAuthKey};
use lightning::types::payment::PaymentSecret;
use lightning::util::ser::Writeable as _;
use tpe::{DecryptionKeyShare, aggregate_dk_shares};

const INVOICE_AMOUNT: Amount = Amount::from_sats(5_000);
const GATEWAY_FEE: Amount = Amount::from_sats(60);

struct Entropy;

impl EntropySource for Entropy {
    fn get_secure_random_bytes(&self) -> [u8; 32] {
        rand::random()
    }
}

/// Test federations generate their configuration in-process and read this
/// switch from the environment. Every test in this binary sets it before
/// building a federation, and nothing unsets it.
fn configure_test_pool() {
    static ENABLE: Once = Once::new();

    ENABLE.call_once(|| {
        // SAFETY: runs once, before this test spawns any federation task that
        // reads the environment; other tests block on the `Once` until done.
        unsafe {
            std::env::set_var("FM_BOLT12_POOL_TARGET", "8");
            std::env::set_var("FM_BOLT12_POOL_BATCH", "4");
        }
    });
}

fn fixtures() -> Fixtures {
    configure_test_pool();

    Fixtures::new_primary(DummyClientInit, DummyInit)
        .with_module(Bolt12ClientInit::default(), Bolt12Init)
}

fn root_secret(seed: u8) -> RootSecret {
    RootSecret::StandardDoubleDerive(PlainRootSecretStrategy::to_root_secret(&[seed; 64]))
}

async fn wallet(fed: &FederationTest, seed: u8) -> ClientHandleArc {
    fed.join_client_with_db(MemDatabase::new().into(), root_secret(seed))
        .await
}

async fn fund(client: &ClientHandleArc, amount: Amount) -> Result<()> {
    client
        .get_first_module::<DummyClientModule>()?
        .mock_receive(amount, AmountUnit::BITCOIN)
        .await;

    Ok(())
}

fn ingress_path() -> BlindedMessagePath {
    BlindedMessagePath::one_hop(
        SecretKey::new(&mut rand::thread_rng()).public_key(SECP256K1),
        ReceiveAuthKey(rand::random()),
        MessageContext::Offers(OffersContext::InvoiceRequest {
            nonce: Nonce::from_entropy_source(&Entropy),
        }),
        &Entropy,
        SECP256K1,
    )
}

/// Register an offer, waiting out the first moments of a new federation in
/// which the consensus clock has not been voted on yet.
async fn create_offer(
    bolt12: &Bolt12ClientModule,
    stock: u64,
) -> Result<(Offer, fedimint_bolt12_client::offers::Bolt12Offer)> {
    create_offer_with(bolt12, offer_params(stock)).await
}

async fn create_offer_with(
    bolt12: &Bolt12ClientModule,
    params: Bolt12OfferParams,
) -> Result<(Offer, fedimint_bolt12_client::offers::Bolt12Offer)> {
    retry(
        "offer registration",
        backoff_util::aggressive_backoff(),
        || bolt12.create_offer(params.clone()),
    )
    .await
}

fn offer_params(stock: u64) -> Bolt12OfferParams {
    Bolt12OfferParams {
        ingress: vec![ingress_path(), ingress_path()],
        description: "Federated offline receive".to_string(),
        expires_at: duration_since_epoch().as_secs() + 3_600,
        max_gateway_fee: PaymentFee::RECEIVE_FEE_LIMIT,
        stock,
        allow_pool: false,
    }
}

fn invoice_request(offer: &Offer, amount: Amount) -> Result<InvoiceRequest> {
    offer
        .request_invoice(
            &ExpandedKey::new(rand::random()),
            Nonce::from_entropy_source(&Entropy),
            SECP256K1,
            PaymentId(rand::random()),
        )
        .map_err(|e| anyhow::anyhow!("request: {e:?}"))?
        .chain(bitcoin::Network::Regtest)
        .map_err(|e| anyhow::anyhow!("chain: {e:?}"))?
        .amount_msats(amount.msats)
        .map_err(|e| anyhow::anyhow!("amount: {e:?}"))?
        .build_and_sign()
        .map_err(|e| anyhow::anyhow!("payer signature: {e:?}"))
}

fn payment_path(offer: &Offer, request: &InvoiceRequest) -> Result<BlindedPaymentPath> {
    let tlvs = UnauthenticatedReceiveTlvs {
        payment_secret: PaymentSecret(rand::random()),
        payment_constraints: PaymentConstraints {
            max_cltv_expiry: 10_000,
            htlc_minimum_msat: 1,
        },
        payment_context: PaymentContext::Bolt12Offer(Bolt12OfferContext {
            offer_id: offer.id(),
            invoice_request: InvoiceRequestFields {
                payer_signing_pubkey: request.payer_signing_pubkey(),
                quantity: request.quantity(),
                payer_note_truncated: None,
                human_readable_name: None,
            },
        }),
    }
    .authenticate(
        Nonce::from_entropy_source(&Entropy),
        &ExpandedKey::new(rand::random()),
    );

    BlindedPaymentPath::one_hop(
        SecretKey::new(&mut rand::thread_rng()).public_key(SECP256K1),
        tlvs,
        72,
        &Entropy,
        SECP256K1,
    )
    .map_err(|()| anyhow::anyhow!("payment path"))
}

/// A stand-in for a gateway: a funded federation client with a gateway key.
struct TestGateway {
    client: ClientHandleArc,
    key: Keypair,
}

impl TestGateway {
    async fn new(fed: &FederationTest) -> Result<Self> {
        let client = fed.new_client().await;

        fund(&client, sats(100_000)).await?;

        Ok(Self {
            client,
            key: Keypair::new(SECP256K1, &mut rand::thread_rng()),
        })
    }

    fn api(&self) -> Result<DynModuleApi> {
        Ok(self
            .client
            .get_first_module::<Bolt12ClientModule>()?
            .module_api()
            .clone())
    }

    /// Have `guardians` vote to approve this gateway and wait until consensus
    /// reflects it.
    async fn approve(&self, fed: &FederationTest, guardians: u16) -> Result<()> {
        let module_id = self
            .client
            .get_first_instance(&Bolt12ClientModule::kind())
            .context("bolt12 module")?;

        for peer in (0..guardians).map(PeerId::from) {
            fed.new_admin_api(peer)
                .await?
                .with_module(module_id)
                .request_admin::<()>(
                    SET_GATEWAY_VOTE_ENDPOINT,
                    ApiRequestErased::new((self.key.public_key(), true)),
                    ApiAuth::new("pass".to_string()),
                )
                .await?;
        }

        Ok(())
    }

    async fn is_approved(&self) -> Result<bool> {
        Ok(self
            .api()?
            .bolt12_gateway_approved(self.key.public_key())
            .await?)
    }

    async fn await_approved(&self) -> Result<()> {
        retry(
            "gateway approval",
            backoff_util::aggressive_backoff(),
            || async {
                ensure!(self.is_approved().await?, "not approved yet");

                Ok(())
            },
        )
        .await
    }

    /// Submit a BOLT12 output worth `amount` and wait for the federation's
    /// verdict.
    async fn submit(&self, output: Bolt12OutputV0, amount: Amount) -> Result<OutPoint> {
        let module_id = self
            .client
            .get_first_instance(&Bolt12ClientModule::kind())
            .context("bolt12 module")?;
        let operation_id = OperationId::new_random();

        let range = self
            .client
            .finalize_and_submit_transaction(
                operation_id,
                "BOLT12 test gateway",
                |_| (),
                TransactionBuilder::new().with_outputs(
                    ClientOutputBundle::new_no_sm(vec![ClientOutput {
                        output: Bolt12Output::V0(output),
                        amounts: Amounts::new_bitcoin(amount),
                    }])
                    .into_dyn(module_id),
                ),
            )
            .await?;

        self.client
            .transaction_updates(operation_id)
            .await
            .await_tx_accepted(range.txid())
            .await
            .map_err(|e| anyhow::anyhow!("rejected: {e}"))?;

        // The returned range covers change; our output is the first one.
        Ok(OutPoint {
            txid: range.txid(),
            out_idx: 0,
        })
    }
}

/// An invoice issued for a payer, with what the gateway needs to settle it.
struct Issued {
    reservation: Reservation,
    invoice: Bolt12Invoice,
}

/// Do what a gateway does when an invoice request arrives.
async fn issue_invoice(gateway: &TestGateway, offer: &Offer, amount: Amount) -> Result<Issued> {
    let api = gateway.api()?;

    let (_, handle) = parse_routing_metadata(offer.metadata().context("offer metadata")?)?;
    let (registration, state): (RegistrationId, Registration) = api
        .bolt12_registration_by_handle(handle)
        .await?
        .context("registration")?;
    // The offer's own stock first, then the federation's pool.
    let (source, payment_hash) = match api.bolt12_next_stock(registration).await? {
        Some((index, item)) => (Source::Stock { index }, item.payment_hash),
        None => {
            let (index, payment_hash) = api
                .request_current_consensus::<Option<(u64, [u8; 32])>>(
                    NEXT_POOL_ENDPOINT.to_owned(),
                    ApiRequestErased::new(()),
                )
                .await?
                .context("no stock and an empty pool")?;

            (Source::Pool { index }, payment_hash)
        }
    };

    let request = invoice_request(offer, amount)?;
    let path = encode_payment_path(&payment_path(offer, &request)?)?;
    let request = request.encode();

    let reserve = Reserve::new(
        registration,
        source,
        amount,
        GATEWAY_FEE,
        terms_hash(&request, &path),
        &gateway.key,
    );
    let id = reserve.reservation_id();

    gateway
        .submit(Bolt12OutputV0::Reserve(reserve), Amount::ZERO)
        .await?;

    let reservation = api.bolt12_reservation(id).await?.context("reservation")?;

    ensure!(reservation.payment_hash == payment_hash);

    let bolt12 = gateway.client.get_first_module::<Bolt12ClientModule>()?;

    let invoice = sign_invoice(
        &api,
        bolt12.bolt12_config(),
        &gateway.key,
        SigningJob {
            policy: &state.policy,
            reservation: &reservation,
            invoice_request: &request,
            payment_path: &path,
        },
    )
    .await?;

    Ok(Issued {
        reservation,
        invoice,
    })
}

/// Collect decryption shares the way a gateway does after funding, and
/// decrypt the Lightning preimage.
async fn released_preimage(
    gateway: &TestGateway,
    outpoint: OutPoint,
    reservation: &Reservation,
) -> Result<Option<[u8; 32]>> {
    let api = gateway.api()?;
    let bolt12 = gateway.client.get_first_module::<Bolt12ClientModule>()?;
    let cfg = bolt12.bolt12_config();
    let contract = reservation.contract();

    let mut shares = std::collections::BTreeMap::new();

    for peer in cfg.tpe_pks.keys().take(3) {
        let peer_shares: Vec<DecryptionKeyShare> = api
            .request_single_peer(
                DECRYPTION_SHARES_ENDPOINT.to_owned(),
                ApiRequestErased::new(outpoint),
                *peer,
            )
            .await?;

        ensure!(contract.verify_decryption_shares(&cfg.tpe_pks[peer], &peer_shares));

        shares.insert(peer.to_usize() as u64, peer_shares);
    }

    let keys: Vec<_> = (0..contract.ciphertexts().len())
        .map(|i| {
            aggregate_dk_shares(
                &shares
                    .iter()
                    .map(|(peer, shares)| (*peer, shares[i]))
                    .collect(),
            )
        })
        .collect();

    ensure!(contract.verify_agg_decryption_keys(&cfg.tpe_agg_pk, &keys));

    Ok(contract.release(&keys))
}

async fn await_balance_at_least(client: &ClientHandleArc, amount: Amount) -> Result<()> {
    retry(
        "wallet balance",
        backoff_util::aggressive_backoff_long(),
        || async {
            let balance = client.get_balance_for_btc().await?;

            ensure!(balance >= amount, "balance is {balance}");

            Ok(())
        },
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn offline_wallet_receives_and_claims_after_restoring_from_seed() -> Result<()> {
    let fed = fixtures().new_fed_not_degraded().await;
    let gateway = TestGateway::new(&fed).await?;

    // The wallet registers an offer with stock for two payments, then goes
    // offline for good: its database is dropped with it.
    let offer = {
        let wallet = wallet(&fed, 7).await;

        fund(&wallet, sats(1_000)).await?;

        let bolt12 = wallet.get_first_module::<Bolt12ClientModule>()?;
        let (offer, registered) = create_offer(&bolt12, 2).await?;

        let state = bolt12
            .offer_state(registered.index)
            .await?
            .context("offer state")?;

        assert_eq!((state.stock_len, state.stock_unused), (2, 2));
        assert_eq!(bolt12.offers().await, vec![registered]);
        assert_eq!(offer.paths().len(), 2);

        offer
    };

    // A gateway nobody approved cannot reserve an invoice.
    assert!(!gateway.is_approved().await?);
    assert!(
        issue_invoice(&gateway, &offer, INVOICE_AMOUNT)
            .await
            .is_err()
    );

    gateway.approve(&fed, 3).await?;
    gateway.await_approved().await?;

    let issued = issue_invoice(&gateway, &offer, INVOICE_AMOUNT).await?;
    let cfg = gateway
        .client
        .get_first_module::<Bolt12ClientModule>()?
        .bolt12_config()
        .clone();
    let bolt12 = &cfg.bolt12;

    // The payer sees an ordinary invoice signed by the offer's issuer key.
    assert_eq!(issued.invoice.signing_pubkey(), bolt12.signing_key);
    assert_eq!(issued.invoice.amount_msats(), INVOICE_AMOUNT.msats);
    assert_eq!(
        issued.invoice.payment_hash().0,
        issued.reservation.payment_hash
    );
    assert_eq!(
        issued.invoice.relative_expiry(),
        Duration::from_secs(INVOICE_LIFETIME)
    );

    // Until the gateway funds the receive, no guardian has a share to give.
    let id = Reservation::id(issued.reservation.registration, issued.reservation.source);
    let net = INVOICE_AMOUNT.saturating_sub(GATEWAY_FEE);

    // Funding the wrong amount is rejected and releases nothing.
    assert!(
        gateway
            .submit(Bolt12OutputV0::Receive(id), net.saturating_sub(sats(1)))
            .await
            .is_err()
    );

    let outpoint = gateway.submit(Bolt12OutputV0::Receive(id), net).await?;

    // Funding released the preimage to the gateway, which would now settle
    // the Lightning payment.
    let preimage = released_preimage(&gateway, outpoint, &issued.reservation)
        .await?
        .context("stock holds the preimage")?;

    assert_eq!(
        sha256::Hash::hash(&preimage).to_byte_array(),
        issued.reservation.payment_hash
    );

    // A funded reservation cannot be funded again.
    assert!(
        gateway
            .submit(Bolt12OutputV0::Receive(id), net)
            .await
            .is_err()
    );

    // The recipient returns with nothing but its seed, finds the receive and
    // claims it.
    let restored = wallet(&fed, 7).await;

    await_balance_at_least(&restored, net.saturating_sub(sats(100))).await?;

    let bolt12 = restored.get_first_module::<Bolt12ClientModule>()?;
    let offers = bolt12.offers().await;

    // The federation remembers the registration but not the offer string.
    assert_eq!(offers.len(), 1);
    assert_eq!(offers[0].offer, None);

    let state = bolt12
        .offer_state(offers[0].index)
        .await?
        .context("offer state")?;

    assert_eq!((state.stock_len, state.stock_unused), (2, 1));

    // A restored wallet derives the same stock secrets, so it can top up.
    let state = bolt12.add_stock(offers[0].index, 3).await?;

    assert_eq!((state.stock_len, state.stock_unused), (5, 4));

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn each_invoice_uses_a_fresh_hash_and_unpaid_ones_are_bounded() -> Result<()> {
    let fed = fixtures().new_fed_not_degraded().await;
    let gateway = TestGateway::new(&fed).await?;
    let wallet = wallet(&fed, 9).await;

    fund(&wallet, sats(1_000)).await?;

    let bolt12 = wallet.get_first_module::<Bolt12ClientModule>()?;
    let (offer, registered) = create_offer(&bolt12, 12).await?;

    gateway.approve(&fed, 3).await?;
    gateway.await_approved().await?;

    let mut hashes = std::collections::BTreeSet::new();

    for _ in 0..fedimint_bolt12_common::protocol::MAX_PENDING_PER_OFFER {
        let issued = issue_invoice(&gateway, &offer, INVOICE_AMOUNT).await?;

        assert!(hashes.insert(issued.reservation.payment_hash));
    }

    // The offer's allowance of unpaid invoices is used up.
    assert!(
        issue_invoice(&gateway, &offer, INVOICE_AMOUNT)
            .await
            .is_err()
    );

    // Each unpaid invoice still consumed a stock item for good.
    let state = bolt12
        .offer_state(registered.index)
        .await?
        .context("offer state")?;

    assert_eq!(state.stock_unused, 4);

    // An amount the fees would swallow is refused outright.
    assert!(issue_invoice(&gateway, &offer, sats(1)).await.is_err());

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn signing_works_with_one_guardian_offline() -> Result<()> {
    let fed = fixtures().new_fed_degraded().await;
    let gateway = TestGateway::new(&fed).await?;
    let wallet = wallet(&fed, 11).await;

    fund(&wallet, sats(1_000)).await?;

    let bolt12 = wallet.get_first_module::<Bolt12ClientModule>()?;
    let (offer, _) = create_offer(&bolt12, 1).await?;

    // Three online guardians are a quorum for approval, signing and release.
    gateway.approve(&fed, 3).await?;
    gateway.await_approved().await?;

    let issued = issue_invoice(&gateway, &offer, INVOICE_AMOUNT).await?;
    let id = Reservation::id(issued.reservation.registration, issued.reservation.source);
    let net = INVOICE_AMOUNT.saturating_sub(GATEWAY_FEE);

    let before = wallet.get_balance_for_btc().await?;
    let outpoint = gateway.submit(Bolt12OutputV0::Receive(id), net).await?;

    assert!(
        released_preimage(&gateway, outpoint, &issued.reservation)
            .await?
            .is_some()
    );

    // The wallet is online this time and claims without being restored.
    await_balance_at_least(&wallet, before + net.saturating_sub(sats(100))).await?;

    Ok(())
}

/// The public key type is only used through the gateway key.
#[allow(dead_code)]
fn _assert_types(_: PublicKey) {}

#[tokio::test(flavor = "multi_thread")]
async fn generated_preimages_take_over_when_stock_runs_out() -> Result<()> {
    let fed = fixtures().new_fed_not_degraded().await;
    let gateway = TestGateway::new(&fed).await?;

    gateway.approve(&fed, 3).await?;
    gateway.await_approved().await?;

    let wallet = wallet(&fed, 9).await;

    fund(&wallet, sats(1_000)).await?;

    let bolt12 = wallet.get_first_module::<Bolt12ClientModule>()?;
    let (offer, _) = create_offer_with(
        &bolt12,
        Bolt12OfferParams {
            allow_pool: true,
            ..offer_params(1)
        },
    )
    .await?;

    let first = issue_invoice(&gateway, &offer, INVOICE_AMOUNT).await?;

    assert!(matches!(first.reservation.source, Source::Stock { .. }));

    // Meanwhile committees of guardians generate preimages; once one is in
    // the pool, the stockless offer still issues invoices.
    let second = retry(
        "a generated preimage",
        backoff_util::custom_backoff(Duration::from_secs(1), Duration::from_secs(2), Some(300)),
        || issue_invoice(&gateway, &offer, INVOICE_AMOUNT),
    )
    .await?;

    assert!(matches!(second.reservation.source, Source::Pool { .. }));
    assert_eq!(
        second.invoice.payment_hash().0,
        second.reservation.payment_hash
    );

    let balance = wallet.get_balance_for_btc().await?;
    let net = INVOICE_AMOUNT.saturating_sub(GATEWAY_FEE);
    let id = Reservation::id(second.reservation.registration, second.reservation.source);
    let outpoint = gateway.submit(Bolt12OutputV0::Receive(id), net).await?;

    // Nobody knew the preimage until funding released the shares.
    let preimage = released_preimage(&gateway, outpoint, &second.reservation)
        .await?
        .context("the shares recover the preimage")?;

    assert_eq!(
        sha256::Hash::hash(&preimage).to_byte_array(),
        second.reservation.payment_hash
    );

    // The online wallet claims it, paying the pool fee.
    let pool_fee = bolt12.bolt12_config().bolt12.pool_fee;

    await_balance_at_least(&wallet, balance + net - pool_fee - sats(100)).await?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn pool_generation_keeps_working_with_one_guardian_offline() -> Result<()> {
    // Peer 3 is offline; peers 0, 1, 2 form the 2f + 1 = 3 committee.
    // Verifies real multi-guardian GF(2^8) parallel-king MPC generates
    // recoverable preimages and that the sticky committee keeps producing
    // across consecutive pool receives without stalling on the offline peer.
    let fed = fixtures().new_fed_degraded().await;
    let gateway = TestGateway::new(&fed).await?;

    gateway.approve(&fed, 3).await?;
    gateway.await_approved().await?;

    let wallet = wallet(&fed, 13).await;
    fund(&wallet, sats(1_000)).await?;

    let bolt12 = wallet.get_first_module::<Bolt12ClientModule>()?;
    let (offer, _) = create_offer_with(
        &bolt12,
        Bolt12OfferParams {
            allow_pool: true,
            ..offer_params(1)
        },
    )
    .await?;

    // Drain the single initial stock item so subsequent receives come from the
    // generated preimage pool.
    let initial = issue_invoice(&gateway, &offer, INVOICE_AMOUNT).await?;
    assert!(matches!(initial.reservation.source, Source::Stock { .. }));

    // Unauthenticated / invalid fetch and relay calls to online guardians must
    // be rejected by the live module API.
    let api = gateway.api()?;
    assert!(
        api.request_single_peer::<Vec<String>>(
            MPC_FETCH_ENDPOINT.to_owned(),
            ApiRequestErased::new("deadbeef"),
            PeerId::from(0),
        )
        .await
        .is_err()
    );
    assert!(
        api.request_single_peer::<Vec<String>>(
            MPC_RELAY_ENDPOINT.to_owned(),
            ApiRequestErased::new("deadbeef"),
            PeerId::from(0),
        )
        .await
        .is_err()
    );

    let net = INVOICE_AMOUNT.saturating_sub(GATEWAY_FEE);

    // Reserve, fund, and recover two consecutive pool-backed receives.
    for _ in 0..2 {
        let issued = retry(
            "pool preimage with one guardian offline",
            backoff_util::custom_backoff(Duration::from_secs(1), Duration::from_secs(2), Some(300)),
            || issue_invoice(&gateway, &offer, INVOICE_AMOUNT),
        )
        .await?;

        assert!(matches!(issued.reservation.source, Source::Pool { .. }));

        let id = Reservation::id(issued.reservation.registration, issued.reservation.source);
        let outpoint = gateway.submit(Bolt12OutputV0::Receive(id), net).await?;

        let preimage = released_preimage(&gateway, outpoint, &issued.reservation)
            .await?
            .context("degraded federation pool shares must recover the preimage")?;

        assert_eq!(
            sha256::Hash::hash(&preimage).to_byte_array(),
            issued.reservation.payment_hash
        );
    }

    Ok(())
}

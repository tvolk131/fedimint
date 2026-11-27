//! A gateway answering federated BOLT12 invoice requests and funding the
//! recipient's claim when the payment arrives, against a four-guardian test
//! federation and the fake Lightning node.

use std::sync::{Arc, Once};

use anyhow::{Context as _, Result, ensure};
use bitcoin::hashes::{Hash as _, sha256};
use fedimint_api_client::api::FederationApiExt as _;
use fedimint_bolt12_client::api::Bolt12FederationApi as _;
use fedimint_bolt12_client::bolt12::Bolt12OfferParams;
use fedimint_bolt12_client::{Bolt12ClientInit, Bolt12ClientModule};
use fedimint_bolt12_common::endpoint_constants::BOLT12_SET_GATEWAY_VOTE_ENDPOINT;
use fedimint_bolt12_common::gateway_api::PaymentFee;
use fedimint_bolt12_server::Bolt12Init;
use fedimint_client::ClientHandleArc;
use fedimint_client_module::module::ClientModule as _;
use fedimint_core::module::{AmountUnit, ApiAuth, ApiRequestErased};
use fedimint_core::secp256k1::{PublicKey, SECP256K1};
use fedimint_core::time::duration_since_epoch;
use fedimint_core::util::{backoff_util, retry};
use fedimint_core::{Amount, PeerId, sats};
use fedimint_dummy_client::{DummyClientInit, DummyClientModule};
use fedimint_dummy_server::DummyInit;
use fedimint_gateway_server::Gateway;
use fedimint_gw_bolt12_client::GatewayClientModuleBolt12;
use fedimint_gwv2_client::GatewayClientModuleV2;
use fedimint_lightning::bolt12::Bolt12Request;
use fedimint_lightning::{InterceptPaymentRequest, NO_INCOMING_CIRCUIT, PaymentAction};
use fedimint_lnv2_client::LightningClientInit;
use fedimint_testing::federation::FederationTest;
use fedimint_testing::fixtures::Fixtures;
use fedimint_testing::ln::FakeLightningTest;
use lightning::ln::channelmanager::PaymentId;
use lightning::ln::inbound_payment::ExpandedKey;
use lightning::offers::invoice::Bolt12Invoice;
use lightning::offers::invoice_request::InvoiceRequest;
use lightning::offers::nonce::Nonce;
use lightning::offers::offer::Offer;
use lightning::sign::EntropySource;
use tokio::sync::oneshot;

const INVOICE_AMOUNT: Amount = Amount::from_sats(5_000);

struct Entropy;

impl EntropySource for Entropy {
    fn get_secure_random_bytes(&self) -> [u8; 32] {
        rand::random()
    }
}

/// Test federations read this switch from the environment when they
/// generate their configuration. Nothing in this binary unsets it.
fn enable_bolt12() {
    static ENABLE: Once = Once::new();

    ENABLE.call_once(|| {
        // SAFETY: runs once, before this test spawns any federation task that
        // reads the environment; other tests block on the `Once` until done.
        unsafe {
            std::env::set_var("FM_ENABLE_FEDERATED_BOLT12", "1");
            std::env::set_var("FM_BOLT12_POOL_TARGET", "8");
            std::env::set_var("FM_BOLT12_POOL_BATCH", "4");
        }
    });
}

fn fixtures() -> Fixtures {
    enable_bolt12();

    Fixtures::new_primary(DummyClientInit, DummyInit)
        .with_module(
            LightningClientInit::default(),
            fedimint_lnv2_server::LightningInit,
        )
        .with_module(Bolt12ClientInit::default(), Bolt12Init)
}

async fn fund(client: &ClientHandleArc, amount: Amount) -> Result<()> {
    client
        .get_first_module::<DummyClientModule>()?
        .mock_receive(amount, AmountUnit::BITCOIN)
        .await;

    Ok(())
}

/// Have a quorum of guardians approve `gateway_key` and wait until consensus
/// reflects it.
async fn approve(
    fed: &FederationTest,
    wallet: &ClientHandleArc,
    gateway_key: PublicKey,
) -> Result<()> {
    let module_id = wallet
        .get_first_instance(&Bolt12ClientModule::kind())
        .context("bolt12 module")?;

    for peer in (0..3).map(PeerId::from) {
        fed.new_admin_api(peer)
            .await?
            .with_module(module_id)
            .request_admin::<()>(
                BOLT12_SET_GATEWAY_VOTE_ENDPOINT,
                ApiRequestErased::new((gateway_key, true)),
                ApiAuth::new("pass".to_string()),
            )
            .await?;
    }

    let api = wallet
        .get_first_module::<Bolt12ClientModule>()?
        .module_api()
        .clone();

    retry(
        "gateway approval",
        backoff_util::aggressive_backoff_long(),
        || async {
            ensure!(
                api.bolt12_gateway_approved(gateway_key).await?,
                "not approved yet"
            );

            Ok(())
        },
    )
    .await
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

/// Hand `request` to the gateway the way its Lightning node does and return
/// the invoice it sends back.
async fn answer(gateway: &Gateway, request: &InvoiceRequest) -> Result<Bolt12Invoice> {
    let (sender, receiver) = oneshot::channel();
    let request = Bolt12Request::new(request.clone(), move |invoice| {
        let _ = sender.send(invoice);

        Ok(())
    });

    gateway
        .answer_bolt12_request(request, gateway.get_lightning_context().await?.lnrpc)
        .await?;

    Ok(receiver.await?)
}

fn held_payment(invoice: &Bolt12Invoice, amount_msat: u64) -> InterceptPaymentRequest {
    InterceptPaymentRequest {
        payment_hash: sha256::Hash::from_byte_array(invoice.payment_hash().0),
        amount_msat,
        incoming_amount_msat: amount_msat,
        expiry: 1_000,
        incoming_chan_id: NO_INCOMING_CIRCUIT.0,
        short_channel_id: None,
        htlc_id: NO_INCOMING_CIRCUIT.1,
    }
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
async fn gateway_answers_invoice_requests_and_funds_held_payments() -> Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;
    let lightning_node = Arc::new(FakeLightningTest::new());
    let gateway = fixtures
        .new_gateway_with_lightning(lightning_node.clone())
        .await;

    fed.connect_gateway(&gateway).await;

    let gateway_client = gateway.select_client(fed.id()).await?.into_value();
    let gateway_key = gateway_client
        .get_first_module::<GatewayClientModuleBolt12>()?
        .keypair
        .public_key();

    fund(&gateway_client, sats(100_000)).await?;

    let wallet = fed.new_client().await;

    fund(&wallet, sats(1_000)).await?;
    approve(&fed, &wallet, gateway_key).await?;

    // The wallet builds its offer from what the gateway advertises.
    let ingress = gateway
        .bolt12_ingress(&fed.id())
        .await?
        .context("the gateway serves federated BOLT12 offers")?;

    assert_eq!(ingress.gateway_key, gateway_key);
    assert!(ingress.verify(fed.id()), "signed ingress must verify");
    let mut tampered = ingress.clone();
    tampered.receive_fee.base = Amount::from_sats(999);
    assert!(
        !tampered.verify(fed.id()),
        "tampered ingress must fail verification"
    );

    let bolt12 = wallet.get_first_module::<Bolt12ClientModule>()?;
    let params = Bolt12OfferParams {
        ingress: vec![ingress.message_path()?],
        description: "Federated offline receive".to_string(),
        expires_at: duration_since_epoch().as_secs() + 3_600,
        max_gateway_fee: PaymentFee::RECEIVE_FEE_LIMIT,
        stock: 4,
        allow_pool: false,
    };

    // A new federation refuses registrations until its clock is set.
    let (offer, _) = retry(
        "offer registration",
        backoff_util::aggressive_backoff(),
        || bolt12.create_bolt12_offer(params.clone()),
    )
    .await?;

    let balance_before_receive = wallet.get_balance_for_btc().await?;

    // The gateway answers a payer's request with a federation-signed invoice
    // for exactly the requested amount, and a repeated request with the same
    // invoice rather than a second reservation.
    let request = invoice_request(&offer, INVOICE_AMOUNT)?;
    let invoice = answer(&gateway, &request).await?;

    assert_eq!(invoice.amount_msats(), INVOICE_AMOUNT.msats);
    assert_eq!(
        Some(invoice.signing_pubkey()),
        offer.issuer_signing_pubkey()
    );
    assert_eq!(
        answer(&gateway, &request).await?.payment_hash(),
        invoice.payment_hash()
    );

    let lightning_context = gateway.get_lightning_context().await?;
    let gateway_balance = gateway_client.get_balance_for_btc().await?;

    let payment_hash = sha256::Hash::from_byte_array(invoice.payment_hash().0);
    let responses = || {
        lightning_node
            .completed_htlcs()
            .into_iter()
            .filter(|response| response.payment_hash == payment_hash)
            .map(|response| response.action)
            .collect::<Vec<_>>()
    };

    // A payment that is short of the invoice is failed back unfunded.
    assert_eq!(
        gateway
            .handle_lightning_payment(
                held_payment(&invoice, INVOICE_AMOUNT.msats - 1),
                &lightning_context
            )
            .await,
        "bolt12"
    );
    assert_eq!(gateway_client.get_balance_for_btc().await?, gateway_balance);
    assert!(matches!(responses().as_slice(), [PaymentAction::Cancel]));

    // So is one that leaves too little time before its claim deadline to
    // settle safely.
    let short_deadline = InterceptPaymentRequest {
        expiry: 10,
        ..held_payment(&invoice, INVOICE_AMOUNT.msats)
    };

    assert_eq!(
        gateway
            .handle_lightning_payment(short_deadline, &lightning_context)
            .await,
        "bolt12"
    );
    assert_eq!(gateway_client.get_balance_for_btc().await?, gateway_balance);
    assert!(matches!(
        responses().as_slice(),
        [PaymentAction::Cancel, PaymentAction::Cancel]
    ));

    // The exact payment funds the recipient's claim, which the online wallet
    // picks up from the receive stream.
    assert_eq!(
        gateway
            .handle_lightning_payment(
                held_payment(&invoice, INVOICE_AMOUNT.msats),
                &lightning_context
            )
            .await,
        "bolt12"
    );

    await_balance_at_least(&wallet, balance_before_receive + sats(4_000)).await?;

    assert!(gateway_client.get_balance_for_btc().await? < gateway_balance);

    // The gateway settles the Lightning payment with the released preimage.
    retry(
        "settlement",
        backoff_util::aggressive_backoff_long(),
        || async {
            match responses().as_slice() {
                [
                    PaymentAction::Cancel,
                    PaymentAction::Cancel,
                    PaymentAction::Settle(preimage),
                ] => {
                    ensure!(sha256::Hash::hash(&preimage.0) == payment_hash);

                    Ok(())
                }
                other => anyhow::bail!("responses so far: {other:?}"),
            }
        },
    )
    .await?;

    // A payment for a hash the gateway never issued is not taken for BOLT12.
    let unknown = InterceptPaymentRequest {
        payment_hash: sha256::Hash::hash(b"unknown"),
        ..held_payment(&invoice, INVOICE_AMOUNT.msats)
    };

    assert!(
        gateway
            .try_handle_lightning_payment_bolt12(&unknown, &lightning_context, None)
            .await
            .is_err()
    );

    // Re-delivering an already-funded BOLT12 payment after receives have been
    // disabled for the federation MUST resume cleanly without sending Cancel.
    let module = gateway_client.get_first_module::<GatewayClientModuleBolt12>()?;
    let lnv2_module = gateway_client.get_first_module::<GatewayClientModuleV2>()?;
    let funded_res = module
        .bolt12_reservation_for_hash(payment_hash)
        .await
        .context("funded reservation present")?;
    module
        .relay_bolt12_htlc(
            funded_res,
            payment_hash,
            fedimint_gw_bolt12_client::IncomingCircuitKey {
                incoming_chan_id: NO_INCOMING_CIRCUIT.0,
                htlc_id: NO_INCOMING_CIRCUIT.1,
            },
            INVOICE_AMOUNT.msats,
            100,
            false,
        )
        .await
        .context("already-funded BOLT12 payment must resume even when receive_enabled == false")?;

    // Front-running the next stock item's payment hash with a BOLT11 invoice
    // creation must NOT wedge BOLT12 issuance: the gateway skips the collided
    // stock item and issues an invoice from the next unused item.
    let registration_id = wallet
        .get_first_module::<Bolt12ClientModule>()?
        .bolt12_offers()
        .await
        .first()
        .context("offer record")?
        .registration;
    let next_stock = wallet
        .get_first_module::<Bolt12ClientModule>()?
        .module_api()
        .bolt12_next_stock(registration_id)
        .await?
        .context("unused stock remains")?;
    let front_run_hash = sha256::Hash::from_byte_array(next_stock.1.payment_hash);
    let routing_info = gateway
        .routing_info_v2(&fed.id())
        .await?
        .context("routing info")?;
    let front_run_amount = Amount::from_sats(1_000);
    let front_run_contract = fedimint_lnv2_common::contracts::IncomingContract::new(
        lnv2_module.cfg.tpe_agg_pk,
        [42; 32],
        [7; 32],
        fedimint_lnv2_common::contracts::PaymentImage::Hash(front_run_hash),
        routing_info
            .receive_fee
            .subtract_from(front_run_amount.msats),
        u64::MAX,
        fedimint_core::secp256k1::Keypair::new(SECP256K1, &mut rand::thread_rng()).public_key(),
        lnv2_module.keypair.public_key(),
        fedimint_core::secp256k1::Keypair::new(SECP256K1, &mut rand::thread_rng()).public_key(),
    );
    gateway
        .create_bolt11_invoice_v2(
            fedimint_lnv2_common::gateway_api::CreateBolt11InvoicePayload {
                federation_id: fed.id(),
                contract: front_run_contract,
                amount: front_run_amount,
                description: fedimint_lnv2_common::Bolt11InvoiceDescription::Direct(String::new()),
                expiry_secs: 3_600,
            },
        )
        .await
        .context("attacker front-runs next stock payment hash via BOLT11")?;

    let request2 = invoice_request(&offer, INVOICE_AMOUNT)?;
    let invoice2 = answer(&gateway, &request2).await?;
    assert_ne!(
        sha256::Hash::from_byte_array(invoice2.payment_hash().0),
        front_run_hash,
        "gateway must skip front-run stock payment hash and use next item"
    );

    // An authoritative `Bolt11` payment-hash owner must terminate with
    // `"cancel"` on non-`ReceiveDisabled` LNv2 errors (such as an amount
    // mismatch on an intercepted forward carrying a non-federation scid, which
    // previously fell through to LNv1 / `"forward"`).
    let front_run_forward_mismatch = InterceptPaymentRequest {
        payment_hash: front_run_hash,
        amount_msat: front_run_amount.msats - 1,
        incoming_amount_msat: front_run_amount.msats - 1,
        expiry: 1_000,
        incoming_chan_id: 99,
        short_channel_id: Some(999_999),
        htlc_id: 1,
    };
    assert_eq!(
        gateway
            .handle_lightning_payment(front_run_forward_mismatch.clone(), &lightning_context)
            .await,
        "cancel",
        "Bolt11-owned payment hash must cancel rather than fall through to LNv1/forward"
    );

    // Leaving/unloading the owning federation while durable `PaymentHashOwner`
    // rows remain in `gateway_db` must leave held payments (`incoming_circuit`
    // absent) held (`"ignore"`) instead of cancelling a possibly funded
    // payment, while cancelling intercepted forwards (which cannot fund fresh
    // contracts).
    drop(lnv2_module);
    drop(module);
    drop(gateway_client);
    let completed_before_unload = lightning_node.completed_htlcs().len();
    fedimint_gateway_ui::IAdminGateway::handle_leave_federation(
        &gateway,
        fedimint_gateway_common::LeaveFedPayload {
            federation_id: fed.id(),
        },
    )
    .await
    .map_err(|err| anyhow::anyhow!("leave federation failed: {err:?}"))?;

    assert_eq!(
        gateway
            .handle_lightning_payment(
                held_payment(&invoice, INVOICE_AMOUNT.msats),
                &lightning_context
            )
            .await,
        "ignore",
        "unloaded owning federation must hold BOLT12 held payment rather than cancel"
    );
    let front_run_held = InterceptPaymentRequest {
        payment_hash: front_run_hash,
        amount_msat: front_run_amount.msats,
        incoming_amount_msat: front_run_amount.msats,
        expiry: 1_000,
        incoming_chan_id: NO_INCOMING_CIRCUIT.0,
        short_channel_id: None,
        htlc_id: NO_INCOMING_CIRCUIT.1,
    };
    assert_eq!(
        gateway
            .handle_lightning_payment(front_run_held, &lightning_context)
            .await,
        "ignore",
        "unloaded owning federation must hold Bolt11 held payment rather than cancel"
    );
    assert_eq!(
        lightning_node.completed_htlcs().len(),
        completed_before_unload,
        "leaving held payments untouched must not emit any Cancel/Forward responses"
    );
    assert_eq!(
        gateway
            .handle_lightning_payment(front_run_forward_mismatch, &lightning_context)
            .await,
        "cancel",
        "unloaded owning federation must cancel intercepted forwards rather than parking HTLCs"
    );

    Ok(())
}

//! BOLT12 message handling shared by guardians, gateways and wallets.
//!
//! Nothing here runs inside consensus. Guardians call [`unsigned_invoice`]
//! when asked to sign; a gateway calls it to learn which digest they sign.

use std::io::{Cursor, Read};
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use bitcoin::Network;
use bitcoin::constants::ChainHash;
use bitcoin::hashes::{Hash, sha256};
use bitcoin::secp256k1::PublicKey;
use bitcoin::secp256k1::schnorr::Signature;
use fedimint_core::config::FederationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use lightning::blinded_path::payment::{BlindedPayInfo, BlindedPaymentPath};
use lightning::blinded_path::{BlindedHop, IntroductionNode};
use lightning::offers::invoice::{Bolt12Invoice, UnsignedBolt12Invoice};
use lightning::offers::invoice_request::InvoiceRequest;
use lightning::offers::offer::Offer;
use lightning::types::payment::PaymentHash;
use lightning::util::ser::{BigSize, Readable, Writeable};

use super::{INVOICE_LIFETIME, ReceivePolicy, Reservation, terms_hash};

/// Upper bound on an offer, an invoice request or an encoded payment path.
pub const MAX_BOLT12_BYTES: usize = 16_384;

const ROUTING_PREFIX: &[u8] = b"fedimint/bolt12/route/v1";

/// Offer metadata that lets any gateway connected to the federation find the
/// registration an invoice request is for.
pub fn routing_metadata(federation: FederationId, handle: [u8; 32]) -> Vec<u8> {
    let mut bytes = ROUTING_PREFIX.to_vec();

    bytes.extend(federation.0.to_byte_array());
    bytes.extend(handle);
    bytes
}

/// Whether offer metadata was produced by [`routing_metadata`].
pub fn is_routing_metadata(bytes: &[u8]) -> bool {
    bytes.len() == ROUTING_PREFIX.len() + 64 && bytes.starts_with(ROUTING_PREFIX)
}

pub fn parse_routing_metadata(bytes: &[u8]) -> Result<(FederationId, [u8; 32])> {
    ensure!(
        is_routing_metadata(bytes),
        "not federated BOLT12 routing metadata"
    );

    let bytes = &bytes[ROUTING_PREFIX.len()..];

    Ok((
        FederationId(sha256::Hash::from_byte_array(bytes[..32].try_into()?)),
        bytes[32..].try_into()?,
    ))
}

/// The hash a registration commits to for `offer`.
pub fn offer_hash(offer: &Offer) -> sha256::Hash {
    sha256::Hash::hash(&offer.encode())
}

/// The offer TLV records echoed in an invoice request, byte for byte.
///
/// Offers are unsigned, so a payer could alter any offer field. Hashing every
/// offer-range record, including unknown ones, and comparing with the
/// registered hash rejects a request for anything but the registered offer.
fn offer_records(request: &[u8]) -> Result<Vec<u8>> {
    let mut reader = Cursor::new(request);
    let mut offer = Vec::new();

    while usize::try_from(reader.position())? < request.len() {
        let start = usize::try_from(reader.position())?;

        let record_type = BigSize::read(&mut reader)
            .map_err(|e| anyhow::anyhow!("invalid TLV type: {e:?}"))?
            .0;
        let length = BigSize::read(&mut reader)
            .map_err(|e| anyhow::anyhow!("invalid TLV length: {e:?}"))?
            .0;

        let remaining = request.len() - usize::try_from(reader.position())?;

        ensure!(
            usize::try_from(length).is_ok_and(|length| length <= remaining),
            "truncated TLV record"
        );

        std::io::copy(&mut (&mut reader).take(length), &mut std::io::sink())?;

        let end = usize::try_from(reader.position())?;

        // BOLT12 reserves 1..80 and the first experimental range for offers.
        if (1..80).contains(&record_type) || (1_000_000_000..2_000_000_000).contains(&record_type) {
            offer.extend_from_slice(&request[start..end]);
        }
    }

    Ok(offer)
}

#[derive(Debug, Clone, Encodable, Decodable)]
struct EncodedPaymentPath {
    introduction: PublicKey,
    blinding: PublicKey,
    hops: Vec<(PublicKey, Vec<u8>)>,
    payinfo: Vec<u8>,
}

/// A stable byte encoding of a blinded payment path.
pub fn encode_payment_path(path: &BlindedPaymentPath) -> Result<Vec<u8>> {
    let IntroductionNode::NodeId(introduction) = path.introduction_node() else {
        anyhow::bail!("short-channel introduction nodes are unsupported");
    };

    let encoded = EncodedPaymentPath {
        introduction: *introduction,
        blinding: path.blinding_point(),
        hops: path
            .blinded_hops()
            .iter()
            .map(|hop| (hop.blinded_node_id, hop.encrypted_payload.clone()))
            .collect(),
        payinfo: path.payinfo.encode(),
    }
    .consensus_encode_to_vec();

    ensure!(
        encoded.len() <= MAX_BOLT12_BYTES,
        "payment path exceeds limit"
    );

    Ok(encoded)
}

pub fn decode_payment_path(bytes: &[u8]) -> Result<BlindedPaymentPath> {
    ensure!(
        bytes.len() <= MAX_BOLT12_BYTES,
        "payment path exceeds limit"
    );

    let path =
        EncodedPaymentPath::consensus_decode_whole(bytes, &ModuleDecoderRegistry::default())?;

    ensure!(
        (1..=8).contains(&path.hops.len()),
        "invalid blinded hop count"
    );

    let mut reader = Cursor::new(&path.payinfo);
    let payinfo =
        BlindedPayInfo::read(&mut reader).map_err(|e| anyhow::anyhow!("invalid payinfo: {e:?}"))?;

    ensure!(
        usize::try_from(reader.position())? == path.payinfo.len(),
        "trailing payinfo data"
    );

    Ok(BlindedPaymentPath::from_blinded_path_and_payinfo(
        path.introduction,
        path.blinding,
        path.hops
            .into_iter()
            .map(|(blinded_node_id, encrypted_payload)| BlindedHop {
                blinded_node_id,
                encrypted_payload,
            })
            .collect(),
        payinfo,
    ))
}

/// The opaque bytes a reservation pins and an invoice is built from.
#[derive(Debug, Clone, Copy)]
pub struct Terms<'a> {
    pub invoice_request: &'a [u8],
    pub payment_path: &'a [u8],
}

/// Everything about the federation an invoice must agree with.
#[derive(Debug, Clone, Copy)]
pub struct Issuer {
    /// The federation's invoice signing key.
    pub signing_key: PublicKey,
    pub network: Network,
}

/// Build the one invoice the federation may sign for a reservation, or explain
/// why there is none.
///
/// The result is a deterministic function of consensus state and `terms`, so
/// every honest guardian derives the same digest.
pub fn unsigned_invoice(
    issuer: Issuer,
    policy: &ReceivePolicy,
    reservation: &Reservation,
    terms: Terms<'_>,
) -> Result<UnsignedBolt12Invoice> {
    ensure!(
        terms.invoice_request.len() <= MAX_BOLT12_BYTES,
        "invoice request exceeds limit"
    );
    ensure!(
        terms_hash(terms.invoice_request, terms.payment_path) == reservation.terms,
        "terms differ from the reservation"
    );
    ensure!(
        policy.claim_pk == reservation.claim_pk,
        "reservation belongs to another registration"
    );

    let offer = offer_records(terms.invoice_request)?;

    ensure!(
        sha256::Hash::hash(&offer) == policy.offer_hash,
        "invoice request is for an unregistered offer"
    );

    let offer = Offer::try_from(offer).map_err(|e| anyhow::anyhow!("invalid offer: {e:?}"))?;

    ensure!(
        offer.issuer_signing_pubkey() == Some(issuer.signing_key),
        "offer is not issued under the federation key"
    );

    // Parsing also verifies the payer's signature over the request.
    let request = InvoiceRequest::try_from(terms.invoice_request.to_vec())
        .map_err(|e| anyhow::anyhow!("invalid invoice request: {e:?}"))?;

    ensure!(
        request.chain() == ChainHash::using_genesis_block(issuer.network),
        "invoice request is for another chain"
    );
    ensure!(
        request.quantity().is_none_or(|quantity| quantity == 1),
        "multiple-item requests are unsupported"
    );
    ensure!(
        request.amount_msats() == Some(reservation.amount.msats),
        "request amount differs from the reservation"
    );

    request
        .respond_with_no_std(
            vec![decode_payment_path(terms.payment_path)?],
            PaymentHash(reservation.payment_hash),
            Duration::from_secs(reservation.created_at),
        )
        .map_err(|e| anyhow::anyhow!("cannot respond to invoice request: {e:?}"))?
        .relative_expiry(u32::try_from(INVOICE_LIFETIME).context("invoice lifetime overflow")?)
        .build()
        .map_err(|e| anyhow::anyhow!("cannot build invoice: {e:?}"))
}

/// The message the federation's threshold signature covers.
pub fn signing_digest(invoice: &UnsignedBolt12Invoice) -> [u8; 32] {
    *invoice.as_ref().as_digest().as_ref()
}

/// Attach an aggregated signature, checking it against the invoice.
pub fn sign(invoice: UnsignedBolt12Invoice, signature: Signature) -> Result<Bolt12Invoice> {
    invoice
        .sign(|_: &UnsignedBolt12Invoice| Ok::<_, ()>(signature))
        .map_err(|e| anyhow::anyhow!("invalid invoice signature: {e:?}"))
}

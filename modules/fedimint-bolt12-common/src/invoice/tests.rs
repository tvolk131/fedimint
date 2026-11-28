use bitcoin::secp256k1::{SECP256K1, SecretKey};
use lightning::blinded_path::payment::{
    Bolt12OfferContext, PaymentConstraints, PaymentContext, UnauthenticatedReceiveTlvs,
};
use lightning::ln::inbound_payment::ExpandedKey;
use lightning::offers::invoice_request::InvoiceRequestFields;
use lightning::offers::nonce::Nonce;
use lightning::offers::offer::OfferId;
use lightning::sign::EntropySource;
use lightning::types::payment::PaymentSecret;

use super::{decode_payment_path, encode_payment_path};

struct Entropy;

impl EntropySource for Entropy {
    fn get_secure_random_bytes(&self) -> [u8; 32] {
        rand::random()
    }
}

#[test]
fn payment_path_round_trips() {
    let tlvs = UnauthenticatedReceiveTlvs {
        payment_secret: PaymentSecret([7; 32]),
        payment_constraints: PaymentConstraints {
            max_cltv_expiry: 1_000,
            htlc_minimum_msat: 1,
        },
        payment_context: PaymentContext::Bolt12Offer(Bolt12OfferContext {
            offer_id: OfferId([1; 32]),
            invoice_request: InvoiceRequestFields {
                payer_signing_pubkey: SecretKey::from_slice(&[2; 32])
                    .expect("valid key")
                    .public_key(SECP256K1),
                quantity: None,
                payer_note_truncated: None,
                human_readable_name: None,
            },
        }),
    }
    .authenticate(
        Nonce::from_entropy_source(&Entropy),
        &ExpandedKey::new([3; 32]),
    );

    let path = lightning::blinded_path::payment::BlindedPaymentPath::one_hop(
        SecretKey::from_slice(&[4; 32])
            .expect("valid key")
            .public_key(SECP256K1),
        tlvs,
        144,
        &Entropy,
        SECP256K1,
    )
    .expect("valid path");

    assert_eq!(path.payinfo.cltv_expiry_delta, 144);

    let decoded =
        decode_payment_path(&encode_payment_path(&path).expect("encodes")).expect("decodes");

    assert_eq!(decoded, path);
    assert_eq!(decoded.payinfo.cltv_expiry_delta, 144);
}

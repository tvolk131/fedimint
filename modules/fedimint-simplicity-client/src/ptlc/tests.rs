use fedimint_core::Amount;
use fedimint_core::secp256k1::Message;

use super::*;

fn key(byte: u8) -> Keypair {
    Keypair::from_secret_key(SECP256K1, &SecretKey::from_slice(&[byte; 32]).unwrap())
}

#[test]
fn adaptor_signatures_are_bip340_compatible_and_extract_both_scalar_signs() {
    let mut nonce_parities = [false; 2];
    for byte in 1..=32 {
        let signer = key(byte);
        let public = signer.x_only_public_key().0;
        let secret = key(33 + byte).secret_key();
        for secret in [secret, secret.negate()] {
            let point = secret.public_key(SECP256K1);
            let digest = [byte; 32];
            let adaptor = AdaptorSignature::encrypt(&signer, point, digest);
            nonce_parities[usize::from(adaptor.0.needs_negation)] = true;
            assert!(adaptor.verify(public, point, digest));
            let signature = adaptor.complete(public, point, digest, &secret).unwrap();
            SECP256K1
                .verify_schnorr(&signature, &Message::from_digest(digest), &public)
                .unwrap();
            assert_eq!(
                adaptor.extract(public, point, digest, &signature).unwrap(),
                secret
            );
            let encoded = serde_json::to_vec(&adaptor).unwrap();
            assert_eq!(
                serde_json::from_slice::<AdaptorSignature>(&encoded).unwrap(),
                adaptor
            );
        }
    }
    assert_eq!(nonce_parities, [true, true]);
}

#[test]
fn transcript_rejects_wrong_keys_messages_scalars_and_unrelated_signatures() {
    let signer = key(1);
    let public = signer.x_only_public_key().0;
    let secret = key(2).secret_key();
    let point = secret.public_key(SECP256K1);
    let digest = [3; 32];
    let adaptor = AdaptorSignature::encrypt(&signer, point, digest);
    let completed = adaptor.complete(public, point, digest, &secret).unwrap();
    assert!(!adaptor.verify(key(4).x_only_public_key().0, point, digest));
    assert!(!adaptor.verify(public, point.negate(SECP256K1), digest));
    assert!(!adaptor.verify(public, point, [5; 32]));
    assert!(
        adaptor
            .complete(public, point, digest, &secret.negate())
            .is_err()
    );
    assert!(
        adaptor
            .complete(public, point, digest, &key(6).secret_key())
            .is_err()
    );
    let unrelated = SECP256K1.sign_schnorr_no_aux_rand(&Message::from_digest(digest), &signer);
    assert!(adaptor.extract(public, point, digest, &unrelated).is_err());
    assert!(adaptor.extract(public, point, [5; 32], &completed).is_err());
    let mut tampered = adaptor;
    tampered.0.needs_negation = !tampered.0.needs_negation;
    assert!(!tampered.verify(public, point, digest));
    assert!(tampered.complete(public, point, digest, &secret).is_err());
}

#[test]
fn funding_validation_binds_all_public_terms() {
    let terms = Ptlc {
        funder: key(1).x_only_public_key().0,
        refund: key(7).x_only_public_key().0,
        claimant: key(2).x_only_public_key().0,
        payment_point: key(3).public_key(),
        amount: Amount::from_sats(100),
        expiry_block_count: 100,
    };
    let output = terms.output(vec![]).unwrap();
    terms.validate_output(&output).unwrap();
    let mut invalid_output = output.clone();
    invalid_output.extension = None;
    assert!(terms.validate_output(&invalid_output).is_err());
    invalid_output = output.clone();
    invalid_output.extension = Some(crate::common::assets::AssetExtension::Bundle(AssetBundle {
        authorities: vec![crate::common::assets::AssetId([9; 32])],
        ..Default::default()
    }));
    assert!(terms.validate_output(&invalid_output).is_err());
    for altered in [
        Ptlc {
            refund: key(4).x_only_public_key().0,
            ..terms.clone()
        },
        Ptlc {
            funder: key(4).x_only_public_key().0,
            ..terms.clone()
        },
        Ptlc {
            claimant: key(4).x_only_public_key().0,
            ..terms.clone()
        },
        Ptlc {
            payment_point: terms.payment_point.negate(SECP256K1),
            ..terms.clone()
        },
        Ptlc {
            amount: Amount::from_sats(101),
            ..terms.clone()
        },
        Ptlc {
            expiry_block_count: 101,
            ..terms.clone()
        },
    ] {
        assert!(altered.validate_output(&output).is_err());
    }
    let mut invalid = terms.clone();
    invalid.claimant = invalid.funder;
    assert!(invalid.program().is_err());
    for refund in [terms.funder, terms.claimant] {
        invalid = terms.clone();
        invalid.refund = refund;
        assert!(invalid.program().is_err());
    }
    invalid = terms.clone();
    invalid.amount = Amount::ZERO;
    assert!(invalid.program().is_err());
    invalid = terms;
    invalid.expiry_block_count = 0;
    assert!(invalid.program().is_err());
}

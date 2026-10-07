use bitcoin::hashes::{Hash, sha256};
use fedimint_core::config::FederationId;
use fedimint_derive_secret::DerivableSecret;

use super::{BuiltinTemplates, ContractDescriptor, WalletKeys};

fn keys(seed: u8, federation: u8, module: u16) -> WalletKeys {
    WalletKeys::new(
        &DerivableSecret::new_root(&[seed; 32], b"test"),
        FederationId(sha256::Hash::from_byte_array([federation; 32])),
        module,
    )
}

#[test]
fn recovery_annotations_are_randomized_authenticated_and_context_bound() {
    let alice = keys(1, 2, 3);
    let descriptor = ContractDescriptor::owner([4; 32]);
    let first = alice.encrypt(&descriptor).unwrap();
    let second = alice.encrypt(&descriptor).unwrap();
    assert_ne!(first, second);
    assert_eq!(alice.decrypt(&first).unwrap(), Some(descriptor.clone()));
    for other in [keys(9, 2, 3), keys(1, 9, 3), keys(1, 2, 9)] {
        assert_eq!(other.decrypt(&first).unwrap(), None);
        assert_ne!(
            other.signing_key(&descriptor).public_key(),
            alice.signing_key(&descriptor).public_key()
        );
    }
    let mut corrupted = first.clone();
    *corrupted.last_mut().unwrap() ^= 1;
    assert_eq!(alice.decrypt(&corrupted).unwrap(), None);
    for len in 0..32 {
        assert_eq!(alice.decrypt(&first[..len]).unwrap(), None);
    }
}

#[test]
fn descriptors_reproduce_policies_and_preserve_application_context() {
    let alice = keys(1, 2, 3);
    for mut descriptor in [
        ContractDescriptor::owner([3; 32]),
        ContractDescriptor::top_up([4; 32], 17, 21),
    ] {
        descriptor.application_data = b"recoverable application context".to_vec();
        let expected = alice.program(&descriptor, &BuiltinTemplates).unwrap();
        let recovered = keys(1, 2, 3)
            .decrypt(&alice.encrypt(&descriptor).unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(recovered, descriptor);
        let actual = alice.program(&recovered, &BuiltinTemplates).unwrap();
        assert_eq!(actual.0, expected.0);
        assert_eq!(actual.1.cmr(), expected.1.cmr());
    }
    let mut unsupported = ContractDescriptor::owner([1; 32]);
    unsupported.template_version = 2;
    let recovered = alice
        .decrypt(&alice.encrypt(&unsupported).unwrap())
        .unwrap()
        .unwrap();
    assert!(alice.program(&recovered, &BuiltinTemplates).is_err());
    unsupported.application_data = vec![0; 1024];
    assert!(alice.encrypt(&unsupported).is_err());
}

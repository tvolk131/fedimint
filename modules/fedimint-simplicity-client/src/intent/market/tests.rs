use bitcoin::hashes::{Hash, sha256};
use fedimint_core::TransactionId;
use fedimint_core::config::FederationId;
use fedimint_core::secp256k1::{Keypair, SECP256K1};

use super::*;
use crate::common::assets::AssetId;

#[test]
fn follows_the_spending_transaction_and_exact_authorities_not_just_cmr() {
    let key = Keypair::from_seckey_slice(SECP256K1, &[1; 32]).unwrap();
    let market = BinaryMarket {
        federation: FederationId(sha256::Hash::from_byte_array([9; 32])),
        module: 2,
        yes: AssetId([1; 32]),
        no: AssetId([2; 32]),
        event: [3; 32],
        rules: [4; 32],
        oracle: key.x_only_public_key().0,
        resolution_start: 5,
        deadline: 10,
    };
    let point = |id: u8| OutPoint {
        txid: TransactionId::from_raw_hash(sha256::Hash::from_byte_array([id; 32])),
        out_idx: 0,
    };
    let contract = WalletContract {
        output: market
            .program()
            .unwrap()
            .asset_output(
                Amount::ZERO,
                [0; 32],
                vec![],
                AssetBundle {
                    balances: vec![],
                    authorities: vec![market.yes, market.no],
                },
            )
            .unwrap(),
        descriptor: ContractDescriptor::binary_market([0; 32], &market),
        creation_session: 0,
        spent_by: None,
    };
    let mut initial = contract.clone();
    for extra_authority in [false, true] {
        let mut malformed = contract.clone();
        let mut bundle = malformed.output.bundle().unwrap().clone();
        if extra_authority {
            bundle.authorities.push(AssetId([8; 32]));
        } else {
            bundle.balances.push(AssetAmount {
                asset: market.yes,
                quantity: 1,
            });
        }
        malformed.output.extension = Some(crate::common::assets::AssetExtension::Bundle(bundle));
        // Correct policy/state and asset origins alone cannot validate the
        // vault: these authenticated funding outputs are unspendable.
        assert!(successor(point(1), &market, &BTreeMap::from([(point(1), malformed)])).is_err());
    }
    initial.spent_by = Some(point(2).txid);
    let mut contracts = BTreeMap::from([(point(1), initial), (point(3), contract.clone())]);
    assert!(successor(point(1), &market, &contracts).is_err());
    contracts.insert(point(2), contract.clone());
    assert_eq!(
        successor(point(1), &market, &contracts).unwrap().0,
        point(2)
    );
    let mut invalid = contract.clone();
    invalid.output.extension = Some(crate::common::assets::AssetExtension::Bundle(
        AssetBundle::default(),
    ));
    contracts.insert(point(2), invalid);
    assert!(successor(point(1), &market, &contracts).is_err());
    contracts.insert(point(2), contract.clone());
    contracts.insert(
        OutPoint {
            out_idx: 1,
            ..point(2)
        },
        contract,
    );
    assert!(successor(point(1), &market, &contracts).is_err());
}

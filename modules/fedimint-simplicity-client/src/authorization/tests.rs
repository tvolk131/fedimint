use bitcoin::hashes::Hash;
use fedimint_core::TransactionId;
use fedimint_core::secp256k1::{SECP256K1, SecretKey};
use fedimint_core::transaction::TransactionSignature;

use super::*;
use crate::compiler::witnesses;

#[test]
fn finalization_checks_the_combined_resource_budget_before_submission() {
    let owner = Keypair::from_secret_key(SECP256K1, &SecretKey::from_slice(&[1; 32]).unwrap());
    let program = crate::market::owner_program(owner.x_only_public_key().0).unwrap();
    let authorization = Authorization {
        federation: FederationId(Hash::all_zeros()),
        module: 4,
        spends: vec![],
        creations: vec![],
        receipt: None,
        max_fee: None,
    };
    for count in [32, 38] {
        let tx = Transaction {
            inputs: (0..count)
                .map(|index| {
                    DynInput::from_typed(
                        if index % 2 == 0 { 4 } else { 7 },
                        program
                            .input(
                                OutPoint {
                                    txid: TransactionId::from_raw_hash(Hash::all_zeros()),
                                    out_idx: index,
                                },
                                owner.public_key(),
                                witnesses([("SIGNATURE", crate::placeholder_signature())]),
                            )
                            .unwrap(),
                    )
                })
                .collect(),
            outputs: vec![],
            nonce: [0; 8],
            signatures: TransactionSignature::NaiveMultisig(vec![]),
        };
        let result = authorization.verify_finalized(&tx);
        if count == 32 {
            result.unwrap();
        } else {
            assert!(result.unwrap_err().to_string().contains("resource limit"));
        }
    }
}

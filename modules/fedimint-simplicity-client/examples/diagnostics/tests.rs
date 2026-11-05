use bitcoin::hashes::{Hash, sha256};
use fedimint_core::Amount;
use fedimint_core::core::DynOutput;
use fedimint_core::encoding::Encodable as _;
use fedimint_core::transaction::TransactionSignature;
use fedimint_simplicity_client::ContractProgram;
use fedimint_simplicity_client::preflight::Outcome;
use serde_json::json;

use super::*;

fn request() -> serde_json::Value {
    let program = ContractProgram::compile("fn main() {}", Default::default()).unwrap();
    let output = program
        .output(
            Amount::from_msats(100),
            [8; 32],
            b"secret recovery payload".to_vec(),
        )
        .unwrap();
    let tx = Transaction {
        inputs: vec![],
        outputs: vec![DynOutput::from_typed(4, output)],
        nonce: [0; 8],
        signatures: TransactionSignature::NaiveMultisig(vec![]),
    };
    json!({
        "federation_id": FederationId(sha256::Hash::hash(b"cli test")),
        "transaction_hex": tx.consensus_encode_to_hex(),
        "modules": {"4": null},
    })
}

#[test]
fn offline_request_decodes_typed_contracts_and_reports_missing_context() {
    let report = analyze_request(&serde_json::to_vec(&request()).unwrap()).unwrap();
    assert!(!report.has_failures());
    assert!(
        report
            .checks
            .iter()
            .any(|check| check.name == "module_context"
                && matches!(check.outcome, Outcome::NotChecked { .. }))
    );
    let json = serde_json::to_string(&report).unwrap();
    assert!(!json.contains("secret recovery payload"));
    assert!(report.simplicity_fees_msat.unwrap() > 0);
}

#[test]
fn parser_errors_are_bounded_and_do_not_echo_private_input() {
    for bytes in [
        b"private malformed input".to_vec(),
        serde_json::to_vec(&json!({"federation_id": "private malformed input"})).unwrap(),
    ] {
        assert_eq!(
            analyze_request(&bytes).unwrap_err().to_string(),
            "invalid diagnostic request JSON"
        );
    }
    let mut request = request();
    request["transaction_hex"] = json!("private malformed input");
    assert_eq!(
        analyze_request(&serde_json::to_vec(&request).unwrap())
            .unwrap_err()
            .to_string(),
        "invalid transaction encoding"
    );
    assert_eq!(
        analyze_request(&vec![0; MAX_REQUEST_BYTES as usize + 1])
            .unwrap_err()
            .to_string(),
        "diagnostic request exceeds 1 MiB"
    );
}

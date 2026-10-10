use bitcoin::hashes::{Hash, sha256};
use fedimint_core::core::{DynInput, DynOutput};
use fedimint_core::encoding::Encodable as _;
use fedimint_core::secp256k1::{Keypair, SecretKey};
use fedimint_core::{Amount, OutPoint, TransactionId};

use super::*;
use crate::common::StoredContract;
use crate::common::assets::{AssetAmount, AssetBundle, AssetExtension, AssetId};
use crate::{ContractProgram, sign_transaction};

const MODULE: u16 = 4;

fn key() -> Keypair {
    Keypair::from_secret_key(SECP256K1, &SecretKey::from_slice(&[1; 32]).unwrap())
}
fn federation() -> FederationId {
    FederationId(sha256::Hash::hash(b"preflight"))
}

fn fixture(source: &str) -> (Transaction, BTreeMap<u16, PruningSnapshot>) {
    let program = ContractProgram::compile(source, Default::default()).unwrap();
    let point = OutPoint {
        txid: TransactionId::from_raw_hash(sha256::Hash::hash(b"private outpoint")),
        out_idx: 0,
    };
    let output = program
        .output(
            Amount::from_sats(1),
            [42; 32],
            b"private recovery data".to_vec(),
        )
        .unwrap();
    let snapshot = PruningSnapshot {
        contracts: BTreeMap::from([(
            point,
            StoredContract {
                output: output.clone(),
                creation_session: 0,
                creation_block_count: 0,
            },
        )]),
        session_index: 9,
        block_count: 100,
        ..Default::default()
    };
    let mut tx = Transaction {
        inputs: vec![DynInput::from_typed(
            MODULE,
            program
                .input(point, key().public_key(), Default::default())
                .unwrap(),
        )],
        outputs: vec![DynOutput::from_typed(MODULE, output)],
        signatures: TransactionSignature::NaiveMultisig(vec![]),
        nonce: [0; 8],
    };
    let environment = snapshot.environment(federation(), MODULE, &tx, 0).unwrap();
    tx.inputs[0] = DynInput::from_typed(
        MODULE,
        program
            .input_with_environment(point, key().public_key(), Default::default(), &environment)
            .unwrap(),
    );
    sign_transaction(&mut tx, &[key()]).unwrap();
    (tx, BTreeMap::from([(MODULE, snapshot)]))
}

fn check<'a>(report: &'a Report, name: &str) -> &'a Outcome {
    &report
        .checks
        .iter()
        .find(|check| check.name == name)
        .unwrap()
        .outcome
}

#[test]
fn exact_candidate_is_unchanged_and_report_contains_no_spending_material() {
    let (tx, snapshots) = fixture("fn main() {}");
    let before = tx.consensus_encode_to_vec();
    let report = analyze(&tx, federation(), &snapshots);
    assert!(!report.has_failures());
    assert_eq!(
        check(&report, "program_execution_and_pruning"),
        &Outcome::Passed
    );
    assert_eq!(check(&report, "outer_input_signature"), &Outcome::Passed);
    assert!(matches!(
        check(&report, "input_liveness"),
        Outcome::NotChecked { .. }
    ));
    assert!(matches!(
        check(&report, "outer_funding"),
        Outcome::NotChecked { .. }
    ));
    let input = tx.inputs[0]
        .as_any()
        .downcast_ref::<ContractInput>()
        .unwrap();
    let output = tx.outputs[0]
        .as_any()
        .downcast_ref::<ContractOutput>()
        .unwrap();
    assert_eq!(
        report.simplicity_fees_msat,
        Some((runtime::input_fee(input).unwrap() + common::output_fee(output)).msats)
    );
    assert_eq!(
        report.resources.as_ref().unwrap().redemption_bytes,
        input.program.len() + input.witness.len()
    );
    assert_eq!(report.observations[0].session_index, 9);
    let json = serde_json::to_string(&report).unwrap();
    for secret in [
        "private recovery data".to_owned(),
        input.outpoint.txid.to_string(),
        key().public_key().to_string(),
    ] {
        assert!(!json.contains(&secret));
    }
    assert_eq!(tx.consensus_encode_to_vec(), before);
}

#[test]
fn missing_context_and_unsigned_drafts_are_not_reported_as_invalid_spends() {
    let (mut tx, mut snapshots) = fixture("fn main() {}");
    tx.signatures = TransactionSignature::NaiveMultisig(vec![]);
    snapshots.get_mut(&MODULE).unwrap().contracts.clear();
    let report = analyze(&tx, federation(), &snapshots);
    assert!(!report.has_failures());
    assert!(matches!(
        check(&report, "outer_signature_envelope"),
        Outcome::NotChecked { .. }
    ));
    assert!(matches!(
        check(&report, "resolved_inputs"),
        Outcome::NotChecked { .. }
    ));
    assert!(
        !report
            .checks
            .iter()
            .any(|check| check.name == "program_execution_and_pruning")
    );
    let report = analyze(&tx, federation(), &BTreeMap::new());
    assert!(matches!(
        check(&report, "module_context"),
        Outcome::NotChecked { .. }
    ));
}

#[test]
fn wrong_signature_commitment_and_unsupported_active_version_are_distinct() {
    let (mut tx, mut snapshots) = fixture("fn main() {}");
    tx.nonce = [1; 8];
    let report = analyze(&tx, federation(), &snapshots);
    assert!(matches!(
        check(&report, "outer_input_signature"),
        Outcome::Failed {
            code: "invalid_outer_signature",
            ..
        }
    ));
    snapshots
        .get_mut(&MODULE)
        .unwrap()
        .contracts
        .values_mut()
        .next()
        .unwrap()
        .output
        .cmr = [0; 32];
    let report = analyze(&tx, federation(), &snapshots);
    assert!(matches!(
        check(&report, "program_execution_and_pruning"),
        Outcome::Failed {
            code: "commitment_mismatch",
            ..
        }
    ));
    snapshots.get_mut(&MODULE).unwrap().consensus_version = ModuleConsensusVersion::new(9, 9);
    let report = analyze(&tx, federation(), &snapshots);
    assert!(matches!(
        check(&report, "active_version"),
        Outcome::Failed {
            code: "unsupported_version",
            ..
        }
    ));
    assert!(
        !report
            .checks
            .iter()
            .any(|check| check.name == "program_execution_and_pruning")
    );
}

#[test]
fn pruning_and_clock_sensitive_paths_use_the_supplied_observation() {
    let source = "fn main() { match jet::lt_64(jet::fm_session_index(), 10) { true => { assert!(jet::eq_32(42, 42)); }, false => { assert!(jet::eq_64(7, 7)); }, } }";
    let (mut tx, mut snapshots) = fixture(source);
    assert!(!analyze(&tx, federation(), &snapshots).has_failures());
    snapshots.get_mut(&MODULE).unwrap().session_index = 10;
    assert!(matches!(
        check(
            &analyze(&tx, federation(), &snapshots),
            "program_execution_and_pruning"
        ),
        Outcome::Failed {
            code: "program_rejected",
            ..
        }
    ));
    snapshots.get_mut(&MODULE).unwrap().session_index = 9;
    let point = tx.inputs[0]
        .as_any()
        .downcast_ref::<ContractInput>()
        .unwrap()
        .outpoint;
    tx.inputs[0] = DynInput::from_typed(
        MODULE,
        ContractProgram::compile(source, Default::default())
            .unwrap()
            .input(point, key().public_key(), Default::default())
            .unwrap(),
    );
    sign_transaction(&mut tx, &[key()]).unwrap();
    assert!(matches!(
        check(
            &analyze(&tx, federation(), &snapshots),
            "program_execution_and_pruning"
        ),
        Outcome::Failed {
            code: "program_rejected",
            ..
        }
    ));
}

#[test]
fn aggregate_caps_reject_before_execution_across_instances() {
    let (mut tx, snapshots) = fixture("fn main() {}");
    let mut input = tx.inputs[0]
        .as_any()
        .downcast_ref::<ContractInput>()
        .unwrap()
        .clone();
    input.witness = vec![0; common::MAX_WITNESS_BYTES];
    tx.inputs = vec![
        DynInput::from_typed(MODULE, input.clone()),
        DynInput::from_typed(MODULE + 1, input),
    ];
    let report = analyze(&tx, federation(), &snapshots);
    assert!(matches!(
        check(&report, "structure_and_resources"),
        Outcome::Failed {
            code: "resource_limit",
            ..
        }
    ));
    assert!(matches!(
        check(&report, "execution"),
        Outcome::NotChecked { .. }
    ));
    assert!(report.resources.is_none());
}

#[test]
fn asset_conservation_is_checked_but_registry_membership_is_not_invented() {
    let (mut tx, mut snapshots) = fixture("fn main() {}");
    let amount = AssetAmount {
        asset: AssetId([7; 32]),
        quantity: 10,
    };
    let stored = snapshots
        .get_mut(&MODULE)
        .unwrap()
        .contracts
        .values_mut()
        .next()
        .unwrap();
    stored.output.version = 1;
    stored.output.extension = Some(AssetExtension::Bundle(AssetBundle {
        balances: vec![amount],
        authorities: vec![],
    }));
    tx.outputs[0] = DynOutput::from_typed(MODULE, stored.output.clone());
    sign_transaction(&mut tx, &[key()]).unwrap();
    let mut inflated = stored.output.clone();
    let report = analyze(&tx, federation(), &snapshots);
    assert!(!report.has_failures());
    assert!(matches!(
        check(&report, "asset_registry"),
        Outcome::NotChecked { .. }
    ));
    if let Some(AssetExtension::Bundle(bundle)) = &mut inflated.extension {
        bundle.balances[0].quantity += 1;
    }
    tx.outputs[0] = DynOutput::from_typed(MODULE, inflated);
    sign_transaction(&mut tx, &[key()]).unwrap();
    assert!(matches!(
        check(&analyze(&tx, federation(), &snapshots), "asset_accounting"),
        Outcome::Failed {
            code: "invalid_asset_transition",
            ..
        }
    ));
}

#[test]
fn genesis_checks_creation_authorization_and_authority_assignment() {
    let program = ContractProgram::compile("fn main() {}", Default::default()).unwrap();
    let (creation, ids) = crate::assets::creation(federation(), MODULE, &key(), vec![0]).unwrap();
    let authority = program
        .asset_output(
            Amount::ZERO,
            [0; 32],
            vec![],
            AssetBundle {
                authorities: ids,
                balances: vec![],
            },
        )
        .unwrap();
    let mut tx = Transaction {
        inputs: vec![],
        outputs: vec![
            DynOutput::from_typed(MODULE, authority.clone()),
            DynOutput::from_typed(
                MODULE,
                ContractOutput::action_output(AssetActions {
                    creations: vec![creation],
                    ..Default::default()
                }),
            ),
        ],
        nonce: [0; 8],
        signatures: TransactionSignature::NaiveMultisig(vec![]),
    };
    let snapshots = BTreeMap::from([(MODULE, PruningSnapshot::default())]);
    crate::assets::sign_creation(&mut tx, federation(), MODULE, &key()).unwrap();
    let report = analyze(&tx, federation(), &snapshots);
    assert!(!report.has_failures());
    assert_eq!(check(&report, "asset_accounting"), &Outcome::Passed);
    assert!(matches!(
        check(&report, "asset_registry"),
        Outcome::NotChecked { .. }
    ));
    tx.nonce = [1; 8];
    assert!(matches!(
        check(&analyze(&tx, federation(), &snapshots), "asset_accounting"),
        Outcome::Failed {
            code: "invalid_creation_signature",
            ..
        }
    ));
    let mut wrong_authority = authority;
    if let Some(AssetExtension::Bundle(bundle)) = &mut wrong_authority.extension {
        bundle.authorities[0] = AssetId([3; 32]);
    }
    tx.outputs[0] = DynOutput::from_typed(MODULE, wrong_authority);
    crate::assets::sign_creation(&mut tx, federation(), MODULE, &key()).unwrap();
    assert!(matches!(
        check(&analyze(&tx, federation(), &snapshots), "asset_accounting"),
        Outcome::Failed {
            code: "invalid_asset_transition",
            ..
        }
    ));
}

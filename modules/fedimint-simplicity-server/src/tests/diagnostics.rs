//! Compare the offline checker with actual core admission/consensus processing.
use fedimint_simplicity_client::preflight;
use fedimint_simplicity_client::pruning::PruningSnapshot;

use super::*;

#[tokio::test]
async fn local_diagnostics_match_guardian_checks_without_promising_liveness() {
    let fed = Harness::new();
    let owner = key();
    let program = ContractProgram::compile(
        "fn main() { match jet::lt_64(jet::fm_session_index(), 10) { true => { assert!(jet::eq_32(42, 42)); }, false => { assert!(jet::eq_64(7, 7)); }, } }",
        Default::default(),
    ).unwrap();
    let funding = fed
        .fund(vec![DynOutput::from_typed(
            SIMP,
            program
                .output(Amount::from_sats(10), [0; 32], vec![])
                .unwrap(),
        )])
        .await;
    let point = OutPoint {
        txid: funding.tx_hash(),
        out_idx: 0,
    };
    let snapshot = PruningSnapshot {
        session_index: 9,
        contracts: BTreeMap::from([(point, fed.contract(point).await.unwrap())]),
        ..Default::default()
    };
    let draft = program
        .input(point, owner.public_key(), Default::default())
        .unwrap();
    let mut tx = transaction(vec![DynInput::from_typed(SIMP, draft.clone())], vec![]);
    let env = snapshot.environment(federation_id(), SIMP, &tx, 0).unwrap();
    let pruned = program
        .input_with_environment(point, owner.public_key(), Default::default(), &env)
        .unwrap();
    tx.inputs[0] = DynInput::from_typed(SIMP, pruned.clone());
    sign_transaction(&mut tx, &[owner]).unwrap();
    let snapshots = BTreeMap::from([(SIMP, snapshot)]);
    for variant in 0..7 {
        let mut candidate = tx.clone();
        let mut input = pruned.clone();
        match variant {
            0 | 1 => {}
            2 => input = draft.clone(),
            3 => {
                let other = ContractProgram::compile("fn main() {}", Default::default()).unwrap();
                input = other
                    .input(point, owner.public_key(), Default::default())
                    .unwrap();
            }
            4 => input.program = vec![255],
            5 => input.witness = vec![0; MAX_WITNESS_BYTES + 1],
            6 => candidate
                .inputs
                .push(DynInput::from_typed(SIMP, input.clone())),
            _ => unreachable!(),
        }
        candidate.inputs[0] = DynInput::from_typed(SIMP, input);
        let keys = vec![owner; candidate.inputs.len()];
        sign_transaction(&mut candidate, &keys).unwrap();
        if variant == 1 {
            candidate.nonce = [99; 8];
        }
        let report = preflight::analyze(&candidate, federation_id(), &snapshots);
        assert_eq!(report.has_failures(), variant != 0, "{variant}: {report:?}");
        assert_eq!(
            fed.check_submission(&candidate, 9).await.is_err(),
            report.has_failures(),
            "{variant}"
        );
        if variant != 0 {
            assert!(fed.process(&candidate, 9).await.is_err());
            assert!(fed.contract(point).await.is_some());
        }
    }
    // The same exact bytes can pass locally yet fail after the clock advances.
    assert!(!preflight::analyze(&tx, federation_id(), &snapshots).has_failures());
    assert!(fed.check_submission(&tx, 10).await.is_err());
    fed.process(&tx, 9).await.unwrap();
    // Old observations cannot prove that an input is still live either.
    assert!(!preflight::analyze(&tx, federation_id(), &snapshots).has_failures());
    assert!(fed.check_submission(&tx, 9).await.is_err());
}

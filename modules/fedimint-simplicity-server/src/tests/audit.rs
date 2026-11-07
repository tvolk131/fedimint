use fedimint_core::TransactionId;
use fedimint_simplicity_common::{ContractOutput, resources};
use futures::StreamExt;

use super::*;
use crate::db::{ContractPrefix, insert_contract, live_contract_total};

/// Audit the module alone, returning its item count and net assets. Each item
/// is one line between the balance sheet header and the net assets footer.
async fn audit(module: &Simplicity, db: &Database) -> (usize, i64) {
    let mut audit = Audit::default();
    module
        .audit(&mut db.begin_transaction_nc().await, &mut audit, SIMP)
        .await;
    (
        audit.to_string().lines().count() - 2,
        audit.net_assets().unwrap().milli_sat,
    )
}

fn point(out_idx: u64) -> OutPoint {
    OutPoint {
        txid: TransactionId::from_raw_hash(sha256::Hash::hash(b"simplicity-audit")),
        out_idx,
    }
}

fn stored(output: &fedimint_simplicity_common::ContractOutput, amount: Amount) -> StoredContract {
    let mut output = output.clone();
    output.amount = amount;
    StoredContract {
        output,
        creation_session: 0,
        creation_block_count: 0,
    }
}

/// The running total, the contract table it summarizes, and the audit must all
/// agree on the expected liability.
async fn assert_liability(fed: &Harness, expected: Amount) {
    let db = fed.db.with_prefix_module_id(SIMP).0;
    let mut dbtx = db.begin_transaction_nc().await;
    let scanned = dbtx
        .find_by_prefix(&ContractPrefix)
        .await
        .fold(Amount::ZERO, |total, (_, contract)| async move {
            total + contract.output.amount
        })
        .await;
    assert_eq!(scanned, expected);
    assert_eq!(live_contract_total(&mut dbtx).await, expected);
    assert_eq!(fed.audit().await, -(expected.msats as i64));
}

#[tokio::test]
async fn unfunded_outputs_cannot_overflow_the_live_contract_total() {
    let fed = Harness::new();
    let program = contract_program(&key(), 0, 0);
    // Every output is individually permitted, but their sum exceeds u64.
    // Output processing must reject this before core checks the funding,
    // without panicking or retaining any of the preceding insertions.
    let tx = transaction(
        vec![],
        (0..9)
            .map(|index| {
                DynOutput::from_typed(
                    SIMP,
                    program
                        .output(
                            Amount::from_msats(2_100_000_000_000_000_000),
                            [index; 32],
                            vec![],
                        )
                        .unwrap(),
                )
            })
            .collect(),
    );
    assert_eq!(
        resources::check_transaction(&tx),
        Ok(()),
        "the overflow fixture must pass structural and resource validation"
    );
    let total_msats: u128 = tx
        .outputs
        .iter()
        .map(|output| {
            u128::from(
                output
                    .as_any()
                    .downcast_ref::<ContractOutput>()
                    .unwrap()
                    .amount
                    .msats,
            )
        })
        .sum();
    assert!(
        total_msats > u128::from(u64::MAX),
        "the overflow fixture must exceed the live total's u64 range"
    );
    for mode in [TxProcessingMode::Submission, TxProcessingMode::Consensus] {
        let result = match mode {
            TxProcessingMode::Submission => fed.check_submission(&tx, 0).await,
            TxProcessingMode::Consensus => fed.process(&tx, 0).await,
        };
        let error = result.unwrap_err();
        let Some(TransactionError::Output(error)) = error.downcast_ref::<TransactionError>() else {
            panic!("expected an output overflow error: {error:#}");
        };
        assert_eq!(
            error
                .as_any()
                .downcast_ref::<fedimint_simplicity_common::ContractOutputError>()
                .unwrap()
                .0,
            ContractError::Limit
        );
        assert_liability(&fed, Amount::ZERO).await;
        for out_idx in 0..9 {
            assert!(
                fed.contract(OutPoint {
                    txid: tx.tx_hash(),
                    out_idx
                })
                .await
                .is_none()
            );
        }
    }
}

#[tokio::test]
async fn funding_failure_rolls_back_contracts_and_live_total() {
    let fed = Harness::new();
    let owner = key();
    let program = contract_program(&owner, 0, 0);
    let amount = Amount::from_sats(100);
    let funding = fed
        .fund(vec![DynOutput::from_typed(
            SIMP,
            program.output(amount, [0; 32], vec![]).unwrap(),
        )])
        .await;
    let input = OutPoint {
        txid: funding.tx_hash(),
        out_idx: 0,
    };
    let original = fed.contract(input).await.unwrap();
    let mut tx = draft_spend(
        &program,
        input,
        &owner,
        true,
        vec![DynOutput::from_typed(
            SIMP,
            program
                .output(Amount::from_sats(101), [1; 32], vec![])
                .unwrap(),
        )],
    );
    authorize(&fed, &mut tx, &program, input, &owner, true, &[]).await;
    // Core discovers the shortfall only after removing the input and adding
    // its successor, which have also subtracted from and added to the total.
    let error = fed.process(&tx, 0).await.unwrap_err();
    assert!(matches!(
        error.downcast_ref::<TransactionError>(),
        Some(TransactionError::UnbalancedTransaction { .. })
    ));
    assert_eq!(fed.contract(input).await.unwrap(), original);
    assert!(
        fed.contract(OutPoint {
            txid: tx.tx_hash(),
            out_idx: 0
        })
        .await
        .is_none()
    );
    assert_liability(&fed, amount).await;
}

#[tokio::test]
async fn audit_total_follows_contract_creation_and_spends() {
    let fed = Harness::new();
    assert_liability(&fed, Amount::ZERO).await;
    let owner = key();
    let program = contract_program(&owner, 0, 0);
    let funding = fed
        .fund(
            [Amount::from_sats(100), Amount::from_sats(250), Amount::ZERO]
                .into_iter()
                .enumerate()
                .map(|(index, amount)| {
                    DynOutput::from_typed(
                        SIMP,
                        program.output(amount, [index as u8; 32], vec![]).unwrap(),
                    )
                })
                .collect(),
        )
        .await;
    let created = |out_idx| OutPoint {
        txid: funding.tx_hash(),
        out_idx,
    };
    assert_liability(&fed, Amount::from_sats(350)).await;

    let mut release = draft_spend(
        &program,
        created(0),
        &owner,
        true,
        vec![MintRequest::new(Denomination(10)).output()],
    );
    authorize(&fed, &mut release, &program, created(0), &owner, true, &[]).await;
    fed.process(&release, 0).await.unwrap();
    assert_liability(&fed, Amount::from_sats(250)).await;
    assert!(
        fed.process(&release, 0).await.is_err(),
        "contract cannot be spent twice"
    );
    assert_liability(&fed, Amount::from_sats(250)).await;

    // Spending into a successor subtracts the consumed contract and adds the
    // new one in the same transaction.
    let successor = program
        .output(Amount::from_sats(40), [9; 32], vec![])
        .unwrap();
    let mut respend = draft_spend(
        &program,
        created(1),
        &owner,
        true,
        vec![DynOutput::from_typed(SIMP, successor)],
    );
    authorize(&fed, &mut respend, &program, created(1), &owner, true, &[]).await;
    fed.process(&respend, 0).await.unwrap();
    assert_liability(&fed, Amount::from_sats(40)).await;
}

#[tokio::test]
async fn audit_reads_one_total_regardless_of_contract_count() {
    let module = Simplicity::new_for_testing(vec![PeerId::from(0)]).unwrap();
    let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());
    let output = contract_program(&key(), 0, 0)
        .output(Amount::ZERO, [0; 32], vec![])
        .unwrap();

    let mut expected = 0;
    let mut created = 0;
    for count in [1, 1_000] {
        let mut dbtx = db.begin_transaction().await;
        for index in created..count {
            insert_contract(
                &mut dbtx.to_ref_nc(),
                point(index),
                &stored(&output, Amount::from_msats(index + 1)),
            )
            .await
            .unwrap();
            expected += index + 1;
        }
        dbtx.commit_tx().await;
        created = count;
        assert_eq!(audit(&module, &db).await, (1, -(expected as i64)));
    }

    // A contract written without updating the total is invisible to the
    // audit, so it never scans the contract table.
    let mut dbtx = db.begin_transaction().await;
    dbtx.insert_new_entry(
        &ContractKey(point(created)),
        &stored(&output, Amount::from_sats(1)),
    )
    .await;
    dbtx.commit_tx().await;
    assert_eq!(audit(&module, &db).await, (1, -(expected as i64)));
}

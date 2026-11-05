//! Admission does not freeze consensus clocks or permanently cache rejection.
use super::*;

#[tokio::test]
async fn a_vote_before_execution_in_the_same_session_closes_claim_and_opens_refund() {
    for version in [0, 1] {
        let fed = Harness::new();
        let owner = key();
        let program = ContractProgram::compile(
            "fn main() {
                match witness::REFUND {
                    false => assert!(jet::lt_64(jet::fm_block_count(), 10)),
                    true => assert!(jet::le_64(10, jet::fm_block_count())),
                }
            }",
            arguments([]),
        )
        .unwrap();
        let mut contract = program
            .output(Amount::from_sats(10), [0; 32], vec![])
            .unwrap();
        contract.version = version;
        if version == 1 {
            contract.extension = Some(AssetExtension::Bundle(bundle(&[], &[])));
        }
        let funding = fed.fund(vec![output(contract)]).await;
        let origin = point(&funding, 0);
        let build = async |refund| {
            let input = program
                .input(
                    origin,
                    owner.public_key(),
                    witnesses([("REFUND", Value::from(refund))]),
                )
                .unwrap();
            let (mut tx, sponsor) = sponsored(vec![DynInput::from_typed(SIMP, input)], vec![]);
            fed.sign(&mut tx, &[owner, sponsor]).await.unwrap();
            tx
        };
        let claim = build(false).await;
        let refund = build(true).await;
        fed.vote(9).await;
        fed.check_submission(&claim, 7).await.unwrap();
        assert_error(fed.check_submission(&refund, 7).await, "program rejected");
        assert_error(fed.process(&refund, 7).await, "program rejected");
        let before = fed.contract(origin).await.unwrap();
        // The session has not changed. An earlier ordered module vote suffices.
        fed.vote(10).await;
        assert_error(fed.process(&claim, 7).await, "program rejected");
        assert_eq!(fed.contract(origin).await.unwrap(), before);
        // The identical previously rejected bytes now succeed at the boundary.
        fed.process(&refund, 7).await.unwrap();
        assert!(fed.contract(origin).await.is_none());
    }
}

#[tokio::test]
async fn an_unspent_path_can_close_and_reopen_without_rebuilding_the_transaction() {
    for version in [0, 1] {
        let fed = Harness::new();
        let owner = key();
        let program = ContractProgram::compile(
            "fn main() {
                assert!(jet::eq_64(jet::fm_session_index(), jet::fm_block_count()));
            }",
            arguments([]),
        )
        .unwrap();
        let mut contract = program
            .output(Amount::from_sats(10), [0; 32], vec![])
            .unwrap();
        contract.version = version;
        if version == 1 {
            contract.extension = Some(AssetExtension::Bundle(bundle(&[], &[])));
        }
        let funding = fed.fund(vec![output(contract)]).await;
        let origin = point(&funding, 0);
        let input = program
            .input(origin, owner.public_key(), witnesses([]))
            .unwrap();
        let (mut tx, sponsor) = sponsored(vec![DynInput::from_typed(SIMP, input)], vec![]);
        sign_transaction(&mut tx, &[owner, sponsor]).unwrap();
        fed.vote(2).await;
        fed.check_submission(&tx, 2).await.unwrap();
        for _ in 0..2 {
            assert_error(fed.check_submission(&tx, 3).await, "program rejected");
            assert_error(fed.process(&tx, 3).await, "program rejected");
            assert!(fed.contract(origin).await.is_some());
        }
        fed.vote(4).await;
        fed.check_submission(&tx, 4).await.unwrap();
        fed.process(&tx, 4).await.unwrap();
        assert!(fed.contract(origin).await.is_none());
        assert!(fed.process(&tx, 4).await.is_err());
    }
}

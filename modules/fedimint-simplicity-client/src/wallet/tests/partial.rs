use std::collections::BTreeMap;

use super::*;
use crate::descriptor::SuccessorPosition;
use crate::exchange::{OrderState, PartialLimitOrder};
use crate::intent::IntentContext;

#[derive(Debug)]
struct PartialTemplates;
impl ContractTemplates for PartialTemplates {
    fn compile(
        &self,
        descriptor: &ContractDescriptor,
        owner: fedimint_core::secp256k1::XOnlyPublicKey,
    ) -> anyhow::Result<(u32, crate::ContractProgram)> {
        if descriptor.template == "partial" {
            let order = PartialLimitOrder::consensus_decode_whole(
                &descriptor.parameters,
                &Default::default(),
            )?;
            Ok((1, order.program()?))
        } else {
            BuiltinTemplates.compile(descriptor, owner)
        }
    }
    fn is_successor(
        &self,
        descriptor: &ContractDescriptor,
        before: &ContractOutput,
        after: &ContractOutput,
        position: SuccessorPosition,
    ) -> bool {
        descriptor.template == "partial"
            && position.input_index == position.output_index
            && before.cmr == after.cmr
            && PartialLimitOrder::consensus_decode_whole(
                &descriptor.parameters,
                &Default::default(),
            )
            .is_ok_and(|order| order.state(before).is_ok() && order.state(after).is_ok())
    }
}

#[tokio::test]
async fn partial_order_recovery_uses_assigned_successors_not_policy_lookalikes() {
    let keys = WalletKeys::new(&root(), federation(), MODULE);
    let mut descriptor = ContractDescriptor::owner([41; 32]);
    let order = PartialLimitOrder {
        module: MODULE,
        maker: keys.signing_key(&descriptor).x_only_public_key().0,
        asset: AssetId([5; 32]),
        unit_price: Amount::from_msats(333),
        buy: false,
        close_block: 100,
    };
    descriptor.template = "partial".into();
    descriptor.parameters = order.consensus_encode_to_vec();
    let output = |state, recovery| {
        let (amount, bundle) = order.balances(state).unwrap();
        order
            .program()
            .unwrap()
            .asset_output(amount, [0; 32], recovery, bundle)
            .unwrap()
    };
    let creation = tx(
        0,
        &[],
        vec![output(
            OrderState::new(10),
            keys.encrypt(&descriptor).unwrap(),
        )],
    );
    let before = OrderState::new(10);
    let after = order.fill(before, 3).unwrap();
    let unrelated = OutPoint {
        txid: point(&creation).txid,
        out_idx: 9,
    };
    // The tracked order is module-local input 1, despite a foreign input before
    // it. Only absolute output 1 is its successor; 0 and 2 copy the same policy.
    let mut fill = tx(
        1,
        &[unrelated, point(&creation)],
        vec![output(after, vec![]); 3],
    );
    fill.inputs.insert(
        0,
        DynInput::from_typed(1234, fedimint_core::core::DynUnknown(vec![9])),
    );
    let next = OutPoint {
        txid: fill.tx_hash(),
        out_idx: 1,
    };
    let claim = tx(2, &[next], vec![output(OrderState::new(7), vec![])]);
    let cancel = tx(3, &[point(&claim)], vec![]);
    let history = [
        session(&[creation.clone(), fill.clone()]),
        session(&[claim.clone(), cancel.clone()]),
    ];
    for _ in 0..2 {
        let store = WalletStore::open(
            database(),
            &root(),
            federation(),
            MODULE,
            Arc::new(PartialTemplates),
        )
        .await
        .unwrap();
        store.apply_session(0, &history[0], false).await.unwrap();
        store.apply_session(0, &history[0], true).await.unwrap();
        let mut dbtx = store.db.begin_transaction_nc().await;
        assert_eq!(
            dbtx.get_value(&db::SuccessorKey(point(&creation))).await,
            Some(next)
        );
        let context = IntentContext {
            contracts: store.contracts().await.into_iter().collect(),
            successors: BTreeMap::from([(point(&creation), next)]),
        };
        assert_eq!(context.current(point(&creation)).unwrap().0, next);
        assert_eq!(context.contracts.len(), 2);
        assert_eq!(context.contracts[&next].descriptor, descriptor);
        drop(dbtx);
        store.apply_session(1, &history[1], true).await.unwrap();
        let contracts = store.contracts().await;
        assert_eq!(contracts.len(), 3);
        assert!(contracts.iter().all(|(_, c)| c.spent_by.is_some()));
        assert_eq!(store.history().await.len(), 4);
        let context = IntentContext {
            contracts: contracts.into_iter().collect(),
            successors: BTreeMap::from([(point(&creation), next), (next, point(&claim))]),
        };
        assert!(context.current(point(&creation)).is_err());
    }
}

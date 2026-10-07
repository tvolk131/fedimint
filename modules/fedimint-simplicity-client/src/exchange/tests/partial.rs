use super::*;

fn terms(buy: bool) -> PartialLimitOrder {
    PartialLimitOrder {
        module: 2,
        maker: key(6).x_only_public_key().0,
        asset: AssetId([1; 32]),
        unit_price: Amount::from_msats(333),
        buy,
        close_block: 100,
    }
}
fn output(order: &PartialLimitOrder, state: OrderState) -> ContractOutput {
    let (amount, bundle) = order.balances(state).unwrap();
    order
        .program()
        .unwrap()
        .asset_output(amount, [0; 32], vec![], bundle)
        .unwrap()
}

#[test]
fn partial_fills_accumulate_exact_proceeds_and_finish_without_rounding() {
    for buy in [false, true] {
        let order = terms(buy);
        let program = order.program().unwrap();
        let mut before = OrderState::new(101);
        for quantity in [1, 17, 80, 3] {
            let after = order.fill(before, quantity).unwrap();
            let env = environment(
                vec![output(&order, before)],
                vec![output(&order, after)],
                0,
                Default::default(),
            );
            assert!(execute(
                &program,
                &env,
                PartialLimitOrder::witnesses(false, before.remaining, quantity)
            ));
            assert_eq!(
                order
                    .state(&env.outputs[0].contract.clone().unwrap())
                    .unwrap(),
                after
            );
            before = after;
        }
        assert_eq!(before.remaining, 0);
        assert_eq!(
            before.bitcoin_proceeds.msats,
            if buy { 0 } else { 101 * 333 }
        );
        assert_eq!(before.position_proceeds, if buy { 101 } else { 0 });
        assert!(order.fill(before, 1).is_err());
    }
}

#[test]
fn partial_fills_reject_stolen_proceeds_wrong_successors_and_aliases() {
    for buy in [false, true] {
        let order = terms(buy);
        let program = order.program().unwrap();
        let before = order.fill(OrderState::new(100), 25).unwrap();
        let after = order.fill(before, 25).unwrap();
        let old = output(&order, before);
        let new = output(&order, after);
        let witness = || PartialLimitOrder::witnesses(false, before.remaining, 25);
        for case in 0..9 {
            let mut env = environment(vec![old.clone()], vec![new.clone()], 0, Default::default());
            let target = Arc::make_mut(&mut env.outputs)[0]
                .contract
                .as_mut()
                .unwrap();
            match case {
                0 => target.amount = Amount::from_msats(target.amount.msats + 1),
                1 => target.amount = Amount::from_msats(target.amount.msats.saturating_sub(1)),
                2 => target.cmr[0] ^= 1,
                3 => target.state[0] ^= 1,
                4 => target.version = 0,
                5 => {
                    target.extension = Some(crate::common::assets::AssetExtension::Bundle(
                        balances(&[(order.asset, 50), (AssetId([2; 32]), 1)], &[]),
                    ))
                }
                6 => {
                    target.extension = Some(crate::common::assets::AssetExtension::Bundle(
                        balances(&[(order.asset, 50)], &[AssetId([3; 32])]),
                    ))
                }
                7 => {
                    // Reusing the previous payment cannot pay for a second fill.
                    let unpaid = OrderState {
                        remaining: after.remaining,
                        ..before
                    };
                    *target = output(&order, unpaid);
                }
                _ => Arc::make_mut(&mut env.outputs)[0].contract = None,
            }
            assert!(
                !execute(&program, &env, witness()),
                "buy={buy}, case={case}"
            );
        }
        let mut env = environment(
            vec![old.clone(), old],
            vec![new.clone(), new],
            0,
            Default::default(),
        );
        assert!(execute(&program, &env, witness()));
        env.input_index = 1;
        assert!(execute(&program, &env, witness()));
        env.outputs = vec![env.outputs[0].clone()].into();
        assert!(!execute(&program, &env, witness()));
        env.input_index = 0;
        for (remaining, fill) in [(75, 0), (75, 76), (74, 25), (u64::MAX, u64::MAX)] {
            assert!(!execute(
                &program,
                &env,
                PartialLimitOrder::witnesses(false, remaining, fill)
            ));
        }
        env.block_count = order.close_block;
        assert!(!execute(&program, &env, witness()));
        for signer in [key(6), key(7)] {
            let signature = SECP256K1
                .sign_schnorr_no_aux_rand(&Message::from_digest(env.signature_hash), &signer);
            let witness = witnesses([
                ("MAKER_ACTION", Value::from(true)),
                ("REMAINING", Value::u64(0)),
                ("FILL", Value::u64(0)),
                ("SIGNATURE", Value::byte_array(*signature.as_ref())),
            ]);
            assert_eq!(execute(&program, &env, witness), signer == key(6));
        }
    }
}

#[test]
fn partial_order_checked_arithmetic_rejects_unrepresentable_transitions() {
    let mut sell = terms(false);
    sell.unit_price = Amount::from_msats(u64::MAX);
    assert!(sell.fill(OrderState::new(2), 2).is_err());
    let before = OrderState {
        bitcoin_proceeds: Amount::from_msats(1),
        ..OrderState::new(1)
    };
    assert!(sell.fill(before, 1).is_err());
    let buy = terms(true);
    assert!(
        buy.fill(
            OrderState {
                position_proceeds: u64::MAX,
                ..OrderState::new(1)
            },
            1
        )
        .is_err()
    );
    assert!(buy.balances(OrderState::new(u64::MAX)).is_err());
}

#[test]
fn vm_rejects_payment_and_proceeds_overflow() {
    for buy in [false, true] {
        let mut order = terms(buy);
        order.unit_price = Amount::from_msats(u64::MAX);
        let program = order.program().unwrap();
        let old = output(&order, OrderState::new(1));
        let env = environment(vec![old.clone()], vec![old], 0, Default::default());
        assert!(!execute(
            &program,
            &env,
            PartialLimitOrder::witnesses(false, 2, 2)
        ));
        let order = terms(buy);
        let before = OrderState {
            remaining: 1,
            bitcoin_proceeds: if buy {
                Amount::ZERO
            } else {
                Amount::from_msats(u64::MAX)
            },
            position_proceeds: if buy { u64::MAX } else { 0 },
        };
        let old = output(&order, before);
        let new = output(&order, OrderState::new(0));
        let env = environment(vec![old], vec![new], 0, Default::default());
        assert!(!execute(
            &order.program().unwrap(),
            &env,
            PartialLimitOrder::witnesses(false, 1, 1)
        ));
    }
}

#[test]
fn amm_and_partial_orders_use_disjoint_successor_slots() {
    let pool = pool();
    let reserves = PoolReserves {
        yes: 1000,
        no: 1000,
        fees: Amount::ZERO,
    };
    let quote = reserves.buy(true, 10).unwrap();
    let mut env = trade_environment(&pool, reserves, quote);
    let order = terms(false);
    let before = OrderState::new(10);
    let after = order.fill(before, 3).unwrap();
    let mut inputs = env.inputs.to_vec();
    inputs.push(EnvironmentInput {
        outpoint: OutPoint {
            out_idx: 2,
            ..inputs[0].outpoint
        },
        contract: output(&order, before),
    });
    env.inputs = inputs.into();
    env.input_count = 3;
    let mut outputs = env.outputs.to_vec();
    outputs.push(
        environment(
            vec![output(&order, before)],
            vec![output(&order, after)],
            0,
            Default::default(),
        )
        .outputs[0]
            .clone(),
    );
    env.outputs = outputs.into();
    assert!(execute(
        &pool.program().unwrap(),
        &env,
        ConstantProductPool::witnesses(quote.action, 0)
    ));
    env.input_index = 2;
    env.current = env.inputs[2].contract.clone();
    assert!(execute(
        &order.program().unwrap(),
        &env,
        PartialLimitOrder::witnesses(false, 10, 3)
    ));
    // Placing the order's successor in the AMM's slot cannot satisfy the order.
    Arc::make_mut(&mut env.outputs).swap(1, 2);
    assert!(!execute(
        &order.program().unwrap(),
        &env,
        PartialLimitOrder::witnesses(false, 10, 3)
    ));
}

mod partial;

use std::sync::Arc;

use bitcoin::hashes::{Hash as _, sha256};
use fedimint_core::config::FederationId;
use fedimint_core::secp256k1::{Keypair, Message, SECP256K1, SecretKey};
use fedimint_core::{OutPoint, TransactionId};

use super::*;
use crate::common::assets::AssetActions;
use crate::common::runtime::{self, Environment, EnvironmentInput, EnvironmentOutput};

fn key(byte: u8) -> Keypair {
    Keypair::from_secret_key(SECP256K1, &SecretKey::from_slice(&[byte; 32]).unwrap())
}

fn pool() -> ConstantProductPool {
    ConstantProductPool {
        market: BinaryMarket {
            federation: FederationId(sha256::Hash::hash(b"exchange tests")),
            module: 2,
            yes: AssetId([1; 32]),
            no: AssetId([2; 32]),
            event: [3; 32],
            rules: [4; 32],
            oracle: key(9).x_only_public_key().0,
            resolution_start: 100,
            deadline: 200,
        },
        identity: AssetId([5; 32]),
        provider: key(6).x_only_public_key().0,
    }
}

fn environment(
    inputs: Vec<ContractOutput>,
    outputs: Vec<ContractOutput>,
    index: usize,
    actions: AssetActions,
) -> Environment {
    Environment {
        current: inputs[index].clone(),
        signature_hash: [8; 32],
        session_index: 10,
        block_count: 50,
        creation_session: 1,
        creation_block_count: 1,
        input_index: index as u32,
        input_count: inputs.len() as u32,
        inputs: inputs
            .into_iter()
            .enumerate()
            .map(|(i, contract)| EnvironmentInput {
                outpoint: OutPoint {
                    txid: TransactionId::from_raw_hash(sha256::Hash::hash(b"input")),
                    out_idx: i as u64,
                },
                contract,
            })
            .collect::<Vec<_>>()
            .into(),
        outputs: outputs
            .into_iter()
            .map(|contract| EnvironmentOutput {
                hash: DynOutput::from_typed(2, contract.clone())
                    .consensus_hash_sha256()
                    .to_byte_array(),
                module_id: 2,
                contract: Some(contract),
            })
            .collect::<Vec<_>>()
            .into(),
        actions: Arc::new(actions),
    }
}

fn execute(program: &ContractProgram, env: &Environment, witness: WitnessValues) -> bool {
    let input = program
        .input(
            env.inputs[env.input_index as usize].outpoint,
            key(7).public_key(),
            witness,
        )
        .unwrap();
    runtime::execute(&input, env).is_ok()
}

fn order() -> LimitOrder {
    let maker = key(6).x_only_public_key().0;
    LimitOrder {
        module: 2,
        maker,
        asset: AssetId([1; 32]),
        quantity: 100,
        price: Amount::from_sats(40),
        buy: false,
        close_block: 100,
        payment: owner_program(maker)
            .unwrap()
            .asset_output(
                Amount::from_sats(40),
                [0; 32],
                vec![1, 2, 3],
                AssetBundle::default(),
            )
            .unwrap(),
    }
}

#[test]
fn whole_fill_requires_the_exact_payment_and_does_not_alias_other_inputs() {
    for buy in [false, true] {
        let mut order = order();
        order.buy = buy;
        if buy {
            order.payment.amount = Amount::ZERO;
            order.payment.extension = Some(crate::common::assets::AssetExtension::Bundle(
                balances(&[(order.asset, order.quantity)], &[]),
            ));
        }
        let program = order.program().unwrap();
        let (amount, bundle) = order.escrow();
        let escrow = program
            .asset_output(amount, [0; 32], vec![], bundle)
            .unwrap();
        order.validate_output(&escrow).unwrap();
        let env = environment(
            vec![escrow.clone()],
            vec![order.payment.clone()],
            0,
            Default::default(),
        );
        assert!(execute(&program, &env, LimitOrder::witnesses(false)));
        // A foreign-instance output retains its hash but has no typed contract
        // in this instance's environment. It cannot discharge a second order.
        let mut foreign = env.clone();
        Arc::make_mut(&mut foreign.outputs)[0].contract = None;
        assert!(!execute(&program, &foreign, LimitOrder::witnesses(false)));
        for case in 0..4 {
            let mut payment = order.payment.clone();
            match case {
                0 => payment.amount = Amount::from_msats(payment.amount.msats + 1),
                1 => payment.cmr[0] ^= 1,
                2 => payment.recovery.push(4),
                _ => payment.state[0] ^= 1,
            }
            let bad = environment(vec![escrow.clone()], vec![payment], 0, Default::default());
            assert!(!execute(&program, &bad, LimitOrder::witnesses(false)));
        }
        let alias = environment(
            vec![escrow.clone(), escrow.clone()],
            vec![order.payment.clone()],
            1,
            Default::default(),
        );
        assert!(!execute(&program, &alias, LimitOrder::witnesses(false)));
        let mut expired = env.clone();
        expired.block_count = 100;
        assert!(!execute(&program, &expired, LimitOrder::witnesses(false)));
        for signer in [key(6), key(7)] {
            let signature = SECP256K1
                .sign_schnorr_no_aux_rand(&Message::from_digest(env.signature_hash), &signer);
            let witness = witnesses([
                ("CANCEL", Value::from(true)),
                ("SIGNATURE", Value::byte_array(*signature.as_ref())),
            ]);
            assert_eq!(execute(&program, &expired, witness), signer == key(6));
        }
    }
}

fn trade_environment(
    pool: &ConstantProductPool,
    reserves: PoolReserves,
    quote: PoolQuote,
) -> Environment {
    let program = pool.program().unwrap();
    let vault = pool
        .market
        .program()
        .unwrap()
        .asset_output(
            Amount::from_sats(10000),
            [0; 32],
            vec![],
            balances(&[], &[pool.market.yes, pool.market.no]),
        )
        .unwrap();
    let before = program
        .asset_output(reserves.fees, [0; 32], vec![], pool.bundle(reserves))
        .unwrap();
    let after = program
        .asset_output(quote.after.fees, [0; 32], vec![], pool.bundle(quote.after))
        .unwrap();
    let quantities = balances(
        &[
            (pool.market.yes, quote.collateral_sats),
            (pool.market.no, quote.collateral_sats),
        ],
        &[],
    )
    .balances;
    let actions = if quote.action < 2 {
        AssetActions {
            issuance: quantities,
            ..Default::default()
        }
    } else {
        AssetActions {
            burns: quantities,
            ..Default::default()
        }
    };
    environment(vec![vault.clone(), before], vec![vault, after], 1, actions)
}

#[test]
fn amm_executes_all_sides_and_rejects_fee_policy_identity_and_clock_mutations() {
    let pool = pool();
    let program = pool.program().unwrap();
    for reserves in [
        PoolReserves {
            yes: 1000,
            no: 1000,
            fees: Amount::ZERO,
        },
        PoolReserves {
            yes: 1 << 40,
            no: 1 << 40,
            fees: Amount::from_msats(50),
        },
    ] {
        for yes in [false, true] {
            for quote in [
                reserves.buy(yes, 250).unwrap(),
                reserves.sell(yes, 450).unwrap(),
            ] {
                let env = trade_environment(&pool, reserves, quote);
                assert!(execute(
                    &program,
                    &env,
                    ConstantProductPool::witnesses(quote.action, 0)
                ));
                for case in 0..6 {
                    let mut bad = env.clone();
                    match case {
                        0 => {
                            Arc::make_mut(&mut bad.outputs)[1]
                                .contract
                                .as_mut()
                                .unwrap()
                                .amount
                                .msats -= 1
                        }
                        1 => {
                            Arc::make_mut(&mut bad.outputs)[1]
                                .contract
                                .as_mut()
                                .unwrap()
                                .cmr[0] ^= 1
                        }
                        2 => bad.block_count = 100,
                        3 => Arc::make_mut(&mut bad.inputs)[0].contract.cmr[0] ^= 1,
                        4 => {
                            Arc::make_mut(&mut bad.outputs)[1]
                                .contract
                                .as_mut()
                                .unwrap()
                                .extension =
                                Some(crate::common::assets::AssetExtension::Bundle(balances(
                                    &[
                                        (pool.market.yes, quote.after.yes),
                                        (pool.market.no, quote.after.no),
                                    ],
                                    &[],
                                )))
                        }
                        _ => Arc::make_mut(&mut bad.actions).issuance.push(AssetAmount {
                            asset: pool.identity,
                            quantity: 1,
                        }),
                    }
                    assert!(
                        !execute(
                            &program,
                            &bad,
                            ConstantProductPool::witnesses(quote.action, 0)
                        ),
                        "mutation {case}"
                    );
                }
            }
        }
    }
}

#[test]
fn liquidity_changes_require_the_provider_and_exact_integer_proportions() {
    let pool = pool();
    let program = pool.program().unwrap();
    let reserves = PoolReserves {
        yes: 801,
        no: 1251,
        fees: Amount::from_msats(42),
    };
    for scale in [5000, 10000, 15000] {
        let after = reserves.scale(scale).unwrap();
        let before = program
            .asset_output(reserves.fees, [0; 32], vec![], pool.bundle(reserves))
            .unwrap();
        let output = program
            .asset_output(Amount::ZERO, [0; 32], vec![], pool.bundle(after))
            .unwrap();
        let env = environment(vec![before], vec![output], 0, Default::default());
        for signer in [key(6), key(7)] {
            let signature = SECP256K1
                .sign_schnorr_no_aux_rand(&Message::from_digest(env.signature_hash), &signer);
            let witness = witnesses([
                ("ACTION", Value::u8(4)),
                ("SCALE", Value::u64(scale)),
                ("SIGNATURE", Value::byte_array(*signature.as_ref())),
            ]);
            assert_eq!(execute(&program, &env, witness.clone()), signer == key(6));
            let mut bad = env.clone();
            let output = Arc::make_mut(&mut bad.outputs)[0]
                .contract
                .as_mut()
                .unwrap();
            output.extension = Some(crate::common::assets::AssetExtension::Bundle(pool.bundle(
                PoolReserves {
                    yes: after.yes + 1,
                    ..after
                },
            )));
            assert!(!execute(&program, &bad, witness));
        }
    }
}

#[test]
fn integer_quotes_preserve_product_and_round_trips_cannot_make_money() {
    for y in [2, 10, 1000, 1 << 40] {
        for n in [2, 11, 1000, 1 << 40] {
            for amount in [1, 2, 100, 250] {
                let reserves = PoolReserves {
                    yes: y,
                    no: n,
                    fees: Amount::ZERO,
                };
                for yes in [false, true] {
                    let buy = reserves.buy(yes, amount).unwrap();
                    assert!(
                        u128::from(buy.after.yes) * u128::from(buy.after.no)
                            >= u128::from(y) * u128::from(n)
                    );
                    if let Ok(sell) = buy.after.sell(yes, buy.positions) {
                        assert!(sell.trader_amount < buy.trader_amount);
                        assert!(
                            u128::from(sell.after.yes) * u128::from(sell.after.no)
                                >= u128::from(buy.after.yes) * u128::from(buy.after.no)
                        );
                    }
                }
            }
        }
    }
    let pool = PoolReserves {
        yes: 1000,
        no: 1000,
        fees: Amount::ZERO,
    };
    let quote = pool.buy(true, 250).unwrap();
    assert_eq!(
        (quote.positions, quote.after.yes, quote.after.no),
        (450, 800, 1250)
    );
    assert_eq!(quote.trader_amount.msats, 250750);
    assert!(pool.scale(0).is_err());
    assert!(pool.buy(true, u64::MAX).is_err());
}

use fedimint_core::endpoint_constants::{
    AWAIT_SIGNED_SESSION_OUTCOME_ENDPOINT, SESSION_COUNT_ENDPOINT,
};
use fedimint_core::module::SerdeModuleEncoding;
use fedimint_core::session_outcome::{ConsensusItem, SignedSessionOutcome};

use super::*;

async fn federation() -> Federation {
    fedimint_core::rustls::install_crypto_provider().await;
    let registry = registry();
    let peers: Vec<_> = (0..4).map(PeerId::from).collect();
    let port = fedimint_portalloc::port_alloc(12).unwrap();
    let params = local_config_gen_params(&peers, port, true, &registry).unwrap();
    let mut configs =
        ServerConfig::trusted_dealer_gen(&params, &registry, "simplicity-session-test");
    for config in configs.values_mut() {
        config.consensus.broadcast_rounds_per_session = 100;
        config.local.broadcast_round_delay_ms = 50;
    }
    let first = &configs[&PeerId::from(0)];
    let module_id = |kind| {
        *first
            .consensus
            .modules
            .iter()
            .find(|(_, config)| config.kind == kind)
            .unwrap()
            .0
    };
    let simplicity = module_id(fedimint_simplicity_common::KIND);
    let dummy = module_id(fedimint_dummy_common::KIND);
    let decoders = registry.available_decoders(first.consensus.iter_module_instances());
    let api = DynGlobalApi::new(
        ConnectorRegistry::build_from_testing_env().bind().await,
        first
            .consensus
            .api_endpoints()
            .into_iter()
            .map(|(peer, endpoint)| (peer, endpoint.url))
            .collect(),
        None,
    );
    let mut fed = Federation {
        id: first.calculate_federation_id(),
        configs,
        guardians: BTreeMap::new(),
        directory: tempfile::tempdir().unwrap(),
        port,
        api,
        decoders,
        simplicity,
        dummy,
        block_count: AtomicU64::new(INITIAL_BLOCK_COUNT),
        completed: false,
    };
    for peer in peers {
        fed.start(peer);
    }
    fed.wait_all_clock().await;
    fed
}

async fn signed_session(fed: &Federation, peer: PeerId, index: u64) -> SignedSessionOutcome {
    let encoded: SerdeModuleEncoding<SignedSessionOutcome> = fed
        .api
        .request_single_peer(
            AWAIT_SIGNED_SESSION_OUTCOME_ENDPOINT.to_owned(),
            ApiRequestErased::new(index),
            peer,
        )
        .await
        .unwrap();
    let signed = encoded.try_into_inner(&fed.decoders).unwrap();
    assert!(signed.verify(&fed.configs[&peer].consensus.broadcast_public_keys, index));
    signed
}

async fn session_count_on(fed: &Federation, peer: PeerId) -> u64 {
    fed.api
        .request_single_peer(
            SESSION_COUNT_ENDPOINT.to_owned(),
            ApiRequestErased::new(()),
            peer,
        )
        .await
        .unwrap()
}

async fn inclusion_session(fed: &Federation, transaction: &Transaction, start: u64) -> u64 {
    for index in start.. {
        let signed = signed_session(fed, PeerId::from(0), index).await;
        let matches = signed
            .session_outcome
            .items
            .iter()
            .filter(|accepted| {
                matches!(&accepted.item, ConsensusItem::Transaction(accepted) if accepted == transaction)
            })
            .count();
        if matches != 0 {
            assert_eq!(matches, 1);
            return index;
        }
    }
    unreachable!()
}

fn spend(
    fed: &Federation,
    program: &ContractProgram,
    points: &[OutPoint],
    creation_session: u64,
    outputs: Vec<DynOutput>,
    owner: &Keypair,
) -> Transaction {
    let inputs = points
        .iter()
        .map(|point| {
            DynInput::from_typed(
                fed.simplicity,
                program
                    .input(
                        *point,
                        owner.public_key(),
                        witnesses([("CREATION_SESSION", Value::u64(creation_session))]),
                    )
                    .unwrap(),
            )
        })
        .collect();
    let (mut transaction, sponsor) = fed.sponsored(inputs, outputs);
    let mut keys = vec![*owner; points.len()];
    keys.push(sponsor);
    sign_transaction(&mut transaction, &keys).unwrap();
    transaction
}

async fn assert_rejected(fed: &Federation, transaction: &Transaction) {
    let outcome = fed
        .api
        .submit_transaction(transaction.clone())
        .await
        .try_into_inner(&fed.decoders)
        .unwrap();
    let error = outcome.0.unwrap_err().to_string();
    assert!(error.contains("program rejected"), "{error}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn creation_sessions_and_expired_policy_replay_match_authenticated_history() {
    let _ = fedimint_logging::TracingSetup::default().init();
    tokio::time::timeout(Duration::from_secs(180), session_context())
        .await
        .expect("session-context consensus and guardian replay timed out");
}

async fn session_context() {
    let mut fed = federation().await;
    let online = PeerId::from(0);
    let offline = PeerId::from(3);
    signed_session(&fed, offline, 0).await;
    let persisted_session = session_count_on(&fed, offline).await;
    assert!(persisted_session > 0);
    fed.stop(offline);
    signed_session(&fed, online, persisted_session).await;

    let first_session = session_count_on(&fed, online).await;
    let opens = first_session + 4;
    let closes = opens + 4;
    let program = ContractProgram::compile(
        "fn main() {
            assert!(jet::eq_64(jet::fm_creation_session(), witness::CREATION_SESSION));
            assert!(jet::lt_64(jet::fm_creation_session(), jet::fm_session_index()));
            assert!(jet::le_64(param::OPENS, jet::fm_session_index()));
            assert!(jet::lt_64(jet::fm_session_index(), param::CLOSES));
        }",
        arguments([("OPENS", Value::u64(opens)), ("CLOSES", Value::u64(closes))]),
    )
    .unwrap();
    let outputs = vec![
        program
            .output(Amount::from_sats(10), [1; 32], vec![1; 32])
            .unwrap(),
        program
            .asset_output(
                Amount::from_sats(10),
                [2; 32],
                vec![2; 32],
                bundle(&[], &[]),
            )
            .unwrap(),
        program
            .asset_output(
                Amount::from_sats(10),
                [3; 32],
                vec![3; 32],
                bundle(&[], &[]),
            )
            .unwrap(),
    ];
    let (mut funding, sponsor) = fed.sponsored(
        vec![],
        outputs
            .iter()
            .cloned()
            .map(|output| fed.output(output))
            .collect(),
    );
    sign_transaction(&mut funding, &[sponsor]).unwrap();
    fed.submit(&funding).await;
    let created_in = inclusion_session(&fed, &funding, first_session).await;
    assert!(created_in > persisted_session);
    let expected: Vec<_> = outputs
        .into_iter()
        .map(|output| StoredContract {
            output,
            creation_session: created_in,
            creation_block_count: INITIAL_BLOCK_COUNT,
        })
        .collect();
    for (index, stored) in expected.iter().enumerate() {
        assert_eq!(
            fed.wait_contract(point(&funding, index as u64)).await,
            *stored
        );
    }

    let owner = key();
    let consumed = [point(&funding, 0), point(&funding, 1)];
    let successor_program = ContractProgram::compile("fn main() {}", arguments([])).unwrap();
    let successors = [
        successor_program
            .output(Amount::from_sats(10), [4; 32], vec![4; 32])
            .unwrap(),
        successor_program
            .asset_output(
                Amount::from_sats(10),
                [5; 32],
                vec![5; 32],
                bundle(&[], &[]),
            )
            .unwrap(),
    ];
    let transaction = spend(
        &fed,
        &program,
        &consumed,
        created_in,
        successors
            .iter()
            .cloned()
            .map(|output| fed.output(output))
            .collect(),
        &owner,
    );
    assert!(session_count_on(&fed, online).await < opens);
    assert_rejected(&fed, &transaction).await;
    for (index, stored) in expected.iter().enumerate() {
        assert_eq!(
            fed.wait_contract(point(&funding, index as u64)).await,
            *stored
        );
    }

    signed_session(&fed, online, opens - 1).await;
    let forged = spend(
        &fed,
        &program,
        &consumed,
        created_in + 1,
        transaction.outputs.clone(),
        &owner,
    );
    assert_rejected(&fed, &forged).await;
    fed.submit(&transaction).await;
    let spent_in = inclusion_session(&fed, &transaction, opens).await;
    assert!((opens..closes).contains(&spent_in));
    assert!(spent_in > created_in);
    let expected_successors: Vec<_> = successors
        .into_iter()
        .map(|output| StoredContract {
            output,
            creation_session: spent_in,
            creation_block_count: INITIAL_BLOCK_COUNT,
        })
        .collect();
    for (index, stored) in expected_successors.iter().enumerate() {
        assert_eq!(
            fed.wait_contract(point(&transaction, index as u64)).await,
            *stored
        );
    }

    let expired_history = signed_session(&fed, online, closes).await;
    assert!(session_count_on(&fed, online).await > closes);
    let retained = point(&funding, 2);
    let expired = spend(&fed, &program, &[retained], created_in, vec![], &owner);
    assert_rejected(&fed, &expired).await;
    assert_eq!(fed.wait_contract(retained).await, expected[2]);

    fed.start(offline);
    fed.wait_all_clock().await;
    let replayed_history = signed_session(&fed, offline, closes).await;
    assert_eq!(
        replayed_history.session_outcome,
        expired_history.session_outcome
    );
    assert!(session_count_on(&fed, offline).await > closes);
    for (index, stored) in expected_successors.iter().enumerate() {
        assert_eq!(
            fed.wait_contract(point(&transaction, index as u64)).await,
            *stored
        );
    }
    assert_eq!(fed.wait_contract(retained).await, expected[2]);
    for peer in fed.guardians.keys() {
        for consumed in consumed {
            assert!(fed.contract_on(*peer, consumed).await.is_none());
        }
    }
    fed.completed = true;
}

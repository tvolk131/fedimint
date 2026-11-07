//! Funding that changes a pruned fee must roll back real ecash and
//! reservations, and a plan built from stale state must stop for attention
//! without submitting anything. The templates and handlers here are test-only
//! stand-ins for application code.
use fedimint_core::encoding::{Decodable as _, Encodable as _};
use fedimint_core::secp256k1::XOnlyPublicKey;
use fedimint_simplicity_client::TransactionPlan;
use fedimint_simplicity_client::descriptor::{BuiltinTemplates, ContractTemplates};
use fedimint_simplicity_client::intent::{
    Intent, IntentContext, IntentHandlers, IntentPlan, IntentPolicy, IntentStatus, NoIntentHandlers,
};

use super::*;

mod race;

const FUNDING_SENSITIVE: &str = "funding-sensitive-pruning-test";
const TOP_UP: &str = "top-up-test";
const SHARED: &str = "shared-open-test";

/// Anyone may spend this contract once the Bitcoin height reaches `OPENS`.
const SHARED_POLICY: &str =
    "fn main() { assert!(jet::le_64(param::OPENS, jet::fm_block_count())); }";

/// Owner-authorized policy with consensus clocks and a collateral-preserving
/// top-up branch, from the module's test fixtures.
pub(super) fn top_up_descriptor(
    key_nonce: [u8; 32],
    min_session: u64,
    min_block_count: u64,
) -> ContractDescriptor {
    ContractDescriptor {
        template: TOP_UP.to_owned(),
        parameters: (min_session, min_block_count).consensus_encode_to_vec(),
        ..ContractDescriptor::owner(key_nonce)
    }
}

/// A public contract no wallet owns; the key nonce is irrelevant to its policy.
pub(super) fn shared_descriptor(opens: u64) -> ContractDescriptor {
    ContractDescriptor {
        template: SHARED.to_owned(),
        parameters: opens.consensus_encode_to_vec(),
        ..ContractDescriptor::owner([0; 32])
    }
}

#[fedimint_core::apply(fedimint_core::async_trait_maybe_send!)]
impl IntentHandlers for Templates {
    async fn build(
        &self,
        wallet: &SimplicityClientModule,
        intent: &Intent,
        context: &IntentContext,
    ) -> anyhow::Result<IntentPlan> {
        if intent.template == "pruning-race-test" {
            return race::build(wallet, intent, context).await;
        }
        if intent.template != "invalid-pruning-plan-test" {
            return NoIntentHandlers.build(wallet, intent, context).await;
        }
        let (point, count) =
            <(OutPoint, u64)>::consensus_decode_whole(&intent.data, &Default::default())?;
        let shared_inputs: Vec<_> = (0..count)
            .map(|out_idx| OutPoint { out_idx, ..point })
            .collect();
        Ok(IntentPlan {
            max_fee: None,
            spends: shared_inputs
                .iter()
                .copied()
                .map(SpendIntent::owner)
                .collect(),
            outputs: vec![],
            shared_inputs,
        })
    }
}

#[derive(Debug)]
pub(super) struct Templates;
impl ContractTemplates for Templates {
    fn owns_balance(&self, descriptor: &ContractDescriptor) -> bool {
        matches!(descriptor.template.as_str(), FUNDING_SENSITIVE | TOP_UP)
            || BuiltinTemplates.owns_balance(descriptor)
    }
    fn compile(
        &self,
        descriptor: &ContractDescriptor,
        owner: XOnlyPublicKey,
    ) -> anyhow::Result<(u32, fedimint_simplicity_client::ContractProgram)> {
        let program = match descriptor.template.as_str() {
            FUNDING_SENSITIVE => fedimint_simplicity_client::ContractProgram::compile(
                "fn main() { let signature: Signature = witness::SIGNATURE; jet::bip_0340_verify((param::OWNER, jet::fm_sig_hash_all()), signature); match witness::VARIABLE { true => { match jet::eq_32(jet::fm_output_count(), 1) { true => {}, false => { jet::bip_0340_verify((param::OWNER, jet::fm_sig_hash_all()), signature); }, } }, false => {}, } }",
                compiler::arguments([("OWNER", word(owner.serialize()))]),
            )?,
            TOP_UP => {
                let (min_session, min_block_count) = <(u64, u64)>::consensus_decode_whole(
                    &descriptor.parameters,
                    &Default::default(),
                )?;
                fedimint_simplicity_client::ContractProgram::compile(
                    ORIGINAL_POLICY,
                    compiler::arguments([
                        ("OWNER", word(owner.serialize())),
                        ("MIN_SESSION", Value::u64(min_session)),
                        ("MIN_BLOCK_COUNT", Value::u64(min_block_count)),
                    ]),
                )?
            }
            SHARED => {
                let opens =
                    u64::consensus_decode_whole(&descriptor.parameters, &Default::default())?;
                fedimint_simplicity_client::ContractProgram::compile(
                    SHARED_POLICY,
                    compiler::arguments([("OPENS", Value::u64(opens))]),
                )?
            }
            _ => return BuiltinTemplates.compile(descriptor, owner),
        };
        Ok((fedimint_simplicity_common::EXECUTION_VERSION, program))
    }
}

pub(super) async fn check(client: &ClientHandle) {
    let wallet = client.get_first_module::<SimplicityClientModule>().unwrap();
    let descriptor = ContractDescriptor {
        template: FUNDING_SENSITIVE.to_owned(),
        ..ContractDescriptor::owner([98; 32])
    };
    let output = wallet
        .output(&descriptor, Amount::ZERO, [0; 32], Default::default())
        .unwrap();
    // A direct send with no spend is quoted by the core funding dry run too,
    // and submitting the same plan prepares the same transaction.
    let direct = TransactionPlan {
        outputs: vec![output.clone()],
        ..Default::default()
    };
    let direct_fee = wallet.quote_transaction(&direct).await.unwrap();
    assert!(direct_fee >= fedimint_simplicity_common::output_fee(&output));
    let (operation, txid) = wallet.submit_plan(direct).await.unwrap();
    wallet.await_operation(operation).await.unwrap();
    client.await_no_active_states(operation).await;
    let point = OutPoint { txid, out_idx: 0 };
    let destination = wallet
        .receive(Amount::from_sats(20), Default::default())
        .unwrap();
    let spend = |variable| SpendIntent {
        outpoint: point,
        witnesses: compiler::witnesses([("VARIABLE", Value::from(variable))]),
        signature_witness: Some("SIGNATURE".to_owned()),
    };
    // Quotes charge the submitted pruned representation, not the larger
    // original policy containing unused signature checks.
    let contracts = wallet.contracts_for([point]).await;
    let snapshot = wallet.pruning_snapshot([point]).await.unwrap();
    let plan = TransactionPlan {
        spends: vec![spend(false)],
        outputs: vec![destination.clone()],
        ..Default::default()
    };
    let request = wallet
        .plan_fee_request(&plan, &contracts, &snapshot)
        .unwrap();
    let key = wallet.descriptor_key(&descriptor);
    let program = Templates
        .compile(&descriptor, key.x_only_public_key().0)
        .unwrap()
        .1;
    let raw = program
        .input(
            point,
            key.public_key(),
            witnesses([
                ("VARIABLE", Value::from(false)),
                ("SIGNATURE", placeholder_signature()),
            ]),
        )
        .unwrap();
    let module = client
        .get_first_instance(&fedimint_simplicity_common::KIND)
        .unwrap();
    let tx = Transaction {
        inputs: vec![DynInput::from_typed(module, raw.clone())],
        outputs: vec![DynOutput::from_typed(module, destination.clone())],
        nonce: [0; 8],
        signatures: TransactionSignature::NaiveMultisig(vec![]),
    };
    let signature =
        fedimint_simplicity_client::signature_value(client.federation_id(), module, &tx, &key)
            .unwrap();
    let pruned = program
        .input_with_environment(
            point,
            key.public_key(),
            witnesses([("VARIABLE", Value::from(false)), ("SIGNATURE", signature)]),
            &snapshot
                .environment(client.federation_id(), module, &tx, 0)
                .unwrap(),
        )
        .unwrap();
    let fee = fedimint_simplicity_common::runtime::input_fee(&pruned).unwrap();
    assert_eq!(request.input_fee.get_bitcoin(), fee);
    assert!(fee < fedimint_simplicity_common::runtime::input_fee(&raw).unwrap());
    assert_eq!(
        wallet.quote_transaction(&plan).await.unwrap(),
        wallet.quote_fee_request(request).await.unwrap()
    );
    let notes = super::ecash::notes(client).await;
    let balance = client.get_balance_for_btc().await.unwrap();
    let history = wallet.history().await;
    let error = wallet
        .submit(vec![spend(true)], vec![destination.clone()], vec![])
        .await
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("funding changed pruning fees"),
        "{error:#}"
    );
    assert_eq!(
        super::ecash::notes(client).await,
        notes,
        "finalization must return the identical ecash notes"
    );
    assert_eq!(client.get_balance_for_btc().await.unwrap(), balance);
    assert_eq!(wallet.history().await, history);
    // The same input remains spendable with a funding-independent branch.
    let (operation, _) = wallet
        .submit(vec![spend(false)], vec![destination], vec![])
        .await
        .unwrap();
    wallet.await_operation(operation).await.unwrap();
    client.await_no_active_states(operation).await;
    // A custom handler returning a stale or oversized plan must stop for
    // attention, rather than spin forever before recording any attempt.
    let notes = super::ecash::notes(client).await;
    for (count, reason) in [(1u64, "no longer unspent"), (33, "too many pruning inputs")] {
        let id = wallet
            .submit_intent(
                Intent {
                    template: "invalid-pruning-plan-test".to_owned(),
                    version: 1,
                    data: (point, count).consensus_encode_to_vec(),
                },
                IntentPolicy::default(),
            )
            .await
            .unwrap();
        let record = tokio::time::timeout(Duration::from_secs(20), wallet.await_intent(id))
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(record.status, IntentStatus::Attention(ref error) if error.contains(reason)),
            "{record:?}"
        );
        assert!(record.attempts.is_empty());
        assert_eq!(super::ecash::notes(client).await, notes);
    }
    race::check(client).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn funding_sensitive_pruning_and_stale_plans_roll_back_real_ecash() {
    let _ = fedimint_logging::TracingSetup::default().init();
    tokio::time::timeout(Duration::from_secs(180), async {
        let mut fed = Federation::new().await;
        let client = join(ecash::builder, &fed, db(), 61, false, false).await;
        ecash::funds(&client).await;
        check(&client).await;
        client.shutdown().await;
        fed.completed = true;
    })
    .await
    .unwrap();
}

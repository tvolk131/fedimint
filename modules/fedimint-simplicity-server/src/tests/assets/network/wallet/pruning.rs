//! Funding that changes a pruned fee must roll back real ecash and
//! reservations.
use fedimint_core::encoding::{Decodable as _, Encodable as _};
use fedimint_core::secp256k1::XOnlyPublicKey;
use fedimint_simplicity_client::descriptor::{BuiltinTemplates, ContractTemplates};
use fedimint_simplicity_client::intent::{
    BuiltinIntents, Intent, IntentContext, IntentHandlers, IntentPlan, IntentPolicy, IntentStatus,
};

use super::*;

mod race;

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
            return BuiltinIntents.build(wallet, intent, context).await;
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
        descriptor.template == "funding-sensitive-pruning-test"
            || BuiltinTemplates.owns_balance(descriptor)
    }
    fn is_successor(
        &self,
        descriptor: &ContractDescriptor,
        before: &ContractOutput,
        after: &ContractOutput,
        position: fedimint_simplicity_client::descriptor::SuccessorPosition,
    ) -> bool {
        BuiltinTemplates.is_successor(descriptor, before, after, position)
    }
    fn compile(
        &self,
        descriptor: &ContractDescriptor,
        owner: XOnlyPublicKey,
    ) -> anyhow::Result<(u32, fedimint_simplicity_client::ContractProgram)> {
        if descriptor.template != "funding-sensitive-pruning-test" {
            return BuiltinTemplates.compile(descriptor, owner);
        }
        Ok((
            0,
            fedimint_simplicity_client::ContractProgram::compile(
                "fn main() { let signature: Signature = witness::SIGNATURE; jet::bip_0340_verify((param::OWNER, jet::fm_sig_hash_all()), signature); match witness::VARIABLE { true => { match jet::eq_32(jet::fm_output_count(), 1) { true => {}, false => { jet::bip_0340_verify((param::OWNER, jet::fm_sig_hash_all()), signature); }, } }, false => {}, } }",
                compiler::arguments([(
                    "OWNER",
                    Value::u256(compiler::U256::from_byte_array(owner.serialize())),
                )]),
            )?,
        ))
    }
}

pub(super) async fn check(client: &ClientHandle) {
    let wallet = client.get_first_module::<SimplicityClientModule>().unwrap();
    let descriptor = ContractDescriptor {
        template: "funding-sensitive-pruning-test".to_owned(),
        ..ContractDescriptor::owner([98; 32])
    };
    let output = wallet
        .output(&descriptor, Amount::ZERO, [0; 32], Default::default())
        .unwrap();
    let txid = submit(&wallet, vec![], vec![output], vec![]).await;
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
    let context = wallet.intent_context().await;
    let snapshot = wallet.pruning_snapshot([point]).await.unwrap();
    let plan = IntentPlan {
        max_fee: None,
        spends: vec![spend(false)],
        outputs: vec![destination.clone()],
        shared_inputs: vec![point],
    };
    let request = wallet.plan_fee_request(&plan, &context, &snapshot).unwrap();
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
        wallet.quote_plan(&plan, &context).await.unwrap(),
        wallet.quote_fee_request(request).await.unwrap()
    );
    let notes = super::intents::notes(client).await;
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
        super::intents::notes(client).await,
        notes,
        "finalization must return the identical ecash notes"
    );
    assert_eq!(client.get_balance_for_btc().await.unwrap(), balance);
    assert_eq!(wallet.history().await, history);
    // The same input remains spendable with a funding-independent branch.
    submit(&wallet, vec![spend(false)], vec![destination], vec![]).await;
    // A custom handler returning a stale or oversized plan must stop for
    // attention, rather than spin forever before recording any attempt.
    let notes = super::intents::notes(client).await;
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
        assert_eq!(super::intents::notes(client).await, notes);
    }
    race::check(client).await;
}

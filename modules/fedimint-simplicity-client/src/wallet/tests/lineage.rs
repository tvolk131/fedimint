//! How the wallet recognizes a public successor. The core wallet does not know
//! application covenants; it trusts only what a template asserts. These minimal
//! policies stand in for applications and pin the generic contract: a successor
//! needs a non-copyable authority or a covenant-assigned input/output pair, and
//! a copied policy alone never qualifies. Full application behavior is tested
//! with the application.
use std::collections::BTreeMap;

use fedimint_core::core::DynUnknown;
use fedimint_core::secp256k1::XOnlyPublicKey;

use super::*;
use crate::ContractProgram;
use crate::descriptor::{SuccessorPosition, preserves_authorities};
use crate::intent::IntentContext;
use crate::tests::support::owner_program;

const AUTHORITY: &str = "authority-test";
const ASSIGNED: &str = "assigned-successor-test";

fn compile_owner(
    descriptor: &ContractDescriptor,
    owner: XOnlyPublicKey,
) -> anyhow::Result<(u32, ContractProgram)> {
    anyhow::ensure!(
        descriptor.template_version == 1 && descriptor.parameters.is_empty(),
        "unsupported test template"
    );
    Ok((crate::common::EXECUTION_VERSION, owner_program(owner)?))
}

/// A shared vault recognized by its issuance authorities, which cannot be
/// copied: the successor is the output that preserves them exactly.
#[derive(Debug)]
struct AuthorityTemplates;
impl ContractTemplates for AuthorityTemplates {
    fn compile(
        &self,
        descriptor: &ContractDescriptor,
        owner: XOnlyPublicKey,
    ) -> anyhow::Result<(u32, ContractProgram)> {
        if descriptor.template == AUTHORITY {
            compile_owner(descriptor, owner)
        } else {
            BuiltinTemplates.compile(descriptor, owner)
        }
    }
    fn is_successor(
        &self,
        descriptor: &ContractDescriptor,
        before: &ContractOutput,
        after: &ContractOutput,
        _position: SuccessorPosition,
    ) -> bool {
        descriptor.template == AUTHORITY
            && descriptor.template_version == 1
            && preserves_authorities(before, after)
    }
}

/// A contract with no authorities, whose covenant assigns each input to the
/// output at the same index. Copies of its policy elsewhere are not successors.
#[derive(Debug)]
pub(super) struct AssignedTemplates;
impl ContractTemplates for AssignedTemplates {
    fn compile(
        &self,
        descriptor: &ContractDescriptor,
        owner: XOnlyPublicKey,
    ) -> anyhow::Result<(u32, ContractProgram)> {
        if descriptor.template == ASSIGNED {
            compile_owner(descriptor, owner)
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
        descriptor.template == ASSIGNED
            && descriptor.template_version == 1
            && position.input_index == position.output_index
            && before.cmr == after.cmr
            && before.version == after.version
    }
}

pub(super) fn assigned_descriptor(key_nonce: u8) -> ContractDescriptor {
    ContractDescriptor {
        template: ASSIGNED.to_owned(),
        ..ContractDescriptor::owner([key_nonce; 32])
    }
}

async fn store_with(templates: impl ContractTemplates + 'static) -> WalletStore {
    WalletStore::open(
        database(),
        &root(),
        federation(),
        MODULE,
        Arc::new(templates),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn recovery_follows_an_authority_successor_without_its_original_annotation() {
    let store = store_with(AuthorityTemplates).await;
    let descriptor = ContractDescriptor {
        template: AUTHORITY.to_owned(),
        ..ContractDescriptor::owner([3; 32])
    };
    let authorities = vec![AssetId([1; 32]), AssetId([2; 32])];
    let (_, program) = store
        .keys
        .program(&descriptor, store.templates.as_ref())
        .unwrap();
    let bundle = AssetBundle {
        balances: vec![],
        authorities,
    };
    let mut vault = program
        .asset_output(
            Amount::from_sats(10),
            [0; 32],
            store.keys.encrypt(&descriptor).unwrap(),
            bundle.clone(),
        )
        .unwrap();
    let creation = tx(0, &[], vec![vault.clone()]);
    vault.recovery.clear();
    vault.amount = Amount::from_sats(20);
    // The same policy without the authorities is a lookalike, not a successor.
    let mut lookalike = vault.clone();
    lookalike.extension = Some(crate::common::assets::AssetExtension::Bundle(
        AssetBundle::default(),
    ));
    let successor = tx(1, &[point(&creation)], vec![vault, lookalike]);
    store
        .apply_session(0, &session(&[creation, successor.clone()]), true)
        .await
        .unwrap();
    let contracts = store.contracts().await;
    assert_eq!(contracts.len(), 2, "creation and its authority successor");
    let holdings: Vec<_> = contracts
        .into_iter()
        .filter(|(_, value)| value.spent_by.is_none())
        .collect();
    assert_eq!(holdings.len(), 1);
    assert_eq!(holdings[0].0, point(&successor));
    assert_eq!(holdings[0].1.descriptor, descriptor);
    assert_eq!(holdings[0].1.output.bundle(), Some(&bundle));
    // Watching a shared vault does not make its collateral a wallet balance.
    assert!(!AuthorityTemplates.owns_balance(&descriptor));
}

#[tokio::test]
async fn recovery_uses_assigned_successors_not_policy_lookalikes() {
    let keys = WalletKeys::new(&root(), federation(), MODULE);
    let descriptor = assigned_descriptor(41);
    let program = keys.program(&descriptor, &AssignedTemplates).unwrap().1;
    let output = |msats, recovery| {
        program
            .asset_output(
                Amount::from_msats(msats),
                [0; 32],
                recovery,
                AssetBundle::default(),
            )
            .unwrap()
    };
    let creation = tx(
        0,
        &[],
        vec![output(10_000, keys.encrypt(&descriptor).unwrap())],
    );
    let unrelated = OutPoint {
        txid: point(&creation).txid,
        out_idx: 9,
    };
    // The tracked contract is module-local input 1, despite a foreign input
    // before it. Only absolute output 1 is its successor; 0 and 2 copy the same
    // policy.
    let mut fill = tx(
        1,
        &[unrelated, point(&creation)],
        vec![output(7_000, vec![]); 3],
    );
    fill.inputs
        .insert(0, DynInput::from_typed(1234, DynUnknown(vec![9])));
    let next = OutPoint {
        txid: fill.tx_hash(),
        out_idx: 1,
    };
    let claim = tx(2, &[next], vec![output(5_000, vec![])]);
    let cancel = tx(3, &[point(&claim)], vec![]);
    let history = [
        session(&[creation.clone(), fill.clone()]),
        session(&[claim.clone(), cancel.clone()]),
    ];
    for _ in 0..2 {
        let store = store_with(AssignedTemplates).await;
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

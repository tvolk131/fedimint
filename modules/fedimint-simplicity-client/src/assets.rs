//! Low-level asset transaction builders. Callers retain contract descriptors,
//! outpoints, and recovery data; this does not implement a persistent wallet.
use std::collections::BTreeMap;

use anyhow::ensure;
use common::assets::{
    ASSET_VERSION, AssetActions, AssetAmount, AssetBundle, AssetCreation, AssetExtension, AssetId,
    asset_id, signature_hash_v1, validate_amounts,
};
use fedimint_core::config::FederationId;
use fedimint_core::core::{DynOutput, ModuleInstanceId};
use fedimint_core::secp256k1::schnorr::Signature;
use fedimint_core::secp256k1::{Keypair, Message, SECP256K1};
use fedimint_core::transaction::Transaction;
use fedimint_core::{Amount, OutPoint};

use crate::compiler::{Value, ValueConstructible};
use crate::{ContractProgram, common};

impl ContractProgram {
    pub fn asset_output(
        &self,
        bitcoin: Amount,
        state: [u8; 32],
        recovery: Vec<u8>,
        mut bundle: AssetBundle,
    ) -> anyhow::Result<common::ContractOutput> {
        bundle.balances.sort_by_key(|value| value.asset);
        bundle.authorities.sort();
        validate_amounts(&bundle.balances)?;
        ensure!(
            bundle.authorities.len() <= common::assets::MAX_ASSETS
                && bundle.authorities.windows(2).all(|pair| pair[0] < pair[1]),
            "invalid authority collection"
        );
        let mut output = self.output(bitcoin, state, recovery)?;
        output.version = ASSET_VERSION;
        output.extension = Some(AssetExtension::Bundle(bundle));
        Ok(output)
    }
}

/// One fresh key identifies a batch, independently of its funding inputs.
/// The returned unsigned request must be signed after assembling all outputs.
pub fn creation(
    federation: FederationId,
    module: ModuleInstanceId,
    key: &Keypair,
    authority_outputs: Vec<u32>,
) -> anyhow::Result<(AssetCreation, Vec<AssetId>)> {
    ensure!(
        !authority_outputs.is_empty() && authority_outputs.len() <= common::assets::MAX_ASSETS,
        "invalid creation batch size"
    );
    let ids = (0..authority_outputs.len())
        .map(|ordinal| asset_id(federation, module, key.public_key(), ordinal as u32))
        .collect();
    Ok((
        AssetCreation {
            key: key.public_key(),
            authority_outputs,
            signature: Signature::from_slice(&[0; 64]).expect("fixed signature width"),
        },
        ids,
    ))
}

pub fn action_output(mut actions: AssetActions) -> anyhow::Result<common::ContractOutput> {
    actions.issuance.sort_by_key(|value| value.asset);
    actions.burns.sort_by_key(|value| value.asset);
    validate_amounts(&actions.issuance)?;
    validate_amounts(&actions.burns)?;
    Ok(common::ContractOutput::action_output(actions))
}

/// Sign creation intents before computing any v0 program signatures or outer
/// transaction signatures. All creation signatures are excluded from v1 intent.
pub fn sign_creation(
    tx: &mut Transaction,
    federation: FederationId,
    module: ModuleInstanceId,
    key: &Keypair,
) -> anyhow::Result<()> {
    let message = Message::from_digest(signature_hash_v1(federation, module, tx)?);
    let signature = SECP256K1.sign_schnorr_no_aux_rand(&message, key);
    let mut found = 0;
    for output in &mut tx.outputs {
        if output.module_instance_id() != module {
            continue;
        }
        let mut contract = output
            .as_any()
            .downcast_ref::<common::ContractOutput>()
            .ok_or_else(|| anyhow::anyhow!("wrong module output type"))?
            .clone();
        if let Some(AssetExtension::Actions(actions)) = &mut contract.extension {
            for creation in &mut actions.creations {
                if creation.key == key.public_key() {
                    creation.signature = signature;
                    found += 1;
                }
            }
        }
        *output = DynOutput::from_typed(module, contract);
    }
    ensure!(found == 1, "expected exactly one creation for this key");
    Ok(())
}

pub fn signature_value(
    federation: FederationId,
    module: ModuleInstanceId,
    tx: &Transaction,
    key: &Keypair,
) -> anyhow::Result<Value> {
    let message = Message::from_digest(signature_hash_v1(federation, module, tx)?);
    Ok(Value::byte_array(
        *SECP256K1.sign_schnorr_no_aux_rand(&message, key).as_ref(),
    ))
}

/// Select ordinary asset outputs deterministically, leaving authority-bearing
/// contracts to explicit application operations. Returns selected outpoints and
/// asset change; bitcoin funding and script fees are handled separately.
pub fn select_assets<'a>(
    available: impl IntoIterator<Item = (OutPoint, &'a common::ContractOutput)>,
    requested: &[AssetAmount],
) -> anyhow::Result<(Vec<OutPoint>, Vec<AssetAmount>)> {
    validate_amounts(requested)?;
    let targets = requested
        .iter()
        .map(|value| (value.asset, u128::from(value.quantity)))
        .collect::<BTreeMap<_, _>>();
    let mut totals = BTreeMap::<AssetId, u128>::new();
    let mut selected = Vec::new();
    let mut available = available.into_iter().collect::<Vec<_>>();
    available.sort_by_key(|(point, _)| *point);
    let mut seen = std::collections::BTreeSet::new();
    for (point, output) in available {
        ensure!(seen.insert(point), "duplicate available outpoint");
        let Some(bundle) = output.bundle() else {
            continue;
        };
        if !bundle.authorities.is_empty()
            || !bundle.balances.iter().any(|value| {
                targets
                    .get(&value.asset)
                    .is_some_and(|target| totals.get(&value.asset).copied().unwrap_or(0) < *target)
            })
        {
            continue;
        }
        selected.push(point);
        for value in &bundle.balances {
            *totals.entry(value.asset).or_default() += u128::from(value.quantity);
        }
    }
    for (id, target) in targets {
        let total = totals.entry(id).or_default();
        ensure!(*total >= target, "insufficient asset balance");
        *total -= target;
    }
    let change = totals
        .into_iter()
        .filter(|(_, quantity)| *quantity != 0)
        .map(|(asset, quantity)| {
            Ok(AssetAmount {
                asset,
                quantity: u64::try_from(quantity)?,
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok((selected, change))
}

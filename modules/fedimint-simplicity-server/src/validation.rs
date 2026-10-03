//! Resolve and validate the complete module transition before core mutates any
//! input. The resulting cache is transaction-local, never persisted or trusted
//! from a client.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock};

use fedimint_core::bitcoin::hashes::Hash;
use fedimint_core::config::FederationId;
use fedimint_core::core::{DynInputError, DynOutputError, ModuleInstanceId};
use fedimint_core::db::{DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::Encodable;
use fedimint_core::module::{Amounts, InputMeta, TransactionItemAmounts};
use fedimint_core::secp256k1::{Message, SECP256K1};
use fedimint_core::transaction::{Transaction, TransactionError};
use fedimint_core::{OutPoint, TransactionId};
use fedimint_server_core::ModuleTransactionContext;
use fedimint_simplicity_common::assets::{
    ASSET_VERSION, AssetActions, AssetId, AssetRecord, MAX_ASSETS, asset_id, namespace,
    signature_hash_v1, validate_amounts,
};
use fedimint_simplicity_common::runtime::{
    Environment, EnvironmentInput, EnvironmentOutput, execute,
};
use fedimint_simplicity_common::{
    ContractError, ContractInput, ContractOutput, ContractOutputError, MAX_RECOVERY_BYTES,
    signature_hash,
};

use crate::db::{AssetKey, ContractKey, NamespaceKey};
use crate::{Simplicity, validate_shape};

#[derive(Debug)]
pub(crate) struct ValidatedTransaction {
    pub txid: TransactionId,
    pub inputs: Vec<InputMeta>,
    pub creations: Vec<(AssetId, AssetRecord)>,
    pub namespaces: Vec<[u8; 32]>,
}

fn output_error(context: &ModuleTransactionContext<'_>, error: ContractError) -> TransactionError {
    TransactionError::Output(DynOutputError::from_typed(
        context.module_instance_id,
        ContractOutputError(error),
    ))
}

pub(crate) async fn validate(
    module: &Simplicity,
    dbtx: &mut DatabaseTransaction<'_>,
    context: &ModuleTransactionContext<'_>,
) -> Result<ValidatedTransaction, TransactionError> {
    let output_err = |error| output_error(context, error);
    let input_err = |error| {
        TransactionError::Input(DynInputError::from_typed(context.module_instance_id, error))
    };
    validate_shape(context).map_err(output_err)?;
    let hashes = TransactionHashes::new(context);
    let mut outputs = Vec::new();
    let mut actions = AssetActions::default();
    let mut has_actions = false;
    for output in &context.transaction.outputs {
        let contract = if output.module_instance_id() == context.module_instance_id {
            let contract = output
                .as_any()
                .downcast_ref::<ContractOutput>()
                .ok_or_else(|| output_err(ContractError::Context))?;
            validate_output(contract).map_err(output_err)?;
            if let Some(value) = contract.actions() {
                if has_actions {
                    return Err(output_err(ContractError::Assets));
                }
                has_actions = true;
                actions = value.clone();
            }
            Some(contract.clone())
        } else {
            None
        };
        outputs.push(EnvironmentOutput {
            module_id: output.module_instance_id(),
            hash: output.consensus_hash_sha256().to_byte_array(),
            contract,
        });
    }
    let mut inputs = Vec::new();
    let mut stored_inputs = Vec::new();
    let mut seen = BTreeSet::new();
    for input in context
        .transaction
        .inputs
        .iter()
        .filter(|input| input.module_instance_id() == context.module_instance_id)
    {
        let input = input
            .as_any()
            .downcast_ref::<ContractInput>()
            .ok_or_else(|| input_err(ContractError::Context))?;
        if !seen.insert(input.outpoint) {
            return Err(input_err(ContractError::UnknownContract));
        }
        let stored = dbtx
            .get_value(&ContractKey(input.outpoint))
            .await
            .ok_or_else(|| input_err(ContractError::UnknownContract))?;
        if stored.output.version > ASSET_VERSION {
            return Err(input_err(ContractError::Version));
        }
        inputs.push(input);
        stored_inputs.push(stored);
    }
    let resolved: Arc<[EnvironmentInput]> = inputs
        .iter()
        .zip(&stored_inputs)
        .map(|(input, stored)| EnvironmentInput {
            outpoint: input.outpoint,
            contract: stored.output.clone(),
        })
        .collect();
    let (creations, namespaces) = validate_assets(dbtx, &hashes, &resolved, &outputs, &actions)
        .await
        .map_err(output_err)?;
    let block_count = module.consensus_block_count(dbtx).await;
    let outputs: Arc<[EnvironmentOutput]> = outputs.into();
    let actions = Arc::new(actions);
    let mut metadata = Vec::new();
    for (index, (input, stored)) in inputs.iter().zip(&stored_inputs).enumerate() {
        let signature_hash = hashes.intent(stored.output.version).map_err(input_err)?;
        let environment = Environment {
            signature_hash,
            session_index: context.consensus.session_index,
            block_count,
            current: stored.output.clone(),
            creation_session: stored.creation_session,
            creation_block_count: stored.creation_block_count,
            input_index: index as u32,
            input_count: inputs.len() as u32,
            outputs: outputs.clone(),
            inputs: resolved.clone(),
            actions: actions.clone(),
        };
        let fee = execute(input, &environment).map_err(input_err)?;
        metadata.push(InputMeta {
            pub_key: input.claim_key,
            amount: TransactionItemAmounts {
                amounts: Amounts::new_bitcoin(stored.output.amount),
                fees: Amounts::new_bitcoin(fee),
            },
        });
    }
    Ok(ValidatedTransaction {
        txid: hashes.txid(),
        inputs: metadata,
        creations,
        namespaces,
    })
}

/// Scoped to one immutable outer transaction and one module instance. Evaluate
/// lazily at the original validation step so rejected transactions retain their
/// error ordering and do not incur hashes they previously skipped.
struct TransactionHashes<'a> {
    transaction: &'a Transaction,
    federation_id: FederationId,
    module_id: ModuleInstanceId,
    legacy: OnceLock<Result<[u8; 32], ContractError>>,
    assets: OnceLock<Result<[u8; 32], ContractError>>,
    txid: OnceLock<TransactionId>,
}

impl<'a> TransactionHashes<'a> {
    fn new(context: &ModuleTransactionContext<'a>) -> Self {
        Self {
            transaction: context.transaction,
            federation_id: context.consensus.federation_id,
            module_id: context.module_instance_id,
            legacy: OnceLock::new(),
            assets: OnceLock::new(),
            txid: OnceLock::new(),
        }
    }

    fn intent(&self, version: u32) -> Result<[u8; 32], ContractError> {
        let (cache, hash) = if version == 0 {
            (&self.legacy, signature_hash as fn(_, _, _) -> _)
        } else {
            (&self.assets, signature_hash_v1 as fn(_, _, _) -> _)
        };
        cache
            .get_or_init(|| hash(self.federation_id, self.module_id, self.transaction))
            .clone()
    }

    fn txid(&self) -> TransactionId {
        *self.txid.get_or_init(|| self.transaction.tx_hash())
    }
}

fn validate_output(output: &ContractOutput) -> Result<(), ContractError> {
    if output.version > ASSET_VERSION
        || (output.version == 0 && output.extension.is_some())
        || (output.version == ASSET_VERSION && output.extension.is_none())
    {
        return Err(ContractError::Version);
    }
    if output.recovery.len() > MAX_RECOVERY_BYTES || output.amount.msats > 2_100_000_000_000_000_000
    {
        return Err(ContractError::Limit);
    }
    if let Some(bundle) = output.bundle() {
        validate_amounts(&bundle.balances)?;
        if bundle.authorities.len() > MAX_ASSETS
            || !bundle.authorities.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(ContractError::Assets);
        }
    }
    if let Some(actions) = output.actions() {
        if output.amount.msats != 0 || output.cmr != [0; 32] || output.state != [0; 32] {
            return Err(ContractError::Assets);
        }
        validate_amounts(&actions.issuance)?;
        validate_amounts(&actions.burns)?;
        if actions.creations.len() > MAX_ASSETS
            || actions.creations.iter().any(|creation| {
                creation.authority_outputs.is_empty()
                    || creation.authority_outputs.len() > MAX_ASSETS
            })
            || actions
                .creations
                .iter()
                .map(|creation| creation.authority_outputs.len())
                .sum::<usize>()
                > MAX_ASSETS
        {
            return Err(ContractError::Limit);
        }
    }
    Ok(())
}

#[derive(Default)]
struct Balance {
    consumed: u128,
    created: u128,
    issued: u128,
    burned: u128,
    consumed_authorities: u32,
    created_authorities: u32,
}

type Creations = Vec<(AssetId, AssetRecord)>;

async fn validate_assets(
    dbtx: &mut DatabaseTransaction<'_>,
    hashes: &TransactionHashes<'_>,
    inputs: &[EnvironmentInput],
    outputs: &[EnvironmentOutput],
    actions: &AssetActions,
) -> Result<(Creations, Vec<[u8; 32]>), ContractError> {
    let mut balances = BTreeMap::<AssetId, Balance>::new();
    for input in inputs {
        if let Some(bundle) = input.contract.bundle() {
            for value in &bundle.balances {
                balances.entry(value.asset).or_default().consumed += u128::from(value.quantity);
            }
            for id in &bundle.authorities {
                balances.entry(*id).or_default().consumed_authorities += 1;
            }
        }
    }
    for output in outputs.iter().filter_map(|output| output.contract.as_ref()) {
        if let Some(bundle) = output.bundle() {
            for value in &bundle.balances {
                balances.entry(value.asset).or_default().created += u128::from(value.quantity);
            }
            for id in &bundle.authorities {
                balances.entry(*id).or_default().created_authorities += 1;
            }
        }
    }
    for value in &actions.issuance {
        balances.entry(value.asset).or_default().issued += u128::from(value.quantity);
    }
    for value in &actions.burns {
        balances.entry(value.asset).or_default().burned += u128::from(value.quantity);
    }
    if balances.len() > MAX_ASSETS {
        return Err(ContractError::Limit);
    }
    let mut creations = BTreeMap::new();
    let mut namespaces = BTreeSet::new();
    for creation in &actions.creations {
        let namespace = namespace(hashes.federation_id, hashes.module_id, creation.key);
        if !namespaces.insert(namespace) || dbtx.get_value(&NamespaceKey(namespace)).await.is_some()
        {
            return Err(ContractError::NamespaceUsed);
        }
        let message = Message::from_digest(hashes.intent(ASSET_VERSION)?);
        SECP256K1
            .verify_schnorr(
                &creation.signature,
                &message,
                &creation.key.x_only_public_key().0,
            )
            .map_err(|_| ContractError::CreationSignature)?;
        for (ordinal, output_index) in creation.authority_outputs.iter().enumerate() {
            let id = asset_id(
                hashes.federation_id,
                hashes.module_id,
                creation.key,
                ordinal as u32,
            );
            let output = outputs
                .get(*output_index as usize)
                .and_then(|output| output.contract.as_ref())
                .ok_or(ContractError::Assets)?;
            if !output
                .bundle()
                .is_some_and(|bundle| bundle.authorities.contains(&id))
                || creations.contains_key(&id)
                || dbtx.get_value(&AssetKey(id)).await.is_some()
            {
                return Err(ContractError::Assets);
            }
            creations.insert(
                id,
                AssetRecord {
                    creation_key: creation.key,
                    ordinal: ordinal as u32,
                    authority_outpoint: OutPoint {
                        txid: hashes.txid(),
                        out_idx: u64::from(*output_index),
                    },
                    authority_cmr: output.cmr,
                    authority_state: output.state,
                },
            );
        }
    }
    for (id, balance) in balances {
        if creations.contains_key(&id) {
            // No balances or issuance may exist at genesis. Only one authority.
            if balance.consumed != 0
                || balance.created != 0
                || balance.issued != 0
                || balance.burned != 0
                || balance.consumed_authorities != 0
                || balance.created_authorities != 1
            {
                return Err(ContractError::Assets);
            }
        } else {
            if dbtx.get_value(&AssetKey(id)).await.is_none()
                || balance.consumed_authorities > 1
                || balance.created_authorities > balance.consumed_authorities
                || (balance.issued != 0 && balance.consumed_authorities != 1)
            {
                return Err(ContractError::Assets);
            }
            if balance.consumed + balance.issued != balance.created + balance.burned {
                return Err(ContractError::Assets);
            }
        }
    }
    Ok((
        creations.into_iter().collect(),
        namespaces.into_iter().collect(),
    ))
}

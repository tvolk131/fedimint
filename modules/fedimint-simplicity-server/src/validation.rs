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
use fedimint_simplicity_common::assets::accounting::balances;
use fedimint_simplicity_common::assets::{
    ASSET_VERSION, AssetActions, AssetId, AssetRecord, asset_id, namespace, signature_hash_v1,
};
use fedimint_simplicity_common::resources::check_output;
use fedimint_simplicity_common::runtime::{
    Environment, EnvironmentInput, EnvironmentOutput, decode_program, execute_decoded,
};
use fedimint_simplicity_common::{
    ContractError, ContractInput, ContractOutput, ContractOutputError, signature_hash,
};

use crate::db::{AssetKey, NamespaceKey};
use crate::{Simplicity, preparation, validate_shape};

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
    let prepared = preparation::get(context)?;
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
            check_output(contract).map_err(output_err)?;
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
    let mut input_indices = Vec::new();
    let mut stored_inputs = Vec::new();
    for (index, input) in context
        .transaction
        .inputs
        .iter()
        .enumerate()
        .filter(|(_, input)| input.module_instance_id() == context.module_instance_id)
    {
        let input = input
            .as_any()
            .downcast_ref::<ContractInput>()
            .ok_or_else(|| input_err(ContractError::Context))?;
        let stored = prepared
            .contracts
            .get(&index)
            .ok_or_else(|| input_err(ContractError::MissingContext))?;
        input_indices.push(index);
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
        let cached = prepared
            .programs
            .get(&input_indices[index])
            .ok_or_else(|| input_err(ContractError::MissingContext))?;
        let decoded;
        let program = if let Some(program) = cached {
            program
        } else {
            decoded = decode_program(input).map_err(input_err)?;
            &decoded
        };
        let fee = execute_decoded(input, &environment, program).map_err(input_err)?;
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

type Creations = Vec<(AssetId, AssetRecord)>;

async fn validate_assets(
    dbtx: &mut DatabaseTransaction<'_>,
    hashes: &TransactionHashes<'_>,
    inputs: &[EnvironmentInput],
    outputs: &[EnvironmentOutput],
    actions: &AssetActions,
) -> Result<(Creations, Vec<[u8; 32]>), ContractError> {
    let balances = balances(
        inputs.iter().map(|input| &input.contract),
        outputs.iter().filter_map(|output| output.contract.as_ref()),
        actions,
    )?;
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
            balance.check_genesis()?;
        } else {
            if dbtx.get_value(&AssetKey(id)).await.is_none() {
                return Err(ContractError::Assets);
            }
            balance.check_existing()?;
        }
    }

    Ok((
        creations.into_iter().collect(),
        namespaces.into_iter().collect(),
    ))
}

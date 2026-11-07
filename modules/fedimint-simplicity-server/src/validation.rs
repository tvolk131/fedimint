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
use fedimint_core::{Amount, OutPoint, TransactionId};
use fedimint_server_core::ModuleTransactionContext;
use fedimint_simplicity_common::assets::accounting::balances;
use fedimint_simplicity_common::assets::{AssetActions, AssetId, AssetRecord, asset_id, namespace};
use fedimint_simplicity_common::resources::check_output;
use fedimint_simplicity_common::runtime::{
    Environment, EnvironmentInput, EnvironmentOutput, execute_decoded,
};
use fedimint_simplicity_common::{
    ContractError, ContractInput, ContractOutput, ContractOutputError, signature_hash,
};
use simplicity::RedeemNode;

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
    let executions = inputs
        .iter()
        .zip(&stored_inputs)
        .zip(&input_indices)
        .enumerate()
        .map(|(index, ((input, stored), input_index))| Execution {
            input: (*input).clone(),
            environment: hashes.intent().map(|signature_hash| Environment {
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
            }),
            program: prepared
                .programs
                .get(input_index)
                .cloned()
                .ok_or(ContractError::MissingContext),
        })
        .collect::<Vec<_>>();
    let fees = if executions.is_empty() {
        Ok(Vec::new())
    } else {
        prepared.admission.run(move || execute(executions)).await
    }
    .map_err(input_err)?;
    let metadata = inputs
        .iter()
        .zip(&stored_inputs)
        .zip(fees)
        .map(|((input, stored), fee)| InputMeta {
            pub_key: input.claim_key,
            amount: TransactionItemAmounts {
                amounts: Amounts::new_bitcoin(stored.output.amount),
                fees: Amounts::new_bitcoin(fee),
            },
        })
        .collect();
    Ok(ValidatedTransaction {
        txid: hashes.txid(),
        inputs: metadata,
        creations,
        namespaces,
    })
}

/// One input's execution, owned so it can run off the async runtime. A failure
/// computing the environment or finding the program surfaces only when
/// [`execute`] reaches this input, after every earlier input has executed.
struct Execution {
    input: ContractInput,
    environment: Result<Environment, ContractError>,
    program: Result<Option<Arc<RedeemNode>>, ContractError>,
}

/// Execute inputs in transaction order and stop at the first failure.
fn execute(executions: Vec<Execution>) -> Result<Vec<Amount>, ContractError> {
    executions
        .into_iter()
        .map(|execution| {
            let environment = execution.environment?;
            let program = match execution.program? {
                Some(program) => program,
                None => preparation::decode(&execution.input)?,
            };
            execute_decoded(&execution.input, &environment, &program)
        })
        .collect()
}

/// Scoped to one immutable outer transaction and one module instance. Each hash
/// is computed at most once, only if needed, and failures are cached so they
/// are reported at the step that needs the hash.
struct TransactionHashes<'a> {
    transaction: &'a Transaction,
    federation_id: FederationId,
    module_id: ModuleInstanceId,
    intent: OnceLock<Result<[u8; 32], ContractError>>,
    txid: OnceLock<TransactionId>,
}

impl<'a> TransactionHashes<'a> {
    fn new(context: &ModuleTransactionContext<'a>) -> Self {
        Self {
            transaction: context.transaction,
            federation_id: context.consensus.federation_id,
            module_id: context.module_instance_id,
            intent: OnceLock::new(),
            txid: OnceLock::new(),
        }
    }

    fn intent(&self) -> Result<[u8; 32], ContractError> {
        self.intent
            .get_or_init(|| signature_hash(self.federation_id, self.module_id, self.transaction))
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
        let message = Message::from_digest(hashes.intent()?);
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

//! Wallet integration with the core client's funding, submission and recovery.
use std::sync::Arc;

use anyhow::ensure;
use fedimint_client_module::error::ClientModuleError;
use fedimint_client_module::module::init::{
    ClientModuleInit, ClientModuleInitArgs, ClientModuleRecoverArgs, RecoveryMode,
};
use fedimint_client_module::module::recovery::{NoModuleBackup, RecoveryProgress};
use fedimint_client_module::module::{ClientContext, ClientModule, StateGenerator};
use fedimint_client_module::transaction::{
    ClientInput, ClientInputBundle, ClientInputSM, ClientOutput, ClientOutputBundle,
    ClientOutputSM, TransactionBuilder,
};
use fedimint_core::core::OperationId;
use fedimint_core::db::{DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::module::{AmountUnit, Amounts, ApiVersion, ModuleInit, MultiApiVersion};
use fedimint_core::secp256k1::Keypair;
use fedimint_core::{Amount, OutPoint, TransactionId, apply, async_trait_maybe_send};
use futures::StreamExt as _;

use crate::authorization::{Authorization, PreparedSpend};
use crate::common::assets::AssetBundle;
use crate::common::{ContractInput, ContractOutput, SimplicityCommonInit, SimplicityModuleTypes};
use crate::compiler::{TemplateProgramWitness, WitnessNameToValueMap, WitnessValues};
use crate::descriptor::{BuiltinTemplates, ContractDescriptor, ContractTemplates};
use crate::states::{OperationStatus, SimplicityState};
use crate::wallet::{HistoryEntry, WalletContract, WalletStore, db};

/// Applications provide non-signature witnesses; the named owner signature is
/// installed only after core funding and change are fixed. Public covenants
/// such as the market vault use `None`.
#[derive(Clone)]
pub struct SpendIntent {
    pub outpoint: OutPoint,
    pub witnesses: WitnessValues,
    pub signature_witness: Option<String>,
}

impl SpendIntent {
    pub fn owner(outpoint: OutPoint) -> Self {
        Self {
            outpoint,
            witnesses: WitnessValues::from_map(Default::default()),
            signature_witness: Some("SIGNATURE".to_owned()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SimplicityClientInit {
    pub templates: Arc<dyn ContractTemplates>,
}

impl Default for SimplicityClientInit {
    fn default() -> Self {
        Self {
            templates: Arc::new(BuiltinTemplates),
        }
    }
}

impl ModuleInit for SimplicityClientInit {
    type Common = SimplicityCommonInit;

    async fn dump_database(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        // Descriptors contain wallet secrets and application context.
        Box::new(std::iter::empty())
    }
}

#[apply(async_trait_maybe_send!)]
impl ClientModuleInit for SimplicityClientInit {
    type Module = SimplicityClientModule;

    fn supported_api_versions(&self) -> MultiApiVersion {
        MultiApiVersion::try_from_iter([ApiVersion::new(0, 0)]).expect("one API version")
    }

    fn recovery_mode(&self) -> RecoveryMode {
        RecoveryMode::Unusable
    }

    async fn init(
        &self,
        args: &ClientModuleInitArgs<Self>,
    ) -> Result<Self::Module, ClientModuleError> {
        let store = WalletStore::open(
            args.db.clone(),
            &args.module_root_secret,
            args.federation_id,
            args.context.module_instance_id(),
            self.templates.clone(),
        )
        .await
        .map_err(ClientModuleError::other)?;
        Ok(SimplicityClientModule {
            store,
            context: args.context(),
        })
    }

    async fn recover(
        &self,
        args: &ClientModuleRecoverArgs<Self>,
        _snapshot: Option<&NoModuleBackup>,
    ) -> Result<Option<Amount>, ClientModuleError> {
        let store = WalletStore::open(
            args.db.clone(),
            &args.module_root_secret,
            args.federation_id,
            args.context.module_instance_id(),
            self.templates.clone(),
        )
        .await
        .map_err(ClientModuleError::other)?;
        store
            .sync(&args.api, &args.context.decoders(), |complete, total| {
                let total = total.min(u64::from(u32::MAX)) as u32;
                args.update_recovery_progress(RecoveryProgress {
                    complete: (complete.min(u64::from(total.saturating_sub(1)))) as u32,
                    total,
                });
            })
            .await
            .map_err(ClientModuleError::other)?;
        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct SimplicityClientModule {
    pub(crate) store: WalletStore,
    pub(crate) context: ClientContext<Self>,
}

#[apply(async_trait_maybe_send!)]
impl ClientModule for SimplicityClientModule {
    type Init = SimplicityClientInit;
    type Common = SimplicityModuleTypes;
    type Backup = NoModuleBackup;
    type ModuleStateMachineContext = Self;
    type States = SimplicityState;

    fn context(&self) -> Self {
        self.clone()
    }

    fn input_fee(&self, _amount: &Amounts, input: &ContractInput) -> Option<Amounts> {
        crate::common::runtime::input_fee(input)
            .ok()
            .map(Amounts::new_bitcoin)
    }

    fn output_fee(&self, _amount: &Amounts, output: &ContractOutput) -> Option<Amounts> {
        Some(Amounts::new_bitcoin(crate::common::output_fee(output)))
    }

    async fn get_balance(&self, dbtx: &mut DatabaseTransaction<'_>, unit: AmountUnit) -> Amount {
        if unit != AmountUnit::BITCOIN {
            return Amount::ZERO;
        }
        let contracts = dbtx
            .find_by_prefix(&db::ContractPrefix)
            .await
            .collect::<Vec<_>>()
            .await;
        contracts
            .into_iter()
            .filter(|(_, contract)| {
                contract.spent_by.is_none()
                    && self.store.templates.owns_balance(&contract.descriptor)
            })
            .fold(Amount::ZERO, |total, (_, contract)| {
                total + contract.output.amount
            })
    }
}

impl SimplicityClientModule {
    /// Refresh holdings and confirmed history. Safe to repeat or interrupt.
    pub async fn sync(&self) -> anyhow::Result<()> {
        self.store
            .sync(
                &self.context.global_api(),
                &self.context.decoders(),
                |_, _| {},
            )
            .await
    }

    pub async fn contracts(&self) -> Vec<(OutPoint, WalletContract)> {
        self.store.contracts().await
    }
    pub async fn history(&self) -> Vec<HistoryEntry> {
        self.store.history().await
    }

    /// A fresh receive policy and encrypted descriptor for a sender. The sender
    /// can use this output unchanged, without learning wallet discovery keys.
    pub fn receive(&self, amount: Amount, bundle: AssetBundle) -> anyhow::Result<ContractOutput> {
        self.output(
            &ContractDescriptor::owner(rand::random()),
            amount,
            [0; 32],
            bundle,
        )
    }

    pub fn output(
        &self,
        descriptor: &ContractDescriptor,
        amount: Amount,
        state: [u8; 32],
        bundle: AssetBundle,
    ) -> anyhow::Result<ContractOutput> {
        let (version, program) = self
            .store
            .keys
            .program(descriptor, self.store.templates.as_ref())?;
        let recovery = self.store.keys.encrypt(descriptor)?;
        match version {
            crate::common::EXECUTION_VERSION => {
                ensure!(
                    bundle == AssetBundle::default(),
                    "v0 contracts cannot hold assets"
                );
                program.output(amount, state, recovery)
            }
            crate::common::assets::ASSET_VERSION => {
                program.asset_output(amount, state, recovery, bundle)
            }
            _ => anyhow::bail!("unsupported execution version"),
        }
    }

    /// Atomically reserve inputs, obtain native funding/change from the primary
    /// module, authorize the final intent, and persist the submission. Once
    /// this returns, the core executor retries submission across client
    /// restarts. Asset change and authority successors are explicit
    /// application outputs.
    pub async fn submit(
        &self,
        spends: Vec<SpendIntent>,
        outputs: Vec<ContractOutput>,
        creations: Vec<Keypair>,
    ) -> anyhow::Result<(OperationId, TransactionId)> {
        self.submit_inner(spends, outputs, creations, None).await
    }

    /// Include an encrypted sender receipt even when owned contracts already
    /// identify this transaction. Context is application-defined and versioned.
    pub async fn submit_with_receipt(
        &self,
        spends: Vec<SpendIntent>,
        outputs: Vec<ContractOutput>,
        creations: Vec<Keypair>,
        context: Option<crate::receipt::ReceiptContext>,
    ) -> anyhow::Result<(OperationId, TransactionId)> {
        self.submit_inner(
            spends,
            outputs,
            creations,
            Some(crate::receipt::SenderReceipt { context }),
        )
        .await
    }

    async fn submit_inner(
        &self,
        spends: Vec<SpendIntent>,
        mut outputs: Vec<ContractOutput>,
        creations: Vec<Keypair>,
        requested_receipt: Option<crate::receipt::SenderReceipt>,
    ) -> anyhow::Result<(OperationId, TransactionId)> {
        ensure!(
            !spends.is_empty() || !outputs.is_empty(),
            "empty contract operation"
        );
        ensure!(
            !self.store.is_recovering().await,
            "wallet recovery must finish first"
        );
        let operation_id = OperationId::new_random();
        let points: Vec<_> = spends.iter().map(|spend| spend.outpoint).collect();
        let mut dbtx = self.store.db.begin_transaction().await;
        dbtx.insert_new_entry(&db::OperationResultKey(operation_id), &None)
            .await;
        let mut inputs = vec![];
        let mut prepared = vec![];
        for spend in spends {
            let contract = dbtx
                .get_value(&db::ContractKey(spend.outpoint))
                .await
                .ok_or_else(|| anyhow::anyhow!("unknown contract"))?;
            ensure!(
                contract.spent_by.is_none(),
                "contract has already been spent"
            );
            ensure!(
                dbtx.get_value(&db::ReservationKey(spend.outpoint))
                    .await
                    .is_none(),
                "contract is reserved by another operation"
            );
            dbtx.insert_new_entry(&db::ReservationKey(spend.outpoint), &operation_id)
                .await;
            let (version, program) = self
                .store
                .keys
                .program(&contract.descriptor, self.store.templates.as_ref())?;
            let key = self.store.keys.signing_key(&contract.descriptor);
            let mut witnesses = spend.witnesses.as_inner().as_ref().clone();
            if let Some(name) = &spend.signature_witness {
                witnesses.insert(
                    TemplateProgramWitness::witness_from_str(name.as_str()),
                    crate::placeholder_signature(),
                );
            }
            inputs.push(ClientInput {
                input: program.input(
                    spend.outpoint,
                    key.public_key(),
                    WitnessValues::from_map(witnesses),
                )?,
                keys: vec![key],
                amounts: Amounts::new_bitcoin(contract.output.amount),
            });
            prepared.push(PreparedSpend {
                outpoint: spend.outpoint,
                version,
                key,
                program,
                witnesses: spend.witnesses,
                signature_witness: spend.signature_witness,
            });
        }
        let mut tracked = !points.is_empty();
        for output in &outputs {
            if let Some(descriptor) = self.store.keys.decrypt(&output.recovery)? {
                let (version, program) = self
                    .store
                    .keys
                    .program(&descriptor, self.store.templates.as_ref())?;
                tracked |= version == output.version && program.cmr() == output.cmr;
            }
        }
        let receipt = if requested_receipt.is_some() || !tracked {
            let action_indices = outputs
                .iter()
                .enumerate()
                .filter(|(_, output)| output.actions().is_some())
                .map(|(i, _)| i)
                .collect::<Vec<_>>();
            ensure!(action_indices.len() <= 1, "multiple action outputs");
            let output_index = if let Some(index) = action_indices.first() {
                *index
            } else {
                outputs.push(ContractOutput::action_output(Default::default()));
                outputs.len() - 1
            };
            ensure!(
                outputs[output_index].recovery.is_empty(),
                "action output already contains recovery metadata"
            );
            let plan = crate::receipt::ReceiptPlan {
                keys: self.store.keys.clone(),
                federation: self.store.federation,
                module: self.store.module,
                output_index,
                receipt: requested_receipt
                    .unwrap_or(crate::receipt::SenderReceipt { context: None }),
            };
            outputs[output_index].recovery = plan.placeholder()?;
            Some(plan)
        } else {
            None
        };
        let state_gen: StateGenerator<SimplicityState> = Arc::new(move |range| {
            vec![SimplicityState {
                operation_id,
                txid: range.txid(),
                inputs: points.clone(),
                status: OperationStatus::Submitted,
            }]
        });
        let mut builder = TransactionBuilder::new();
        let has_inputs = !inputs.is_empty();
        if has_inputs {
            builder = builder.with_inputs(self.context.make_client_inputs(ClientInputBundle::new(
                inputs,
                vec![ClientInputSM {
                    state_machines: state_gen.clone(),
                }],
            )));
        }
        if !outputs.is_empty() {
            builder = builder.with_outputs(
                self.context.make_client_outputs(ClientOutputBundle::new(
                    outputs
                        .into_iter()
                        .map(|output| ClientOutput {
                            amounts: Amounts::new_bitcoin(output.amount),
                            output,
                        })
                        .collect(),
                    if has_inputs {
                        vec![]
                    } else {
                        vec![ClientOutputSM {
                            state_machines: state_gen,
                        }]
                    },
                )),
            );
        }
        builder = builder.with_finalizer(
            self.store.module,
            Arc::new(Authorization {
                federation: self.store.federation,
                module: self.store.module,
                spends: prepared,
                creations,
                receipt,
            }),
        );
        let range = self
            .context
            .finalize_and_submit_transaction_dbtx(
                &mut dbtx.to_ref_nc(),
                operation_id,
                "simplicity",
                |_| (),
                builder,
            )
            .await?;
        dbtx.commit_tx_result().await?;
        Ok((operation_id, range.txid()))
    }

    /// Wait for durable submission, rejection cleanup, and confirmed history.
    pub async fn await_operation(&self, operation_id: OperationId) -> anyhow::Result<()> {
        let (result, _) = self
            .store
            .db
            .wait_key_check(&db::OperationResultKey(operation_id), |value| match value {
                Some(Some(result)) => Some(result),
                Some(None) => None,
                None => Some(Err(
                    "unknown local operation; recovered activity is available in history"
                        .to_owned(),
                )),
            })
            .await;
        result.map_err(anyhow::Error::msg)
    }
}

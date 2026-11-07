//! Wallet integration with the core client's funding, submission and recovery.
use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::ensure;
use fedimint_client_module::error::ClientModuleError;
use fedimint_client_module::module::init::{
    ClientModuleInit, ClientModuleInitArgs, ClientModuleRecoverArgs, RecoveryMode,
};
use fedimint_client_module::module::recovery::{NoModuleBackup, RecoveryProgress};
use fedimint_client_module::module::{ClientContext, ClientModule, StateGenerator};
use fedimint_client_module::transaction::{
    ClientInputBundle, ClientInputSM, ClientOutput, ClientOutputBundle, ClientOutputSM,
    TransactionBuilder,
};
use fedimint_core::core::OperationId;
use fedimint_core::db::{DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::module::{AmountUnit, Amounts, ApiVersion, ModuleInit, MultiApiVersion};
use fedimint_core::secp256k1::Keypair;
use fedimint_core::{Amount, OutPoint, TransactionId, apply, async_trait_maybe_send};
use futures::StreamExt as _;

use crate::common::assets::AssetBundle;
use crate::common::{ContractInput, ContractOutput, SimplicityCommonInit, SimplicityModuleTypes};
use crate::compiler::{WitnessNameToValueMap, WitnessValues};
use crate::descriptor::{BuiltinTemplates, ContractDescriptor, ContractTemplates};
use crate::preparation::{PreparedTransaction, TransactionPlan};
use crate::pruning::PruningSnapshot;
use crate::states::{OperationStatus, SimplicityState};
use crate::wallet::{
    HistoryEntry, SessionHistory, WalletContract, WalletCursor, WalletPage, WalletStore, db,
};

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
    pub intents: Arc<dyn crate::intent::IntentHandlers>,
}

impl Default for SimplicityClientInit {
    fn default() -> Self {
        Self {
            templates: Arc::new(BuiltinTemplates),
            intents: Arc::new(crate::intent::NoIntentHandlers),
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
        MultiApiVersion::try_from_iter([ApiVersion::new(0, 1)]).expect("one API version")
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
            core_api_version: args.core_api_version,
            context: args.context(),
            intents: self.intents.clone(),
            intent_lock: Arc::new(tokio::sync::Mutex::new(())),
            tasks: args.task_group().clone(),
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
        let history = SessionHistory::new(
            args.api.clone(),
            args.context.decoders(),
            args.core_api_version,
            args.context.get_config().await.global.broadcast_public_keys,
        );
        store
            .sync(&history, |complete, total| {
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
    core_api_version: ApiVersion,
    pub(crate) context: ClientContext<Self>,
    pub(crate) intents: Arc<dyn crate::intent::IntentHandlers>,
    pub(crate) intent_lock: Arc<tokio::sync::Mutex<()>>,
    tasks: fedimint_core::task::TaskGroup,
}

#[apply(async_trait_maybe_send!)]
impl ClientModule for SimplicityClientModule {
    type Init = SimplicityClientInit;
    type Common = SimplicityModuleTypes;
    type Backup = NoModuleBackup;
    type ModuleStateMachineContext = Self;
    type States = SimplicityState;

    async fn start(&self) {
        let module = self.context.self_ref().clone();
        self.tasks
            .spawn_cancellable("simplicity intents", async move {
                module.run_intents().await;
            });
    }

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
        dbtx.find_by_prefix(&db::ContractPrefix)
            .await
            .fold(Amount::ZERO, |total, (_, contract)| async move {
                if contract.spent_by.is_none()
                    && self.store.templates.owns_balance(&contract.descriptor)
                {
                    total + contract.output.amount
                } else {
                    total
                }
            })
            .await
    }
}

impl SimplicityClientModule {
    /// Refresh holdings and confirmed history. Safe to repeat or interrupt.
    pub async fn sync(&self) -> anyhow::Result<()> {
        self.sync_with_progress(|_| {}).await
    }

    /// As [`Self::sync`], with observational progress scoped to this call.
    /// Progress does not establish completion or authorize spending.
    pub async fn sync_with_progress(
        &self,
        progress: impl Fn(crate::wallet::SyncProgress) + Send + Sync,
    ) -> anyhow::Result<()> {
        self.store
            .sync(&self.session_history().await, |next, end| {
                progress(crate::wallet::SyncProgress::Wallet { next, end });
            })
            .await
    }

    pub async fn session_history(&self) -> SessionHistory {
        SessionHistory::new(
            self.context.global_api(),
            self.context.decoders(),
            self.core_api_version,
            self.context.get_config().await.global.broadcast_public_keys,
        )
    }

    /// Point-read an authenticated local record without allocating the wallet.
    pub async fn contract(&self, point: OutPoint) -> Option<WalletContract> {
        self.store.contract(point).await
    }

    /// Allocate all contract records. Prefer `contracts_page` for large
    /// wallets.
    pub async fn contracts(&self) -> Vec<(OutPoint, WalletContract)> {
        self.store.contracts().await
    }
    /// Allocate the complete history. Prefer `history_page` for large wallets.
    pub async fn history(&self) -> Vec<HistoryEntry> {
        self.store.history().await
    }

    /// Bounded contract listing; see [`WalletStore::contracts_page`].
    pub async fn contracts_page(
        &self,
        cursor: Option<&WalletCursor>,
        limit: usize,
    ) -> anyhow::Result<WalletPage<(OutPoint, WalletContract)>> {
        self.store.contracts_page(cursor, limit).await
    }

    /// Bounded confirmed history; see [`WalletStore::history_page`].
    pub async fn history_page(
        &self,
        cursor: Option<&WalletCursor>,
        limit: usize,
    ) -> anyhow::Result<WalletPage<HistoryEntry>> {
        self.store.history_page(cursor, limit).await
    }

    /// Scope all public descriptors and derived identifiers to this module.
    pub fn scope(
        &self,
    ) -> (
        fedimint_core::config::FederationId,
        fedimint_core::core::ModuleInstanceId,
    ) {
        (self.store.federation, self.store.module)
    }

    /// Derive a template's wallet key. Applications use this for creator oracle
    /// attestations and signed creation namespaces. Never log or export it;
    /// persist only the encrypted descriptor, whose nonce restores the key.
    pub fn descriptor_key(&self, descriptor: &ContractDescriptor) -> Keypair {
        self.store.keys.signing_key(descriptor)
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
        ensure!(
            version == crate::common::EXECUTION_VERSION,
            "unsupported execution version"
        );
        let output = program.asset_output(amount, state, recovery, bundle)?;
        self.store.templates.validate_output(descriptor, &output)?;
        Ok(output)
    }

    /// Atomically reserve inputs, obtain native funding/change from the primary
    /// module, authorize the final transaction, and persist the submission.
    /// Once this returns, the core executor retries submission across client
    /// restarts. Asset change and authority successors are explicit
    /// application outputs.
    pub async fn submit(
        &self,
        spends: Vec<SpendIntent>,
        outputs: Vec<ContractOutput>,
        creations: Vec<Keypair>,
    ) -> anyhow::Result<(OperationId, TransactionId)> {
        self.submit_plan(TransactionPlan {
            spends,
            outputs,
            creations,
            ..Default::default()
        })
        .await
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
        self.submit_plan(TransactionPlan {
            spends,
            outputs,
            creations,
            receipt: Some(crate::receipt::SenderReceipt { context }),
            ..Default::default()
        })
        .await
    }

    /// Submit a plan, preparing it exactly as [`Self::quote_transaction`]
    /// does. A quote authorizes nothing and caches no signatures: this reads
    /// current wallet records and a fresh pruning snapshot, reserves the
    /// inputs, and finalization checks the funded transaction and the plan's
    /// `max_fee` again.
    pub async fn submit_plan(
        &self,
        plan: TransactionPlan,
    ) -> anyhow::Result<(OperationId, TransactionId)> {
        let snapshot = self
            .pruning_snapshot(plan.spends.iter().map(|spend| spend.outpoint))
            .await?;
        let mut dbtx = self.store.db.begin_transaction().await;
        let result = self
            .submit_plan_dbtx(&mut dbtx.to_ref_nc(), plan, false, snapshot)
            .await?;
        dbtx.commit_tx_result().await?;
        Ok(result)
    }

    /// Prepare read-only, then write reservations, funding and the submission
    /// in the caller's database transaction. The pruning snapshot must have
    /// been fetched before that transaction opened.
    pub(crate) async fn submit_plan_dbtx(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        plan: TransactionPlan,
        reserve_funding: bool,
        snapshot: PruningSnapshot,
    ) -> anyhow::Result<(OperationId, TransactionId)> {
        ensure!(
            !self.store.is_recovering().await,
            "wallet recovery must finish first"
        );
        let mut contracts = BTreeMap::new();
        for spend in &plan.spends {
            if let Some(contract) = dbtx.get_value(&db::ContractKey(spend.outpoint)).await {
                contracts.insert(spend.outpoint, contract);
            }
        }
        let PreparedTransaction {
            inputs,
            outputs,
            authorization,
        } = self
            .store
            .prepare_transaction(&plan, &contracts, &snapshot)?;
        let operation_id = OperationId::new_random();
        let points: Vec<_> = plan.spends.iter().map(|spend| spend.outpoint).collect();
        dbtx.insert_new_entry(&db::OperationResultKey(operation_id), &None)
            .await;
        for point in &points {
            ensure!(
                dbtx.get_value(&db::ReservationKey(*point)).await.is_none(),
                "contract is reserved by another operation"
            );
            dbtx.insert_new_entry(&db::ReservationKey(*point), &operation_id)
                .await;
        }
        let authorization = Arc::new(authorization);
        let state_gen: StateGenerator<SimplicityState> = Arc::new(move |range| {
            vec![SimplicityState {
                operation_id,
                txid: range.txid(),
                inputs: points.clone(),
                status: OperationStatus::Submitted,
            }]
        });
        let mut builder = TransactionBuilder::new();
        if reserve_funding {
            builder = builder.with_funding_reservations();
        }
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
        builder = builder.with_finalizer(self.store.module, authorization);
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
        crate::intent::advance_revision(&mut dbtx.to_ref_nc()).await;
        Ok((operation_id, range.txid()))
    }

    /// Read local progress without a federation request or waiting for history.
    /// `Accepted` means the transaction was accepted but history
    /// synchronization is still pending. `Complete` does not imply another
    /// module's change or funding-restoration state machines have finished.
    /// This is informational; use the intent API for cancellation/retry and
    /// funding safety decisions. Mnemonic recovery restores confirmed
    /// history, not local operation IDs.
    pub async fn operation_status(&self, operation_id: OperationId) -> Option<OperationStatus> {
        // Read active state first, then the durable result so a concurrent
        // terminal transition cannot appear pending after we see its result.
        let active = self
            .context
            .get_own_operation_active_states(operation_id)
            .await;
        match self
            .store
            .db
            .begin_transaction_nc()
            .await
            .get_value(&db::OperationResultKey(operation_id))
            .await?
        {
            Some(Ok(())) => Some(OperationStatus::Complete),
            Some(Err(error)) => Some(OperationStatus::Rejected(error)),
            None => Some(
                active
                    .into_iter()
                    .next()
                    .map_or(OperationStatus::Submitted, |(state, _)| state.status),
            ),
        }
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

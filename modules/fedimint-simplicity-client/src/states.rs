use std::time::Duration;

use fedimint_client_module::DynGlobalClientContext;
use fedimint_client_module::sm::{Context, DynState, State, StateTransition};
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId, ModuleKind, OperationId};
use fedimint_core::db::IDatabaseTransactionOpsCoreTyped;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::util::FmtCompactAnyhow as _;
use fedimint_core::{OutPoint, TransactionId};

use crate::LOG_CLIENT_SIMPLICITY;
use crate::client::SimplicityClientModule;
use crate::wallet::db;

impl Context for SimplicityClientModule {
    const KIND: Option<ModuleKind> = Some(crate::common::KIND);
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub enum OperationStatus {
    Submitted,
    Accepted,
    Complete,
    Rejected(String),
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct SimplicityState {
    pub operation_id: OperationId,
    pub txid: TransactionId,
    pub inputs: Vec<OutPoint>,
    pub status: OperationStatus,
}

impl State for SimplicityState {
    type ModuleContext = SimplicityClientModule;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        match self.status {
            OperationStatus::Submitted => {
                let global = global_context.clone();
                let txid = self.txid;
                vec![StateTransition::new(
                    async move { global.await_tx_accepted(txid).await },
                    |dbtx, result: Result<(), String>, mut old: Self| {
                        Box::pin(async move {
                            match result {
                                Ok(()) => old.status = OperationStatus::Accepted,
                                Err(error) => {
                                    for point in &old.inputs {
                                        if dbtx
                                            .module_tx()
                                            .get_value(&db::ReservationKey(*point))
                                            .await
                                            == Some(old.operation_id)
                                        {
                                            dbtx.module_tx()
                                                .remove_entry(&db::ReservationKey(*point))
                                                .await;
                                        }
                                    }
                                    dbtx.module_tx()
                                        .insert_entry(
                                            &db::OperationResultKey(old.operation_id),
                                            &Some(Err(error.clone())),
                                        )
                                        .await;
                                    old.status = OperationStatus::Rejected(error);
                                }
                            }
                            crate::intent::advance_revision(&mut dbtx.module_tx()).await;
                            old
                        })
                    },
                )]
            }
            OperationStatus::Accepted => {
                let module = context.clone();
                let txid = self.txid;
                vec![StateTransition::new(
                    async move {
                        loop {
                            match module.sync().await {
                                Ok(()) if module.store.has_transaction(txid).await => break,
                                Ok(()) => {}
                                Err(error) => {
                                    tracing::warn!(target: LOG_CLIENT_SIMPLICITY, %txid, error = %error.fmt_compact_anyhow(), "Retrying accepted transaction history synchronization")
                                }
                            }
                            fedimint_core::runtime::sleep(Duration::from_secs(1)).await;
                        }
                    },
                    |dbtx, (), mut old: Self| {
                        Box::pin(async move {
                            dbtx.module_tx()
                                .insert_entry(
                                    &db::OperationResultKey(old.operation_id),
                                    &Some(Ok(())),
                                )
                                .await;
                            old.status = OperationStatus::Complete;
                            crate::intent::advance_revision(&mut dbtx.module_tx()).await;
                            old
                        })
                    },
                )]
            }
            OperationStatus::Complete | OperationStatus::Rejected(_) => vec![],
        }
    }

    fn operation_id(&self) -> OperationId {
        self.operation_id
    }
}

impl IntoDynInstance for SimplicityState {
    type DynType = DynState;
    fn into_dyn(self, instance_id: ModuleInstanceId) -> DynState {
        DynState::from_typed(instance_id, self)
    }
}

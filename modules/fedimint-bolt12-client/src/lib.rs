#![deny(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

//! User wallet client module for federated BOLT12 offline receives.

pub mod api;
pub mod bolt12;
#[cfg(feature = "cli")]
mod cli;
pub mod db;
pub mod events;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use api::Bolt12FederationApi;
use bolt12::{Bolt12ReceiveOperationMeta, Bolt12ReceiveStateMachine, Bolt12SetupOperationMeta};
use fedimint_api_client::api::DynModuleApi;
use fedimint_bolt12_common::config::Bolt12ClientConfig;
use fedimint_bolt12_common::gateway_api::{GatewayConnection, RealGatewayConnection};
use fedimint_bolt12_common::{Bolt12CommonInit, Bolt12InputV0, Bolt12ModuleTypes, KIND};
use fedimint_client_module::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client_module::module::recovery::NoModuleBackup;
use fedimint_client_module::module::{ClientContext, ClientModule, IClientModule};
use fedimint_client_module::sm::{Context, DynState, ModuleNotifier, State, StateTransition};
use fedimint_client_module::{
    ClientModuleError, DynGlobalClientContext, sm_enum_variant_translation,
};
use fedimint_core::config::FederationId;
use fedimint_core::core::{Decoder, IntoDynInstance, ModuleInstanceId, ModuleKind, OperationId};
use fedimint_core::db::DatabaseTransaction;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{
    Amounts, ApiAuth, ApiVersion, ModuleCommon, ModuleInit, MultiApiVersion,
};
use fedimint_core::task::TaskGroup;
use fedimint_core::util::{FmtCompact as _, SafeUrl};
use fedimint_core::{PeerId, apply, async_trait_maybe_send};
use fedimint_derive_secret::{ChildId, DerivableSecret};
use fedimint_ln_common::client::GatewayApi;
use fedimint_logging::LOG_CLIENT_MODULE_LNV2;
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator;
use tracing::warn;

use crate::db::DbKeyPrefix;

#[derive(Debug, Clone, Default)]
pub struct Bolt12ClientInit {
    pub gateway_conn: Option<Arc<dyn GatewayConnection + Send + Sync>>,
}

impl ModuleInit for Bolt12ClientInit {
    type Common = Bolt12CommonInit;

    #[allow(clippy::unused_async_trait_impl)]
    async fn dump_database(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        let items: BTreeMap<String, Box<dyn erased_serde::Serialize + Send>> = BTreeMap::new();
        let _ = DbKeyPrefix::iter();
        Box::new(items.into_iter())
    }
}

#[apply(async_trait_maybe_send!)]
impl ClientModuleInit for Bolt12ClientInit {
    type Module = Bolt12ClientModule;

    fn supported_api_versions(&self) -> MultiApiVersion {
        MultiApiVersion::try_from_iter([ApiVersion { major: 0, minor: 0 }])
            .expect("no version conflicts")
    }

    async fn init(
        &self,
        args: &ClientModuleInitArgs<Self>,
    ) -> Result<Self::Module, ClientModuleError> {
        let gateway_conn = self.gateway_conn.clone().unwrap_or_else(|| {
            Arc::new(RealGatewayConnection {
                api: GatewayApi::new(None, args.connector_registry.clone()),
            })
        });

        Ok(Bolt12ClientModule::new(
            *args.federation_id(),
            args.cfg().clone(),
            args.notifier().clone(),
            args.context(),
            args.module_api().clone(),
            args.module_root_secret(),
            gateway_conn,
            args.admin_auth().cloned(),
            args.task_group(),
            args.client_span(),
        ))
    }
}

#[derive(Debug, Clone)]
pub struct Bolt12ClientContext {
    pub decoder: Decoder,
    pub module_api: DynModuleApi,
    pub cfg: Bolt12ClientConfig,
    pub client_ctx: ClientContext<Bolt12ClientModule>,
}

impl Context for Bolt12ClientContext {
    const KIND: Option<ModuleKind> = Some(KIND);
}

#[derive(Debug, Clone)]
pub struct Bolt12ClientModule {
    federation_id: FederationId,
    cfg: Bolt12ClientConfig,
    notifier: ModuleNotifier<Bolt12ClientStateMachines>,
    client_ctx: ClientContext<Self>,
    module_api: DynModuleApi,
    bolt12_secret: DerivableSecret,
    gateway_conn: Arc<dyn GatewayConnection + Send + Sync>,
    #[allow(unused)]
    admin_auth: Option<ApiAuth>,
}

#[apply(async_trait_maybe_send!)]
impl ClientModule for Bolt12ClientModule {
    type Init = Bolt12ClientInit;
    type Common = Bolt12ModuleTypes;
    type Backup = NoModuleBackup;
    type ModuleStateMachineContext = Bolt12ClientContext;
    type States = Bolt12ClientStateMachines;

    fn context(&self) -> Self::ModuleStateMachineContext {
        Bolt12ClientContext {
            decoder: self.decoder(),
            module_api: self.module_api.clone(),
            cfg: self.cfg.clone(),
            client_ctx: self.client_ctx.clone(),
        }
    }

    fn input_fee(
        &self,
        amounts: &Amounts,
        input: &<Self::Common as ModuleCommon>::Input,
    ) -> Option<Amounts> {
        let fee = self.cfg.fee_consensus.fee(amounts.expect_only_bitcoin());
        let Bolt12InputV0::Receive(_, unlock) = input.ensure_v0_ref().ok()?;
        let premium = self.cfg.bolt12.unlock_premium(unlock);
        Some(Amounts::new_bitcoin(fee.checked_add(premium)?))
    }

    fn output_fee(
        &self,
        amounts: &Amounts,
        output: &<Self::Common as ModuleCommon>::Output,
    ) -> Option<Amounts> {
        self.cfg
            .output_fee(output.ensure_v0_ref().ok()?, amounts.expect_only_bitcoin())
            .map(Amounts::new_bitcoin)
    }

    #[cfg(feature = "cli")]
    async fn handle_cli_command(
        &self,
        args: &[std::ffi::OsString],
    ) -> Result<serde_json::Value, ClientModuleError> {
        cli::handle_cli_command(self, args)
            .await
            .map_err(ClientModuleError::other)
    }
}

impl Bolt12ClientModule {
    #[allow(clippy::too_many_arguments)]
    fn new(
        federation_id: FederationId,
        cfg: Bolt12ClientConfig,
        notifier: ModuleNotifier<Bolt12ClientStateMachines>,
        client_ctx: ClientContext<Self>,
        module_api: DynModuleApi,
        module_root_secret: &DerivableSecret,
        gateway_conn: Arc<dyn GatewayConnection + Send + Sync>,
        admin_auth: Option<ApiAuth>,
        task_group: &TaskGroup,
        client_span: &tracing::Span,
    ) -> Self {
        let module = Self {
            federation_id,
            cfg,
            notifier,
            client_ctx,
            module_api,
            bolt12_secret: module_root_secret.child_key(ChildId(0)),
            gateway_conn,
            admin_auth,
        };

        module.spawn_receive_bolt12_task(task_group, client_span);

        module
    }

    fn spawn_receive_bolt12_task(&self, task_group: &TaskGroup, client_span: &tracing::Span) {
        let module = self.clone();
        let api = self.module_api.clone();

        task_group.spawn_cancellable_with_span(
            client_span.clone(),
            "receive_bolt12_task",
            async move {
                api.wait_for_initialized_connections().await;

                let mut backoff = Duration::from_secs(1);
                while let Err(err) = module.recover_bolt12_offers().await {
                    warn!(
                        target: LOG_CLIENT_MODULE_LNV2,
                        err = %err.fmt_compact(),
                        "Could not look for previously registered BOLT12 offers; retrying"
                    );
                    fedimint_core::task::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                }

                loop {
                    module.receive_bolt12().await;
                }
            },
        );
    }

    pub fn bolt12_config(&self) -> &Bolt12ClientConfig {
        &self.cfg
    }

    pub async fn vetted_gateways(&self) -> anyhow::Result<Vec<SafeUrl>> {
        Ok(self.module_api.gateways().await?)
    }

    pub async fn gateways_from_peer(&self, peer: PeerId) -> anyhow::Result<Vec<SafeUrl>> {
        Ok(self.module_api.gateways_from_peer(peer).await?)
    }

    pub async fn add_gateway(&self, gateway: SafeUrl) -> anyhow::Result<bool> {
        let auth = self
            .admin_auth
            .clone()
            .ok_or_else(|| anyhow::anyhow!("Admin auth not set"))?;
        Ok(self.module_api.add_gateway(auth, gateway).await?)
    }

    pub async fn remove_gateway(&self, gateway: SafeUrl) -> anyhow::Result<bool> {
        let auth = self
            .admin_auth
            .clone()
            .ok_or_else(|| anyhow::anyhow!("Admin auth not set"))?;
        Ok(self.module_api.remove_gateway(auth, gateway).await?)
    }

    pub fn notifier(&self) -> &ModuleNotifier<Bolt12ClientStateMachines> {
        &self.notifier
    }

    pub fn module_api(&self) -> &DynModuleApi {
        &self.module_api
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Bolt12OperationMeta {
    Setup(Bolt12SetupOperationMeta),
    Receive(Bolt12ReceiveOperationMeta),
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum Bolt12ClientStateMachines {
    Receive(Bolt12ReceiveStateMachine),
}

impl IntoDynInstance for Bolt12ClientStateMachines {
    type DynType = DynState;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}

impl State for Bolt12ClientStateMachines {
    type ModuleContext = Bolt12ClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        match self {
            Bolt12ClientStateMachines::Receive(state) => {
                sm_enum_variant_translation!(
                    state.transitions(context, global_context),
                    Bolt12ClientStateMachines::Receive
                )
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        match self {
            Bolt12ClientStateMachines::Receive(state) => state.operation_id(),
        }
    }
}

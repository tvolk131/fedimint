use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{anyhow, bail, ensure, Context as _};
use bitcoin::key::Secp256k1;
use fedimint_api_client::api::global_api::with_cache::GlobalFederationApiWithCacheExt as _;
use fedimint_api_client::api::global_api::with_request_hook::{
    ApiRequestHook, RawFederationApiWithRequestHookExt as _,
};
use fedimint_api_client::api::net::Connector;
use fedimint_api_client::api::{ApiVersionSet, DynGlobalApi, ReconnectFederationApi};
use fedimint_client_module::api::ClientRawFederationApiExt as _;
use fedimint_client_module::meta::LegacyMetaSource;
use fedimint_client_module::module::init::ClientModuleInit;
use fedimint_client_module::module::recovery::RecoveryProgress;
use fedimint_client_module::module::{ClientModuleRegistry, FinalClientIface};
use fedimint_client_module::secret::DeriveableSecretClientExt as _;
use fedimint_client_module::transaction::{
    tx_submission_sm_decoder, TxSubmissionContext, TRANSACTION_SUBMISSION_MODULE_INSTANCE,
};
use fedimint_client_module::{AdminCreds, ModuleRecoveryStarted};
use fedimint_core::config::{ClientConfig, ModuleInitRegistry};
use fedimint_core::core::{ModuleInstanceId, ModuleKind};
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped as _};
use fedimint_core::module::registry::{ModuleDecoderRegistry, ModuleRegistry};
use fedimint_core::module::ApiVersion;
use fedimint_core::task::TaskGroup;
use fedimint_core::util::FmtCompactAnyhow as _;
use fedimint_core::{maybe_add_send, NumPeers};
use fedimint_derive_secret::DerivableSecret;
use fedimint_eventlog::{
    run_event_log_ordering_task, DBTransactionEventLogExt as _, EventLogEntry,
};
use fedimint_logging::LOG_CLIENT;
use tokio::sync::{broadcast, watch};
use tracing::{debug, warn};

use super::handle::ClientHandle;
use super::{client_decoders, Client};
use crate::api_announcements::{get_api_urls, run_api_announcement_sync};
use crate::backup::{ClientBackup, Metadata};
use crate::db::{
    self, apply_migrations_client, ApiSecretKey, ClientInitStateKey, ClientMetadataKey,
    ClientModuleRecovery, ClientModuleRecoveryState, ClientPreRootSecretHashKey, InitMode,
    InitState,
};
use crate::meta::MetaService;
use crate::module_init::ClientModuleInitRegistry;
use crate::oplog::OperationLog;
use crate::sm::executor::Executor;
use crate::sm::notifier::Notifier;

/// Used to configure, assemble and build [`Client`]
pub struct ClientBuilder {
    module_inits: ClientModuleInitRegistry,
    primary_module_instance: Option<ModuleInstanceId>,
    primary_module_kind: Option<ModuleKind>,
    admin_creds: Option<AdminCreds>,
    db_no_decoders: Database,
    meta_service: Arc<crate::meta::MetaService>,
    connector: Connector,
    stopped: bool,
    log_event_added_transient_tx: broadcast::Sender<EventLogEntry>,
    request_hook: ApiRequestHook,
}

impl ClientBuilder {
    pub(crate) fn new(db: Database) -> Self {
        let meta_service = MetaService::new(LegacyMetaSource::default());
        let (log_event_added_transient_tx, _log_event_added_transient_rx) =
            broadcast::channel(1024);
        ClientBuilder {
            module_inits: ModuleInitRegistry::new(),
            primary_module_instance: None,
            primary_module_kind: None,
            connector: Connector::default(),
            admin_creds: None,
            db_no_decoders: db,
            stopped: false,
            meta_service,
            log_event_added_transient_tx,
            request_hook: Arc::new(|api| api),
        }
    }

    pub(crate) fn from_existing(client: &Client) -> Self {
        ClientBuilder {
            module_inits: client.module_inits.clone(),
            primary_module_instance: Some(client.primary_module_instance),
            primary_module_kind: None,
            admin_creds: None,
            db_no_decoders: client.db.with_decoders(ModuleRegistry::default()),
            stopped: false,
            // non unique
            meta_service: client.meta_service.clone(),
            connector: client.connector,
            log_event_added_transient_tx: client.log_event_added_transient_tx.clone(),
            request_hook: client.request_hook.clone(),
        }
    }

    /// Replace module generator registry entirely
    pub fn with_module_inits(&mut self, module_inits: ClientModuleInitRegistry) {
        self.module_inits = module_inits;
    }

    /// Make module generator available when reading the config
    pub fn with_module<M: ClientModuleInit>(&mut self, module_init: M) {
        self.module_inits.attach(module_init);
    }

    pub fn stopped(&mut self) {
        self.stopped = true;
    }

    /// Build the [`Client`] with a custom wrapper around its api request logic
    ///
    /// This is intended to be used by downstream applications, e.g. to:
    ///
    /// * simulate offline mode,
    /// * save battery when the OS indicates lack of connectivity,
    /// * inject faults and delays for testing purposes,
    /// * collect statistics and emit notifications.
    pub fn with_api_request_hook(mut self, hook: ApiRequestHook) -> Self {
        self.request_hook = hook;
        self
    }

    /// Uses this module with the given instance id as the primary module. See
    /// [`fedimint_client_module::ClientModule::supports_being_primary`] for
    /// more information.
    ///
    /// ## Panics
    /// If there was a primary module specified previously
    #[deprecated(
        since = "0.6.0",
        note = "Use `with_primary_module_kind` instead, as the instance id can't be known upfront. If you *really* need the old behavior you can use `with_primary_module_instance_id`."
    )]
    pub fn with_primary_module(&mut self, primary_module_instance: ModuleInstanceId) {
        self.with_primary_module_instance_id(primary_module_instance);
    }

    /// **You are likely looking for
    /// [`ClientBuilder::with_primary_module_kind`]. This function is rarely
    /// useful and often dangerous, handle with care.**
    ///
    /// Uses this module with the given instance id as the primary module. See
    /// [`fedimint_client_module::ClientModule::supports_being_primary`] for
    /// more information. Since the module instance id of modules of a
    /// specific kind may differ between different federations it is
    /// generally not recommended to specify it, but rather to specify the
    /// module kind that should be used as primary. See
    /// [`ClientBuilder::with_primary_module_kind`].
    ///
    /// ## Panics
    /// If there was a primary module specified previously
    pub fn with_primary_module_instance_id(&mut self, primary_module_instance: ModuleInstanceId) {
        let was_replaced = self
            .primary_module_instance
            .replace(primary_module_instance)
            .is_some();
        assert!(
            !was_replaced,
            "Only one primary module can be given to the builder."
        );
    }

    /// Uses this module kind as the primary module if present in the config.
    /// See [`fedimint_client_module::ClientModule::supports_being_primary`] for
    /// more information.
    ///
    /// ## Panics
    /// If there was a primary module kind specified previously
    pub fn with_primary_module_kind(&mut self, primary_module_kind: ModuleKind) {
        let was_replaced = self
            .primary_module_kind
            .replace(primary_module_kind)
            .is_some();
        assert!(
            !was_replaced,
            "Only one primary module kind can be given to the builder."
        );
    }

    pub fn with_meta_service(&mut self, meta_service: Arc<MetaService>) {
        self.meta_service = meta_service;
    }

    async fn migrate_database(&self, db: &Database) -> anyhow::Result<()> {
        // Only apply the client database migrations if the database has been
        // initialized.
        // This only works as long as you don't change the client config
        if let Ok(client_config) = self.load_existing_config().await {
            for (module_id, module_cfg) in client_config.modules {
                let kind = module_cfg.kind.clone();
                let Some(init) = self.module_inits.get(&kind) else {
                    // normal, expected and already logged about when building the client
                    continue;
                };

                apply_migrations_client(
                    db,
                    kind.to_string(),
                    init.get_database_migrations(),
                    module_id,
                )
                .await?;
            }
        }

        Ok(())
    }

    pub fn db_no_decoders(&self) -> &Database {
        &self.db_no_decoders
    }

    pub async fn load_existing_config(&self) -> anyhow::Result<ClientConfig> {
        let Some(config) = Client::get_config_from_db(&self.db_no_decoders).await else {
            bail!("Client database not initialized")
        };

        Ok(config)
    }

    pub fn set_admin_creds(&mut self, creds: AdminCreds) {
        self.admin_creds = Some(creds);
    }

    pub fn with_connector(&mut self, connector: Connector) {
        self.connector = connector;
    }

    #[cfg(feature = "tor")]
    pub fn with_tor_connector(&mut self) {
        self.with_connector(Connector::tor());
    }

    async fn init(
        self,
        pre_root_secret: DerivableSecret,
        config: ClientConfig,
        api_secret: Option<String>,
        init_mode: InitMode,
    ) -> anyhow::Result<ClientHandle> {
        if Client::is_initialized(&self.db_no_decoders).await {
            bail!("Client database already initialized")
        }

        // Note: It's important all client initialization is performed as one big
        // transaction to avoid half-initialized client state.
        {
            debug!(target: LOG_CLIENT, "Initializing client database");
            let mut dbtx = self.db_no_decoders.begin_transaction().await;
            // Save config to DB
            dbtx.insert_new_entry(&crate::db::ClientConfigKey, &config)
                .await;
            dbtx.insert_entry(
                &ClientPreRootSecretHashKey,
                &pre_root_secret.derive_pre_root_secret_hash(),
            )
            .await;

            if let Some(api_secret) = api_secret.as_ref() {
                dbtx.insert_new_entry(&ApiSecretKey, api_secret).await;
            }

            let init_state = InitState::Pending(init_mode);
            dbtx.insert_entry(&ClientInitStateKey, &init_state).await;

            let metadata = init_state
                .does_require_recovery()
                .flatten()
                .map_or(Metadata::empty(), |s| s.metadata);

            dbtx.insert_new_entry(&ClientMetadataKey, &metadata).await;

            dbtx.commit_tx_result().await?;
        }

        let stopped = self.stopped;
        self.build(pre_root_secret, config, api_secret, stopped)
            .await
    }

    /// Join a new Federation
    ///
    /// When a user wants to connect to a new federation this function fetches
    /// the federation config and initializes the client database. If a user
    /// already joined the federation in the past and has a preexisting database
    /// use [`ClientBuilder::open`] instead.
    ///
    /// **Warning**: Calling `join` with a `root_secret` key that was used
    /// previous to `join` a Federation will lead to all sorts of malfunctions
    /// including likely loss of funds.
    ///
    /// This should be generally called only if the `root_secret` key is known
    /// not to have been used before (e.g. just randomly generated). For keys
    /// that might have been previous used (e.g. provided by the user),
    /// it's safer to call [`Self::recover`] which will attempt to recover
    /// client module states for the Federation.
    ///
    /// A typical "join federation" flow would look as follows:
    /// ```no_run
    /// # use std::str::FromStr;
    /// # use fedimint_core::invite_code::InviteCode;
    /// # use fedimint_core::config::ClientConfig;
    /// # use fedimint_derive_secret::DerivableSecret;
    /// # use fedimint_client::{Client, ClientBuilder};
    /// # use fedimint_core::db::Database;
    /// # use fedimint_core::config::META_FEDERATION_NAME_KEY;
    /// #
    /// # #[tokio::main]
    /// # async fn main() {
    /// # let root_secret: DerivableSecret = unimplemented!();
    /// // Create a root secret, e.g. via fedimint-bip39, see also:
    /// // https://github.com/fedimint/fedimint/blob/master/docs/secret_derivation.md
    /// // let root_secret = …;
    ///
    /// // Get invite code from user
    /// let invite_code = InviteCode::from_str("fed11qgqpw9thwvaz7te3xgmjuvpwxqhrzw3jxumrvvf0qqqjpetvlg8glnpvzcufhffgzhv8m75f7y34ryk7suamh8x7zetly8h0v9v0rm")
    ///     .expect("Invalid invite code");
    /// let config = fedimint_api_client::api::net::Connector::default().download_from_invite_code(&invite_code).await
    ///     .expect("Error downloading config");
    ///
    /// // Tell the user the federation name, bitcoin network
    /// // (e.g. from wallet module config), and other details
    /// // that are typically contained in the federation's
    /// // meta fields.
    ///
    /// // let network = config.get_first_module_by_kind::<WalletClientConfig>("wallet")
    /// //     .expect("Module not found")
    /// //     .network;
    ///
    /// println!(
    ///     "The federation name is: {}",
    ///     config.meta::<String>(META_FEDERATION_NAME_KEY)
    ///         .expect("Could not decode name field")
    ///         .expect("Name isn't set")
    /// );
    ///
    /// // Open the client's database, using the federation ID
    /// // as the DB name is a common pattern:
    ///
    /// // let db_path = format!("./path/to/db/{}", config.federation_id());
    /// // let db = RocksDb::open(db_path).expect("error opening DB");
    /// # let db: Database = unimplemented!();
    ///
    /// let client = Client::builder(db).await.expect("Error building client")
    ///     // Mount the modules the client should support:
    ///     // .with_module(LightningClientInit)
    ///     // .with_module(MintClientInit)
    ///     // .with_module(WalletClientInit::default())
    ///     .join(root_secret, config, None)
    ///     .await
    ///     .expect("Error joining federation");
    /// # }
    /// ```
    pub async fn join(
        self,
        pre_root_secret: DerivableSecret,
        config: ClientConfig,
        api_secret: Option<String>,
    ) -> anyhow::Result<ClientHandle> {
        self.init(pre_root_secret, config, api_secret, InitMode::Fresh)
            .await
    }

    /// Download most recent valid backup found from the Federation
    pub async fn download_backup_from_federation(
        &self,
        root_secret: &DerivableSecret,
        config: &ClientConfig,
        api_secret: Option<String>,
    ) -> anyhow::Result<Option<ClientBackup>> {
        let connector = self.connector;
        let api = DynGlobalApi::from_endpoints(
            // TODO: change join logic to use FederationId v2
            config
                .global
                .api_endpoints
                .iter()
                .map(|(peer_id, peer_url)| (*peer_id, peer_url.url.clone())),
            &api_secret,
            &connector,
        );
        Client::download_backup_from_federation_static(
            &api,
            &Self::federation_root_secret(root_secret, config),
            &self.decoders(config),
        )
        .await
    }

    /// Join a (possibly) previous joined Federation
    ///
    /// Unlike [`Self::join`], `recover` will run client module recovery for
    /// each client module attempting to recover any previous module state.
    ///
    /// Recovery process takes time during which each recovering client module
    /// will not be available for use.
    ///
    /// Calling `recovery` with a `root_secret` that was not actually previous
    /// used in a given Federation is safe.
    pub async fn recover(
        self,
        root_secret: DerivableSecret,
        config: ClientConfig,
        api_secret: Option<String>,
        backup: Option<ClientBackup>,
    ) -> anyhow::Result<ClientHandle> {
        let client = self
            .init(
                root_secret,
                config,
                api_secret,
                InitMode::Recover {
                    snapshot: backup.clone(),
                },
            )
            .await?;

        Ok(client)
    }

    pub async fn open(self, pre_root_secret: DerivableSecret) -> anyhow::Result<ClientHandle> {
        let Some(config) = Client::get_config_from_db(&self.db_no_decoders).await else {
            bail!("Client database not initialized")
        };

        if let Some(secret_hash) = self
            .db_no_decoders()
            .begin_transaction_nc()
            .await
            .get_value(&ClientPreRootSecretHashKey)
            .await
        {
            ensure!(
                pre_root_secret.derive_pre_root_secret_hash() == secret_hash,
                "Secret hash does not match. Incorrect secret"
            );
        } else {
            debug!(target: LOG_CLIENT, "Backfilling secret hash");
            // Note: no need for dbtx autocommit, we are the only writer ATM
            let mut dbtx = self.db_no_decoders.begin_transaction().await;
            dbtx.insert_entry(
                &ClientPreRootSecretHashKey,
                &pre_root_secret.derive_pre_root_secret_hash(),
            )
            .await;
            dbtx.commit_tx().await;
        }

        let api_secret = Client::get_api_secret_from_db(&self.db_no_decoders).await;
        let stopped = self.stopped;
        let request_hook = self.request_hook.clone();

        let log_event_added_transient_tx = self.log_event_added_transient_tx.clone();
        let client = self
            .build_stopped(
                pre_root_secret,
                &config,
                api_secret,
                log_event_added_transient_tx,
                request_hook,
            )
            .await?;
        if !stopped {
            client.as_inner().start_executor();
        }
        Ok(client)
    }

    /// Build a [`Client`] and start the executor
    pub(crate) async fn build(
        self,
        pre_root_secret: DerivableSecret,
        config: ClientConfig,
        api_secret: Option<String>,
        stopped: bool,
    ) -> anyhow::Result<ClientHandle> {
        let log_event_added_transient_tx = self.log_event_added_transient_tx.clone();
        let request_hook = self.request_hook.clone();
        let client = self
            .build_stopped(
                pre_root_secret,
                &config,
                api_secret,
                log_event_added_transient_tx,
                request_hook,
            )
            .await?;
        if !stopped {
            client.as_inner().start_executor();
        }

        Ok(client)
    }

    // TODO: remove config argument
    /// Build a [`Client`] but do not start the executor
    async fn build_stopped(
        self,
        root_secret: DerivableSecret,
        config: &ClientConfig,
        api_secret: Option<String>,
        log_event_added_transient_tx: broadcast::Sender<EventLogEntry>,
        request_hook: ApiRequestHook,
    ) -> anyhow::Result<ClientHandle> {
        let (log_event_added_tx, log_event_added_rx) = watch::channel(());
        let (log_ordering_wakeup_tx, log_ordering_wakeup_rx) = watch::channel(());

        let decoders = self.decoders(config);
        let config = Self::config_decoded(config, &decoders)?;
        let fed_id = config.calculate_federation_id();
        let db = self.db_no_decoders.with_decoders(decoders.clone());
        let connector = self.connector;
        let peer_urls = get_api_urls(&db, &config).await;
        let api = if let Some(admin_creds) = self.admin_creds.as_ref() {
            ReconnectFederationApi::new_admin(
                admin_creds.peer_id,
                peer_urls
                    .into_iter()
                    .find_map(|(peer, api_url)| (admin_creds.peer_id == peer).then_some(api_url))
                    .context("Admin creds should match a peer")?,
                &api_secret,
                &connector,
            )
            .with_client_ext(db.clone(), log_ordering_wakeup_tx.clone())
            .with_request_hook(&request_hook)
            .with_cache()
            .into()
        } else {
            ReconnectFederationApi::from_endpoints(peer_urls, &api_secret, &connector, None)
                .with_client_ext(db.clone(), log_ordering_wakeup_tx.clone())
                .with_request_hook(&request_hook)
                .with_cache()
                .into()
        };
        let task_group = TaskGroup::new();

        // Migrate the database before interacting with it in case any on-disk data
        // structures have changed.
        self.migrate_database(&db).await?;

        let init_state = Self::load_init_state(&db).await;

        let primary_module_instance = self
            .primary_module_instance
            .or_else(|| {
                let primary_module_kind = self.primary_module_kind?;
                config
                    .modules
                    .iter()
                    .find_map(|(module_instance_id, module_config)| {
                        (module_config.kind() == &primary_module_kind)
                            .then_some(*module_instance_id)
                    })
            })
            .ok_or(anyhow!("No primary module set or found"))?;

        let notifier = Notifier::new();

        let common_api_versions = Client::load_and_refresh_common_api_version_static(
            &config,
            &self.module_inits,
            &api,
            &db,
            &task_group,
        )
        .await
        .inspect_err(|err| {
            warn!(target: LOG_CLIENT, err = %err.fmt_compact_anyhow(), "Failed to discover initial API version to use.");
        })
        .unwrap_or(ApiVersionSet {
            core: ApiVersion::new(0, 0),
            // This will cause all modules to skip initialization
            modules: BTreeMap::new(),
        });

        debug!(target: LOG_CLIENT, ?common_api_versions, "Completed api version negotiation");

        let mut module_recoveries: BTreeMap<
            ModuleInstanceId,
            Pin<Box<maybe_add_send!(dyn Future<Output = anyhow::Result<()>>)>>,
        > = BTreeMap::new();
        let mut module_recovery_progress_receivers: BTreeMap<
            ModuleInstanceId,
            watch::Receiver<RecoveryProgress>,
        > = BTreeMap::new();

        let final_client = FinalClientIface::default();

        let root_secret = Self::federation_root_secret(&root_secret, &config);

        let modules = {
            let mut modules = ClientModuleRegistry::default();
            for (module_instance_id, module_config) in config.modules.clone() {
                let kind = module_config.kind().clone();
                let Some(module_init) = self.module_inits.get(&kind).cloned() else {
                    debug!(
                        target: LOG_CLIENT,
                        kind=%kind,
                        instance_id=%module_instance_id,
                        "Module kind of instance not found in module gens, skipping");
                    continue;
                };

                let Some(&api_version) = common_api_versions.modules.get(&module_instance_id)
                else {
                    warn!(
                        target: LOG_CLIENT,
                        kind=%kind,
                        instance_id=%module_instance_id,
                        "Module kind of instance has incompatible api version, skipping"
                    );
                    continue;
                };

                // since the exact logic of when to start recovery is a bit gnarly,
                // the recovery call is extracted here.
                let start_module_recover_fn =
                    |snapshot: Option<ClientBackup>, progress: RecoveryProgress| {
                        let module_config = module_config.clone();
                        let num_peers = NumPeers::from(config.global.api_endpoints.len());
                        let db = db.clone();
                        let kind = kind.clone();
                        let notifier = notifier.clone();
                        let api = api.clone();
                        let root_secret = root_secret.clone();
                        let admin_auth = self.admin_creds.as_ref().map(|creds| creds.auth.clone());
                        let final_client = final_client.clone();
                        let (progress_tx, progress_rx) = tokio::sync::watch::channel(progress);
                        let task_group = task_group.clone();
                        let module_init = module_init.clone();
                        (
                            Box::pin(async move {
                                module_init
                                    .recover(
                                        final_client.clone(),
                                        fed_id,
                                        num_peers,
                                        module_config.clone(),
                                        db.clone(),
                                        module_instance_id,
                                        common_api_versions.core,
                                        api_version,
                                        root_secret.derive_module_secret(module_instance_id),
                                        notifier.clone(),
                                        api.clone(),
                                        admin_auth,
                                        snapshot.as_ref().and_then(|s| s.modules.get(&module_instance_id)),
                                        progress_tx,
                                        task_group,
                                    )
                                    .await
                                    .inspect_err(|err| {
                                        warn!(
                                            target: LOG_CLIENT,
                                            module_id = module_instance_id, %kind, err = %err.fmt_compact_anyhow(), "Module failed to recover"
                                        );
                                    })
                            }),
                            progress_rx,
                        )
                    };

                let recovery = if let Some(snapshot) = init_state.does_require_recovery() {
                    if let Some(module_recovery_state) = db
                        .begin_transaction_nc()
                        .await
                        .get_value(&ClientModuleRecovery { module_instance_id })
                        .await
                    {
                        if module_recovery_state.is_done() {
                            debug!(
                                id = %module_instance_id,
                                %kind, "Module recovery already complete"
                            );
                            None
                        } else {
                            debug!(
                                id = %module_instance_id,
                                %kind,
                                progress = %module_recovery_state.progress,
                                "Starting module recovery with an existing progress"
                            );
                            Some(start_module_recover_fn(
                                snapshot,
                                module_recovery_state.progress,
                            ))
                        }
                    } else {
                        let progress = RecoveryProgress::none();
                        let mut dbtx = db.begin_transaction().await;
                        dbtx.log_event(
                            log_ordering_wakeup_tx.clone(),
                            None,
                            ModuleRecoveryStarted::new(module_instance_id),
                        )
                        .await;
                        dbtx.insert_entry(
                            &ClientModuleRecovery { module_instance_id },
                            &ClientModuleRecoveryState { progress },
                        )
                        .await;

                        dbtx.commit_tx().await;

                        debug!(
                            id = %module_instance_id,
                            %kind, "Starting new module recovery"
                        );
                        Some(start_module_recover_fn(snapshot, progress))
                    }
                } else {
                    None
                };

                if let Some((recovery, recovery_progress_rx)) = recovery {
                    module_recoveries.insert(module_instance_id, recovery);
                    module_recovery_progress_receivers
                        .insert(module_instance_id, recovery_progress_rx);
                } else {
                    let module = module_init
                        .init(
                            final_client.clone(),
                            fed_id,
                            config.global.api_endpoints.len(),
                            module_config,
                            db.clone(),
                            module_instance_id,
                            common_api_versions.core,
                            api_version,
                            // This is a divergence from the legacy client, where the child secret
                            // keys were derived using *module kind*-specific derivation paths.
                            // Since the new client has to support multiple, segregated modules of
                            // the same kind we have to use the instance id instead.
                            root_secret.derive_module_secret(module_instance_id),
                            notifier.clone(),
                            api.clone(),
                            self.admin_creds.as_ref().map(|cred| cred.auth.clone()),
                            task_group.clone(),
                        )
                        .await?;

                    if primary_module_instance == module_instance_id
                        && !module.supports_being_primary()
                    {
                        bail!("Module instance {primary_module_instance} of kind {kind} does not support being a primary module");
                    }

                    modules.register_module(module_instance_id, kind, module);
                }
            }
            modules
        };

        if init_state.is_pending() && module_recoveries.is_empty() {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_entry(&ClientInitStateKey, &init_state.into_complete())
                .await;
            dbtx.commit_tx().await;
        }

        let executor = {
            let mut executor_builder = Executor::builder();
            executor_builder
                .with_module(TRANSACTION_SUBMISSION_MODULE_INSTANCE, TxSubmissionContext);

            for (module_instance_id, _, module) in modules.iter_modules() {
                executor_builder.with_module_dyn(module.context(module_instance_id));
            }

            for module_instance_id in module_recoveries.keys() {
                executor_builder.with_valid_module_id(*module_instance_id);
            }

            executor_builder.build(db.clone(), notifier, task_group.clone())
        };

        let recovery_receiver_init_val = module_recovery_progress_receivers
            .iter()
            .map(|(module_instance_id, rx)| (*module_instance_id, *rx.borrow()))
            .collect::<BTreeMap<_, _>>();
        let (client_recovery_progress_sender, client_recovery_progress_receiver) =
            watch::channel(recovery_receiver_init_val);

        let client_inner = Arc::new(Client {
            final_client: final_client.clone(),
            config: tokio::sync::RwLock::new(config.clone()),
            api_secret,
            decoders,
            db: db.clone(),
            federation_id: fed_id,
            federation_config_meta: config.global.meta,
            primary_module_instance,
            modules,
            module_inits: self.module_inits.clone(),
            log_ordering_wakeup_tx,
            log_event_added_rx,
            log_event_added_transient_tx: log_event_added_transient_tx.clone(),
            request_hook,
            executor,
            api,
            secp_ctx: Secp256k1::new(),
            root_secret,
            task_group,
            operation_log: OperationLog::new(db.clone()),
            client_recovery_progress_receiver,
            meta_service: self.meta_service,
            connector,
        });
        client_inner
            .task_group
            .spawn_cancellable("MetaService::update_continuously", {
                let client_inner = client_inner.clone();
                async move {
                    client_inner
                        .meta_service
                        .update_continuously(&client_inner)
                        .await;
                }
            });

        client_inner.task_group.spawn_cancellable(
            "update-api-announcements",
            run_api_announcement_sync(client_inner.clone()),
        );

        client_inner.task_group.spawn_cancellable(
            "event log ordering task",
            run_event_log_ordering_task(
                db.clone(),
                log_ordering_wakeup_rx,
                log_event_added_tx,
                log_event_added_transient_tx,
            ),
        );
        let client_iface = std::sync::Arc::<Client>::downgrade(&client_inner);

        let client_arc = ClientHandle::new(client_inner);

        for (_, _, module) in client_arc.modules.iter_modules() {
            module.start().await;
        }

        final_client.set(client_iface.clone());

        if !module_recoveries.is_empty() {
            client_arc.spawn_module_recoveries_task(
                client_recovery_progress_sender,
                module_recoveries,
                module_recovery_progress_receivers,
            );
        }

        Ok(client_arc)
    }

    async fn load_init_state(db: &Database) -> InitState {
        let mut dbtx = db.begin_transaction_nc().await;
        dbtx.get_value(&ClientInitStateKey)
            .await
            .unwrap_or_else(|| {
                // could be turned in a hard error in the future, but for now
                // no need to break backward compat.
                warn!(
                    target: LOG_CLIENT,
                    "Client missing ClientRequiresRecovery: assuming complete"
                );
                db::InitState::Complete(db::InitModeComplete::Fresh)
            })
    }

    fn decoders(&self, config: &ClientConfig) -> ModuleDecoderRegistry {
        let mut decoders = client_decoders(
            &self.module_inits,
            config
                .modules
                .iter()
                .map(|(module_instance, module_config)| (*module_instance, module_config.kind())),
        );

        decoders.register_module(
            TRANSACTION_SUBMISSION_MODULE_INSTANCE,
            ModuleKind::from_static_str("tx_submission"),
            tx_submission_sm_decoder(),
        );

        decoders
    }

    fn config_decoded(
        config: &ClientConfig,
        decoders: &ModuleDecoderRegistry,
    ) -> Result<ClientConfig, fedimint_core::encoding::DecodeError> {
        config.clone().redecode_raw(decoders)
    }

    /// Re-derive client's `root_secret` using the federation ID. This
    /// eliminates the possibility of having the same client `root_secret`
    /// across multiple federations.
    fn federation_root_secret(
        root_secret: &DerivableSecret,
        config: &ClientConfig,
    ) -> DerivableSecret {
        root_secret.federation_key(&config.global.calculate_federation_id())
    }

    /// Register to receiver all new transient (unpersisted) events
    pub fn get_event_log_transient_receiver(&self) -> broadcast::Receiver<EventLogEntry> {
        self.log_event_added_transient_tx.subscribe()
    }
}

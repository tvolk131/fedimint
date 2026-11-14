use fedimint_core::PeerId;
use fedimint_core::config::TypedServerModuleConfig;
use fedimint_core::db::{DatabaseVersion, get_current_database_version};
use fedimint_core::module::ModuleConsensusVersion;
use fedimint_server_core::ServerModuleInit;
use fedimint_simplicity_common::MODULE_CONSENSUS_VERSION;

use crate::{SimplicityInit, config, load_config};

#[test]
fn fresh_database_baseline_has_no_prototype_migrations() {
    let migrations = SimplicityInit.get_database_migrations();
    assert!(migrations.is_empty());
    assert_eq!(
        get_current_database_version(&migrations),
        DatabaseVersion(0)
    );
}

#[test]
fn supported_configuration_loads_and_exports_client_config() {
    let peer = PeerId::from(0);
    let config = config().to_erased();
    assert_eq!(config.consensus.version, MODULE_CONSENSUS_VERSION);
    load_config(&config).unwrap();
    SimplicityInit.get_client_config(&config.consensus).unwrap();
    SimplicityInit.validate_config(&peer, config).unwrap();
}

#[test]
fn incompatible_versions_fail_before_decoding_the_payload() {
    for version in [
        ModuleConsensusVersion::new(0, 0),
        ModuleConsensusVersion::new(0, 2),
        ModuleConsensusVersion::new(0, 3),
        ModuleConsensusVersion::new(1, 0),
    ] {
        for valid_payload in [true, false] {
            let peer = PeerId::from(0);
            let mut config = config().to_erased();
            config.consensus.version = version;
            if !valid_payload {
                // The unit payload encodes to no bytes; any byte is invalid.
                config.consensus.config.push(0);
            }
            for result in [
                load_config(&config).map(|_| ()),
                SimplicityInit
                    .get_client_config(&config.consensus)
                    .map(|_| ()),
                SimplicityInit.validate_config(&peer, config),
            ] {
                let error = result.unwrap_err().to_string();
                assert!(error.contains("unsupported Simplicity module consensus version"));
                assert!(error.contains(&version.to_string()));
                assert!(error.contains(&MODULE_CONSENSUS_VERSION.to_string()));
            }
        }
    }
}

#[test]
fn version_guard_does_not_bypass_payload_validation() {
    let peer = PeerId::from(0);
    let mut invalid = config().to_erased();
    // The unit payload encodes to no bytes; trailing bytes are malformed.
    invalid.consensus.config.push(0);
    assert!(load_config(&invalid).is_err());
    assert!(
        SimplicityInit
            .get_client_config(&invalid.consensus)
            .is_err()
    );
    assert!(SimplicityInit.validate_config(&peer, invalid).is_err());
}

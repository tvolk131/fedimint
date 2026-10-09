//! Activation versions are distinct from immutable contract execution versions.
use fedimint_core::module::ModuleConsensusVersion;

use crate::{ContractError, EXECUTION_VERSION, MODULE_CONSENSUS_VERSION, assets};

/// Maximum consensus rules implemented by this binary. Installing a binary
/// changes support, not the federation's active rules or original config.
pub const SUPPORTED_CONSENSUS_VERSION: ModuleConsensusVersion = MODULE_CONSENSUS_VERSION;
pub const ACTIVE_CONSENSUS_VERSION_ENDPOINT: &str = "active_consensus_version";
pub const SUPPORTED_CONSENSUS_VERSION_ENDPOINT: &str = "supported_consensus_version";

/// Extend this table when adding an execution environment; never change the
/// meaning, permitted jets or costs of an existing execution version.
pub fn required_consensus_version(execution: u32) -> Result<ModuleConsensusVersion, ContractError> {
    match execution {
        EXECUTION_VERSION | assets::ASSET_VERSION => Ok(MODULE_CONSENSUS_VERSION),
        _ => Err(ContractError::Version),
    }
}

pub fn check_execution_version(
    execution: u32,
    active: ModuleConsensusVersion,
) -> Result<(), ContractError> {
    if required_consensus_version(execution)? > active {
        return Err(ContractError::Version);
    }
    Ok(())
}

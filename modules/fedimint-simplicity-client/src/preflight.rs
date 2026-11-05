//! Local checks of an exact candidate against caller-supplied observations.
//!
//! This module performs no I/O, signing, pruning, funding or submission. It
//! never establishes liveness or freshness: separate point queries are not an
//! atomic snapshot, and even authenticated observations can become stale.
use std::collections::{BTreeMap, BTreeSet};

use bitcoin::hashes::Hash as _;
use fedimint_core::config::FederationId;
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::module::ModuleConsensusVersion;
use fedimint_core::secp256k1::{Message, SECP256K1};
use fedimint_core::transaction::{Transaction, TransactionSignature};
use serde::Serialize;

use crate::common::assets::{self, AssetActions, accounting};
use crate::common::consensus::{SUPPORTED_CONSENSUS_VERSION, check_execution_version};
use crate::common::{self, ContractError, ContractInput, ContractOutput, resources, runtime};
use crate::pruning::PruningSnapshot;

#[cfg(test)]
mod tests;

/// Reports contain only fixed diagnostic text, indices, clocks and amounts.
/// No transaction, outpoint, policy, recovery annotation or witness is echoed.
#[derive(Debug, Serialize)]
pub struct Report {
    pub observations: Vec<Observation>,
    pub checks: Vec<Check>,
    pub resources: Option<Resources>,
    /// Exact Simplicity fees when resource checks passed. Foreign-module fees
    /// and funding/change selection are not estimated here.
    pub simplicity_fees_msat: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct Observation {
    pub module_id: ModuleInstanceId,
    pub consensus_version: ModuleConsensusVersion,
    pub session_index: u64,
    pub block_count: u64,
}

#[derive(Debug, Serialize)]
pub struct Resources {
    pub milliweight: u32,
    pub milliweight_limit: u32,
    pub redemption_bytes: usize,
    pub redemption_bytes_limit: usize,
}

#[derive(Debug, Serialize)]
pub struct Check {
    pub name: &'static str,
    pub module_id: Option<ModuleInstanceId>,
    /// Absolute outer transaction input index, not module-local index.
    pub input_index: Option<usize>,
    pub outcome: Outcome,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Outcome {
    Passed,
    Failed { code: &'static str, message: String },
    NotChecked { reason: &'static str },
}

impl Report {
    /// False means no checked condition failed, not that submission is safe or
    /// will succeed. Inspect `not_checked` entries and observation provenance.
    pub fn has_failures(&self) -> bool {
        self.checks
            .iter()
            .any(|check| matches!(check.outcome, Outcome::Failed { .. }))
    }

    fn record(
        &mut self,
        name: &'static str,
        module_id: Option<ModuleInstanceId>,
        input_index: Option<usize>,
        outcome: Outcome,
    ) {
        self.checks.push(Check {
            name,
            module_id,
            input_index,
            outcome,
        });
    }
}

impl From<Result<(), ContractError>> for Outcome {
    fn from(result: Result<(), ContractError>) -> Self {
        match result {
            Ok(()) => Self::Passed,
            Err(error) => Self::Failed {
                code: match error {
                    ContractError::MissingContext => "missing_context",
                    ContractError::Version => "unsupported_version",
                    ContractError::UnknownContract => "unknown_or_duplicate_contract",
                    ContractError::DuplicateOutput => "duplicate_output",
                    ContractError::Context => "invalid_context",
                    ContractError::Limit => "resource_limit",
                    ContractError::Program => "invalid_program_or_witness",
                    ContractError::Commitment => "commitment_mismatch",
                    ContractError::Rejected => "program_rejected",
                    ContractError::Assets => "invalid_asset_transition",
                    ContractError::NamespaceUsed => "namespace_used",
                    ContractError::CreationSignature => "invalid_creation_signature",
                },
                message: error.to_string(),
            },
        }
    }
}

/// Evaluate supplied bytes without modifying the transaction. Snapshots must
/// identify every consumed contract in each instance; a missing record means
/// missing information, not proof that the contract is spent. The caller owns
/// provenance/collection timestamps; default or fabricated snapshots do not
/// become authenticated merely by passing them to this function.
///
/// Resource limits cover all typed Simplicity instances in the transaction.
/// Decode each known instance with `SimplicityCommonInit` before calling this;
/// opaque/unknown modules cannot be included in these checks.
pub fn analyze(
    transaction: &Transaction,
    federation: FederationId,
    snapshots: &BTreeMap<ModuleInstanceId, PruningSnapshot>,
) -> Report {
    let mut report = Report {
        observations: vec![],
        checks: vec![],
        resources: None,
        simplicity_fees_msat: None,
    };
    for (name, reason) in [
        (
            "context_freshness",
            "Caller-supplied observations; authentication, collection times and atomicity are not established by preflight.",
        ),
        (
            "input_liveness",
            "Guardians must confirm inputs remain unspent at inclusion.",
        ),
        (
            "outer_funding",
            "Native funding, foreign-module validity and their fees require the full Fedimint validator.",
        ),
    ] {
        report.record(name, None, None, Outcome::NotChecked { reason });
    }
    let cost = resources::transaction_cost(transaction);
    report.record(
        "structure_and_resources",
        None,
        None,
        cost.as_ref().map(|_| ()).map_err(Clone::clone).into(),
    );
    let Ok(cost) = cost else {
        report.record(
            "execution",
            None,
            None,
            Outcome::NotChecked {
                reason: "Structural/resource checks failed; no programs were executed.",
            },
        );
        return report;
    };
    let inputs: Vec<_> = transaction
        .inputs
        .iter()
        .enumerate()
        .filter_map(|(index, input)| {
            input
                .as_any()
                .downcast_ref::<ContractInput>()
                .map(|contract| (index, input.module_instance_id(), contract))
        })
        .collect();
    let outputs: Vec<_> = transaction
        .outputs
        .iter()
        .enumerate()
        .filter_map(|(index, output)| {
            output
                .as_any()
                .downcast_ref::<ContractOutput>()
                .map(|contract| (index, output.module_instance_id(), contract))
        })
        .collect();
    report.resources = Some(Resources {
        milliweight: cost
            .to_string()
            .parse()
            .expect("pinned Simplicity Cost displays integer milliweight"),
        milliweight_limit: resources::MAX_TRANSACTION_MILLIWEIGHT,
        redemption_bytes: inputs
            .iter()
            .map(|(_, _, input)| input.program.len() + input.witness.len())
            .sum(),
        redemption_bytes_limit: resources::MAX_TRANSACTION_REDEMPTION_BYTES,
    });
    // Decoding already succeeded above; reuse the canonical fee implementation.
    report.simplicity_fees_msat = Some(
        inputs
            .iter()
            .map(|(_, _, input)| {
                runtime::input_fee(input)
                    .expect("immutable input passed decoding")
                    .msats
            })
            .sum::<u64>()
            + outputs
                .iter()
                .map(|(_, _, output)| common::output_fee(output).msats)
                .sum::<u64>(),
    );
    let signatures = match &transaction.signatures {
        TransactionSignature::NaiveMultisig(signatures)
            if signatures.len() == transaction.inputs.len() =>
        {
            Some(signatures)
        }
        TransactionSignature::NaiveMultisig(signatures) if signatures.is_empty() => {
            report.record(
                "outer_signature_envelope",
                None,
                None,
                Outcome::NotChecked {
                    reason: "Unsigned draft: outer signatures are absent.",
                },
            );
            None
        }
        _ => {
            report.record(
                "outer_signature_envelope",
                None,
                None,
                Outcome::Failed {
                    code: "invalid_signature_envelope",
                    message: "Unsupported signature scheme or incorrect signature count."
                        .to_owned(),
                },
            );
            None
        }
    };
    let message = Message::from_digest(transaction.tx_hash().to_byte_array());
    let modules: BTreeSet<_> = inputs
        .iter()
        .map(|(_, module, _)| *module)
        .chain(outputs.iter().map(|(_, module, _)| *module))
        .collect();
    if modules.is_empty() {
        report.record(
            "simplicity_scope",
            None,
            None,
            Outcome::NotChecked {
                reason: "No typed Simplicity inputs or outputs were supplied.",
            },
        );
    }
    for module in modules {
        if let Some(signatures) = signatures {
            for (index, _, input) in inputs.iter().filter(|(_, id, _)| *id == module) {
                let outcome = if SECP256K1
                    .verify_schnorr(
                        &signatures[*index],
                        &message,
                        &input.claim_key.x_only_public_key().0,
                    )
                    .is_ok()
                {
                    Outcome::Passed
                } else {
                    Outcome::Failed {
                        code: "invalid_outer_signature",
                        message: "Outer signature does not authorize this input's claim key."
                            .to_owned(),
                    }
                };
                report.record("outer_input_signature", Some(module), Some(*index), outcome);
            }
        }
        let Some(snapshot) = snapshots.get(&module) else {
            report.record(
                "module_context",
                Some(module),
                None,
                Outcome::NotChecked {
                    reason: "No context was supplied for this module instance.",
                },
            );
            continue;
        };
        report.observations.push(Observation {
            module_id: module,
            consensus_version: snapshot.consensus_version,
            session_index: snapshot.session_index,
            block_count: snapshot.block_count,
        });
        let version = if snapshot.consensus_version < common::MODULE_CONSENSUS_VERSION
            || snapshot.consensus_version > SUPPORTED_CONSENSUS_VERSION
        {
            Err(ContractError::Version)
        } else {
            outputs
                .iter()
                .filter(|(_, id, _)| *id == module)
                .try_for_each(|(_, _, output)| {
                    check_execution_version(output.version, snapshot.consensus_version)
                })
        };
        let supported = version.is_ok();
        report.record("active_version", Some(module), None, version.into());
        if !supported {
            continue;
        }
        let module_inputs: Vec<_> = inputs.iter().filter(|(_, id, _)| *id == module).collect();
        if module_inputs
            .iter()
            .any(|(_, _, input)| !snapshot.contracts.contains_key(&input.outpoint))
        {
            report.record("resolved_inputs", Some(module), None, Outcome::NotChecked { reason: "One or more consumed contract records are missing; execution and asset accounting were skipped." });
            continue;
        }
        let module_outputs: Vec<_> = transaction
            .outputs
            .iter()
            .map(|output| {
                (output.module_instance_id() == module)
                    .then(|| output.as_any().downcast_ref::<ContractOutput>())
                    .flatten()
            })
            .collect();
        let default_actions = AssetActions::default();
        let actions = module_outputs
            .iter()
            .flatten()
            .find_map(|output| output.actions())
            .unwrap_or(&default_actions);
        let resolved: Vec<_> = module_inputs
            .iter()
            .map(|(_, _, input)| &snapshot.contracts[&input.outpoint].output)
            .collect();
        let accounting = check_assets(
            federation,
            module,
            transaction,
            &resolved,
            &module_outputs,
            actions,
        );
        report.record("asset_accounting", Some(module), None, accounting.into());
        if !actions.creations.is_empty()
            || resolved
                .iter()
                .chain(module_outputs.iter().flatten())
                .any(|output| {
                    output.bundle().is_some_and(|bundle| {
                        !bundle.balances.is_empty() || !bundle.authorities.is_empty()
                    })
                })
        {
            report.record("asset_registry", Some(module), None, Outcome::NotChecked { reason: "Asset existence and permanent namespace-use markers require guardian ledger state." });
        }
        for (local_index, (outer_index, _, input)) in module_inputs.into_iter().enumerate() {
            let outcome = match snapshot.environment(federation, module, transaction, local_index) {
                Ok(environment) => runtime::execute(input, &environment).map(|_| ()),
                Err(error) => Err(error
                    .downcast_ref::<ContractError>()
                    .cloned()
                    .unwrap_or(ContractError::Context)),
            };
            report.record(
                "program_execution_and_pruning",
                Some(module),
                Some(*outer_index),
                outcome.into(),
            );
        }
    }
    report
}

fn check_assets(
    federation: FederationId,
    module: ModuleInstanceId,
    transaction: &Transaction,
    inputs: &[&ContractOutput],
    outputs: &[Option<&ContractOutput>],
    actions: &AssetActions,
) -> Result<(), ContractError> {
    let balances = accounting::balances(
        inputs.iter().copied(),
        outputs.iter().flatten().copied(),
        actions,
    )?;
    let mut created = BTreeSet::new();
    for creation in &actions.creations {
        let message =
            Message::from_digest(assets::signature_hash_v1(federation, module, transaction)?);
        SECP256K1
            .verify_schnorr(
                &creation.signature,
                &message,
                &creation.key.x_only_public_key().0,
            )
            .map_err(|_| ContractError::CreationSignature)?;
        for (ordinal, index) in creation.authority_outputs.iter().enumerate() {
            let id = assets::asset_id(federation, module, creation.key, ordinal as u32);
            let output = outputs
                .get(*index as usize)
                .and_then(|output| *output)
                .ok_or(ContractError::Assets)?;
            if !output
                .bundle()
                .is_some_and(|bundle| bundle.authorities.contains(&id))
                || !created.insert(id)
            {
                return Err(ContractError::Assets);
            }
        }
    }
    for (id, balance) in balances {
        if created.contains(&id) {
            balance.check_genesis()?;
        } else {
            balance.check_existing()?;
        }
    }
    Ok(())
}

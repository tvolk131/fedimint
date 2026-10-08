//! Architecture-neutral observations from the implementation, not a copy of
//! consensus.json. Fixed-reference assertions remain separate and mandatory.
use fedimint_core::encoding::Encodable;
use serde_json::json;
use simplicity::jet::Jet;

use super::*;
use crate::assets::{asset_id, namespace, signature_hash_v1};
use crate::jet::FedimintJet;
use crate::{ContractError, runtime};

pub(super) fn outcome(result: Result<Amount, ContractError>) -> serde_json::Value {
    match result {
        Ok(fee) => json!({"fee_msats": fee.msats}),
        Err(error) => json!({"error": format!("{error:?}")}),
    }
}

pub(super) fn write_report(name: &str, value: &serde_json::Value) {
    if let Some(directory) = std::env::var_os("FM_SIMPLICITY_REPORT_DIR") {
        let directory = std::path::PathBuf::from(directory);
        std::fs::create_dir_all(&directory).unwrap();
        fedimint_core::util::write_overwrite(
            directory.join(name),
            serde_json::to_vec_pretty(value).unwrap(),
        )
        .unwrap();
    }
}

#[test]
#[ignore = "cross-architecture observation report; run explicitly"]
fn consensus_observation_report() {
    let (federation, tx) = super::wire::transaction();
    let wire = json!({
        "legacy": legacy().consensus_encode_to_vec(),
        "asset": asset().consensus_encode_to_vec(),
        "actions": ContractOutput::action_output(actions()).consensus_encode_to_vec(),
        "outer_outputs": tx.outputs.consensus_encode_to_vec(),
        "namespace": namespace(federation, 4, key()),
        "asset_id_0": asset_id(federation, 4, key(), 0).0,
        "asset_id_253": asset_id(federation, 4, key(), 253).0,
        "outpoint_hash": input().outpoint.consensus_hash_sha256().to_byte_array(),
        "sighash_v0": crate::signature_hash(federation, 4, &tx).unwrap(),
        "sighash_v1": signature_hash_v1(federation, 4, &tx).unwrap(),
    });
    let jets = super::jets::cases()
        .into_iter()
        .map(|(context, source, target)| {
            let jet = FedimintJet::Context(context);
            let mut env = environment();
            let v1 = super::jets::run(context, &source, target.len(), &env);
            env.current.version = 0;
            json!({
                "name": jet.to_string(), "cmr": jet.cmr().to_byte_array(),
                "cost_milliweight": jet.cost().to_string(),
                "source_bits": source.len(), "target_bits": target.len(),
                "v1": v1, "v0": super::jets::run(context, &source, target.len(), &env),
            })
        })
        .collect::<Vec<_>>();
    let programs = fixtures()["programs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|vector| {
            let mut input = input();
            input.program = bytes(vector["program"].as_str().unwrap());
            input.witness = bytes(vector["witness"].as_str().unwrap());
            let program = runtime::decode_program(&input).unwrap();
            let mut env = environment();
            env.current.cmr = program.cmr().to_byte_array();
            let v1 = outcome(runtime::execute(&input, &env));
            env.current.version = 0;
            let v0 = outcome(runtime::execute(&input, &env));
            env.current.version = 1;
            env.current.cmr[0] ^= 1;
            json!({
                "name": vector["name"], "cmr": program.cmr().to_byte_array(),
                "cost_milliweight": program.bounds().cost.to_string(),
                "extra_cells": program.bounds().extra_cells,
                "extra_frames": program.bounds().extra_frames,
                "v1": v1, "v0": v0,
                "wrong_commitment": outcome(runtime::execute(&input, &env)),
            })
        })
        .collect::<Vec<_>>();
    #[allow(unused_mut)]
    let mut report = json!({"schema": 2, "wire": wire, "jets": jets, "programs": programs});
    #[cfg(feature = "compiler")]
    {
        report["pruning"] = super::pruning::observations();
    }
    write_report("consensus.json", &report);
}

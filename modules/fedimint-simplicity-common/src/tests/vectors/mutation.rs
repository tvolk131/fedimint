//! Opt-in seeded decoder/VM/frame campaign; not a coverage-guided fuzzer.
//! Keep the seed and iteration count with sanitizer artifacts for reproduction.
use std::sync::Arc;

use bitcoin::hashes::{HashEngine as _, sha256};
use serde_json::json;

use super::*;
use crate::{ContractError, runtime};

fn seeds() -> Vec<ContractInput> {
    #[allow(unused_mut)] // The compiler feature adds the signature seed below.
    let mut seeds = fixtures()["programs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|vector| {
            let mut input = input();
            input.program = bytes(vector["program"].as_str().unwrap());
            input.witness = bytes(vector["witness"].as_str().unwrap());
            input
        })
        .collect::<Vec<_>>();
    // Include a real signature seed when the client compiler is available.
    // This is explicitly enabled in the instrumented campaign command.
    #[cfg(feature = "compiler")]
    {
        use fedimint_core::secp256k1::{Keypair, Message, SECP256K1};

        use crate::compiler::{self, U256, Value, ValueConstructible as _};
        let key = Keypair::from_seckey_slice(SECP256K1, &[1; 32]).unwrap();
        let program = compiler::compile(
            "fn main() { jet::bip_0340_verify((param::KEY, jet::fm_sig_hash_all()), witness::SIG); }",
            compiler::arguments([("KEY", Value::u256(U256::from_byte_array(key.x_only_public_key().0.serialize())))]),
        ).unwrap();
        let signature = SECP256K1
            .sign_schnorr_no_aux_rand(&Message::from_digest(environment().signature_hash), &key);
        let satisfied = program
            .satisfy(compiler::witnesses([(
                "SIG",
                Value::byte_array(*signature.as_ref()),
            )]))
            .unwrap();
        let mut input = input();
        (input.program, input.witness) = satisfied.redeem().to_vec_with_witness();
        seeds.push(input);
    }
    seeds
}

fn next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

#[test]
#[ignore = "bounded mutation/sanitizer campaign; run explicitly"]
fn seeded_decode_execute_and_frame_campaign() {
    let iterations = std::env::var("FM_SIMPLICITY_MUTATION_ROUNDS")
        .map(|value| value.parse::<usize>().expect("integer iteration count"))
        .unwrap_or(20_000);
    assert!((100..=1_000_000).contains(&iterations));
    let seed = std::env::var("FM_SIMPLICITY_MUTATION_SEED")
        .map(|value| value.parse::<u64>().expect("decimal seed"))
        .unwrap_or(0x464d_5349_4d50_0001);
    assert_ne!(seed, 0);
    let mut random = seed;
    let programs = seeds();
    let jets = super::jets::cases();
    let mut decoded = 0;
    let mut executed = 0;
    let mut transcript = sha256::Hash::engine();
    for iteration in 0..iterations {
        if iteration % 1000 == 0 {
            eprintln!("mutation seed={seed} iteration={iteration}/{iterations}");
        }
        let mut input = programs[next(&mut random) as usize % programs.len()].clone();
        let data = if next(&mut random) & 1 == 0 {
            &mut input.program
        } else {
            &mut input.witness
        };
        match iteration % 8 {
            0 | 1 if !data.is_empty() => {
                let bit = next(&mut random) as usize % (data.len() * 8);
                data[bit / 8] ^= 1 << (bit % 8);
            }
            2 => data.truncate(next(&mut random) as usize % (data.len() + 1)),
            3 => data.push(next(&mut random) as u8),
            4 => {
                let length = next(&mut random) as usize % 512;
                *data = (0..length).map(|_| next(&mut random) as u8).collect();
            }
            5 => {
                let old = data.clone();
                data.extend_from_slice(&old);
            }
            _ => {} // Keep valid seeds reaching execution throughout the run.
        }
        let mut env = environment();
        env.session_index = next(&mut random);
        env.block_count = next(&mut random);
        env.current.amount = Amount::from_msats(next(&mut random));
        if iteration % 3 == 0 {
            env.outputs = Arc::from([]);
        }
        // Matching the mutated commitment is intentional: otherwise nearly
        // every successfully decoded mutation stops before exercising the VM.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let observation = match runtime::decode_program(&input) {
                Ok(program) => {
                    decoded += 1;
                    env.current.cmr = program.cmr().to_byte_array();
                    let result = runtime::execute_decoded(&input, &env, &program);
                    executed += usize::from(result.is_ok());
                    assert_eq!(result, runtime::execute(&input, &env));
                    env.current.cmr[0] ^= 1;
                    assert_eq!(
                        runtime::execute_decoded(&input, &env, &program),
                        Err(ContractError::Commitment)
                    );
                    json!({
                        "cmr": program.cmr().to_byte_array(),
                        "cost_milliweight": program.bounds().cost.to_string(),
                        "cells": program.bounds().extra_cells, "frames": program.bounds().extra_frames,
                        "execution": super::transcript::outcome(result),
                    })
                }
                Err(error) => json!({"decode_error": format!("{error:?}")}),
            };
            // Call every adapter across the campaign, with both valid and
            // arbitrary source bits. The helper checks cursor and guard words.
            let (jet, source, target) = &jets[iteration % jets.len()];
            let mut source = source.clone();
            if next(&mut random) & 1 == 0 {
                for bit in &mut source {
                    *bit = next(&mut random) & 1 == 1;
                }
            }
            let frame = super::jets::run(*jet, &source, target.len(), &env);
            // Commit to inputs as well as outcomes so equal summaries cannot
            // conceal architecture-dependent case generation or VM results.
            transcript.input(
                &serde_json::to_vec(&json!({
                    "iteration": iteration, "program": input.program, "witness": input.witness,
                    "session": env.session_index, "block": env.block_count,
                    "amount": env.current.amount.msats, "outputs": env.outputs.len(),
                    "vm": observation, "jet": *jet as u8, "source": source, "frame": frame,
                }))
                .unwrap(),
            );
        }));
        assert!(
            result.is_ok(),
            "seed={seed} iteration={iteration} program={:?} witness={:?}",
            input.program,
            input.witness
        );
    }
    assert!(decoded > 0 && executed > 0, "campaign never reached the VM");
    eprintln!(
        "mutation seed={seed} rounds={iterations} decoded={decoded} executed={executed} frame_calls={iterations}"
    );
    super::transcript::write_report(
        "mutation.json",
        &json!({
            "schema": 1, "seed": seed, "rounds": iterations,
            "compiler": cfg!(feature = "compiler"), "decoded": decoded, "executed": executed,
            "frame_calls": iterations, "sha256": sha256::Hash::from_engine(transcript).to_string(),
        }),
    );
}

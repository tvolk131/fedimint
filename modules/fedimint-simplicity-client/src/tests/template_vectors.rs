//! Pinned compilation result for the contract template this crate ships.
//!
//! Recovery recompiles each decrypted descriptor with the current compiler and
//! keeps an output only if its CMR and execution version match. A changed
//! template source, argument encoding or SimplicityHL revision therefore makes
//! outputs from earlier releases disappear from recovery without an error.
//! Expectations live in `tests/vectors/templates.json`; see its README.
//! Application templates pin their own vectors in the application repository.
use std::collections::BTreeMap;

use bitcoin::hex::DisplayHex as _;
use fedimint_core::secp256k1::{Keypair, SECP256K1, SecretKey, XOnlyPublicKey};
use serde::Deserialize;

use crate::ContractProgram;
use crate::descriptor::{BuiltinTemplates, ContractDescriptor, ContractTemplates as _};

const BUILTIN: [&str; 1] = ["owner"];
/// Templates that were builtin before application templates moved out of this
/// crate. Their descriptors now need the application's template set.
const APPLICATION: [&str; 2] = ["top-up-or-release", "binary-market"];

#[derive(Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pinned {
    execution_version: u32,
    cmr: String,
}

fn assert_pinned(name: &str, execution_version: u32, program: &ContractProgram) {
    let mut vectors: BTreeMap<String, Pinned> =
        serde_json::from_str(include_str!("../../tests/vectors/templates.json")).unwrap();
    let expected = vectors
        .remove(name)
        .unwrap_or_else(|| panic!("no vector for template {name} in tests/vectors/templates.json"));
    let actual = Pinned {
        execution_version,
        cmr: program.cmr().to_lower_hex_string(),
    };
    assert!(
        actual == expected,
        "template {name} no longer compiles to its pinned vector\n\
         expected: {expected:?}\n  actual: {actual:?}\n\
         Recovery keeps an output only if the recompiled CMR and execution \
         version match, so outputs created by earlier releases would be skipped \
         without an error. Ship a new template version instead of changing an \
         existing one; see tests/vectors/README.md."
    );
}

fn key(byte: u8) -> XOnlyPublicKey {
    Keypair::from_secret_key(SECP256K1, &SecretKey::from_slice(&[byte; 32]).unwrap())
        .x_only_public_key()
        .0
}

/// Mirrors a stored descriptor rather than calling the current constructors,
/// so each test keeps pinning the version it names.
fn compile_builtin(
    template: &str,
    template_version: u32,
) -> anyhow::Result<(u32, ContractProgram)> {
    let descriptor = ContractDescriptor {
        template: template.to_owned(),
        template_version,
        parameters: vec![],
        key_nonce: [0x31; 32],
        application_data: vec![],
    };
    BuiltinTemplates.compile(&descriptor, key(0x42))
}

fn assert_builtin(template: &str, template_version: u32) {
    let (execution_version, program) = compile_builtin(template, template_version).unwrap();
    assert_pinned(
        &format!("{template}/v{template_version}"),
        execution_version,
        &program,
    );
}

#[test]
fn owner_v1() {
    assert_builtin("owner", 1);
}

/// Supporting another version must add a vector next to the existing ones.
#[test]
fn builtin_templates_compile_only_pinned_versions() {
    for template in BUILTIN {
        for version in [0, 2] {
            assert!(
                compile_builtin(template, version).is_err(),
                "{template}/v{version} compiles; pin it in tests/vectors/templates.json"
            );
        }
    }
}

/// A wallet without the application's template set must not silently skip an
/// owned application output: recovery fails atomically on the unknown template.
#[test]
fn application_templates_are_not_builtin() {
    for template in APPLICATION {
        let error = compile_builtin(template, 1).unwrap_err();
        assert!(
            error.to_string().contains("unsupported contract template"),
            "{template} must be rejected as an unknown template, got: {error:#}"
        );
    }
}

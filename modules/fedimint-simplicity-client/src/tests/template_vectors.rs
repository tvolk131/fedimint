//! Pinned compilation results for every contract template in this crate.
//!
//! Recovery recompiles each decrypted descriptor with the current compiler and
//! keeps an output only if its CMR and execution version match. A changed
//! template source, argument encoding or SimplicityHL revision therefore makes
//! outputs from earlier releases disappear from recovery without an error.
//! Expectations live in `tests/vectors/templates.json`; see its README.
use std::collections::BTreeMap;

use bitcoin::hashes::{Hash as _, sha256};
use bitcoin::hex::DisplayHex as _;
use fedimint_core::Amount;
use fedimint_core::config::FederationId;
use fedimint_core::encoding::Encodable as _;
use fedimint_core::secp256k1::{Keypair, SECP256K1, SecretKey, XOnlyPublicKey};
use serde::Deserialize;

use crate::ContractProgram;
use crate::common::assets::{AssetBundle, AssetId};
use crate::descriptor::{BuiltinTemplates, ContractDescriptor, ContractTemplates as _};
use crate::exchange::{ConstantProductPool, LimitOrder, PartialLimitOrder, balances};
use crate::market::{BinaryMarket, owner_program};

const BUILTIN: [&str; 3] = ["owner", "top-up-or-release", "binary-market"];
const MODULE: u16 = 3;

#[derive(Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pinned {
    /// Only descriptor templates return a version; exchange builders do not.
    execution_version: Option<u32>,
    cmr: String,
}

fn assert_pinned(name: &str, execution_version: Option<u32>, program: &ContractProgram) {
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

fn market() -> BinaryMarket {
    BinaryMarket {
        federation: FederationId(sha256::Hash::from_byte_array([0x11; 32])),
        module: MODULE,
        yes: AssetId([0x21; 32]),
        no: AssetId([0x22; 32]),
        event: [0x23; 32],
        rules: [0x24; 32],
        oracle: key(0x41),
        resolution_start: 1_000,
        deadline: 2_000,
    }
}

/// Mirrors a stored descriptor rather than calling the current constructors,
/// so each test keeps pinning the version it names.
fn compile_builtin(
    template: &str,
    template_version: u32,
) -> anyhow::Result<(u32, ContractProgram)> {
    let parameters = match template {
        "owner" => vec![],
        "top-up-or-release" => (17u64, 21u64).consensus_encode_to_vec(),
        "binary-market" => market().consensus_encode_to_vec(),
        _ => unreachable!("unknown builtin template {template}"),
    };
    let descriptor = ContractDescriptor {
        template: template.to_owned(),
        template_version,
        parameters,
        key_nonce: [0x31; 32],
        application_data: vec![],
    };
    BuiltinTemplates.compile(&descriptor, key(0x42))
}

fn assert_builtin(template: &str, template_version: u32) {
    let (execution_version, program) = compile_builtin(template, template_version).unwrap();
    assert_pinned(
        &format!("{template}/v{template_version}"),
        Some(execution_version),
        &program,
    );
}

#[test]
fn owner_v1() {
    assert_builtin("owner", 1);
}

#[test]
fn top_up_or_release_v1() {
    assert_builtin("top-up-or-release", 1);
}

#[test]
fn binary_market_v1() {
    assert_builtin("binary-market", 1);
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

#[test]
fn limit_order() {
    let maker = key(0x43);
    let asset = AssetId([0x21; 32]);
    let (quantity, price) = (100, Amount::from_sats(40));
    for (buy, name) in [(false, "limit-order/sell"), (true, "limit-order/buy")] {
        let (amount, bundle) = if buy {
            (Amount::ZERO, balances(&[(asset, quantity)], &[]))
        } else {
            (price, AssetBundle::default())
        };
        let order = LimitOrder {
            module: MODULE,
            maker,
            asset,
            quantity,
            price,
            buy,
            close_block: 1_000,
            payment: owner_program(maker)
                .unwrap()
                .asset_output(amount, [0; 32], vec![], bundle)
                .unwrap(),
        };
        assert_pinned(name, None, &order.program().unwrap());
    }
}

#[test]
fn partial_order() {
    for (buy, name) in [(false, "partial-order/sell"), (true, "partial-order/buy")] {
        let order = PartialLimitOrder {
            module: MODULE,
            maker: key(0x43),
            asset: AssetId([0x21; 32]),
            unit_price: Amount::from_msats(333),
            buy,
            close_block: 1_000,
        };
        assert_pinned(name, None, &order.program().unwrap());
    }
}

#[test]
fn constant_product() {
    let pool = ConstantProductPool {
        market: market(),
        identity: AssetId([0x25; 32]),
        provider: key(0x44),
    };
    assert_pinned("constant-product", None, &pool.program().unwrap());
}

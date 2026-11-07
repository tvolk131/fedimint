use bitcoin::hashes::{Hash, HashEngine, sha256};
use serde_json::{Value, json};

fn sha(data: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(data).to_byte_array()
}

fn big(number: u64) -> Vec<u8> {
    match number {
        0..=252 => vec![number as u8],
        253..=65535 => [vec![253], (number as u16).to_be_bytes().to_vec()].concat(),
        65536..=4294967295 => [vec![254], (number as u32).to_be_bytes().to_vec()].concat(),
        _ => [vec![255], number.to_be_bytes().to_vec()].concat(),
    }
}

fn sequence(items: &[Vec<u8>]) -> Vec<u8> {
    [big(items.len() as u64), items.concat()].concat()
}

fn blob(data: &[u8]) -> Vec<u8> {
    [big(data.len() as u64), data.to_vec()].concat()
}

fn extension(variant: u64, data: &[u8]) -> Vec<u8> {
    [vec![1], big(variant), blob(data)].concat()
}

fn output(amount: u64, cmr: &[u8], state: &[u8], recovery: &[u8], ext: &[u8]) -> Vec<u8> {
    [
        big(1),
        big(amount),
        cmr.to_vec(),
        state.to_vec(),
        blob(recovery),
        ext.to_vec(),
    ]
    .concat()
}

fn actions(key: &[u8], signature: &[u8]) -> Vec<u8> {
    let creation = [key.to_vec(), sequence(&[big(1)]), signature.to_vec()].concat();
    let payload = [
        sequence(&[creation]),
        sequence(&[[vec![0x44; 32], big(10)].concat()]),
        sequence(&[[vec![0x55; 32], big(11)].concat()]),
    ]
    .concat();
    output(0, &[0; 32], &[0; 32], &[], &extension(1, &payload))
}

fn outputs(native: &[u8], asset: &[u8], key: &[u8], signature: &[u8]) -> Vec<u8> {
    sequence(&[
        [big(4), blob(native)].concat(),
        [big(4), blob(asset)].concat(),
        [big(7), blob(&actions(key, signature))].concat(),
    ])
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut encoded, byte| {
        write!(encoded, "{byte:02x}").expect("strings accept writes");
        encoded
    })
}

fn compress(state: [u8; 32], block: [u8; 64]) -> [u8; 32] {
    let mut engine = sha256::HashEngine::from_midstate(sha256::Midstate::from_byte_array(state), 0);
    engine.input(&block);
    engine.midstate().to_byte_array()
}

fn tagged(name: &str) -> [u8; 32] {
    let tag = sha(format!("Simplicity\u{1f}Commitment\u{1f}{name}").as_bytes());
    let initial = sha256::Hash::engine().midstate().to_byte_array();
    compress(
        initial,
        [tag, tag].concat().try_into().expect("one SHA block"),
    )
}

fn comp(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    compress(
        tagged("comp"),
        [left, right].concat().try_into().expect("one SHA block"),
    )
}

fn pack(bits: &str) -> String {
    let mut packed = vec![0u8; bits.len().div_ceil(8)];
    for (index, bit) in bits.bytes().enumerate() {
        assert!(matches!(bit, b'0' | b'1'));
        packed[index / 8] |= (bit - b'0') << (7 - index % 8);
    }
    hex(&packed)
}

fn main() {
    let mut padded = [0u8; 64];
    padded[..4].copy_from_slice(b"abc\x80");
    padded[63] = 24;
    assert_eq!(
        compress(sha256::Hash::engine().midstate().to_byte_array(), padded),
        sha(b"abc")
    );
    let key = [
        2, 121, 190, 102, 126, 249, 220, 187, 172, 85, 160, 98, 149, 206, 135, 11, 7, 2, 155, 252,
        219, 45, 206, 40, 217, 89, 242, 129, 91, 22, 248, 23, 152,
    ];
    let native = output(
        1000,
        &[0x11; 32],
        &[0x22; 32],
        &[0xde, 0xad],
        &extension(0, &[0, 0]),
    );
    let bundle = [
        sequence(&[
            [vec![0x44; 32], big(253)].concat(),
            [vec![0x55; 32], big(65536)].concat(),
        ]),
        sequence(&[vec![0x44; 32], vec![0x55; 32]]),
    ]
    .concat();
    let asset = output(
        65536,
        &[0x11; 32],
        &[0x22; 32],
        &[0xde, 0xad],
        &extension(0, &bundle),
    );
    let point = [vec![0x33; 32], big(253)].concat();
    let spends = sequence(&[[point.clone(), key.to_vec()].concat()]);
    let namespace = sha(&[
        blob(b"fedimint/simplicity/namespace/v1"),
        vec![0x99; 32],
        big(4),
        key.to_vec(),
    ]
    .concat());
    let wire = json!({
        "native_output": hex(&native),
        "asset_output": hex(&asset),
        "actions_output": hex(&actions(&key, &[0x66; 64])),
        "outputs": hex(&outputs(&native, &asset, &key, &[0x66; 64])),
        "outpoint_hash": hex(&sha(&point)),
        "namespace": hex(&namespace),
        "asset_id_0": hex(&sha(&[blob(b"fedimint/simplicity/asset/v1"), namespace.to_vec(), big(0)].concat())),
        "asset_id_253": hex(&sha(&[blob(b"fedimint/simplicity/asset/v1"), namespace.to_vec(), big(253)].concat())),
        "sighash_v1": hex(&sha(&[blob(b"fedimint/simplicity/intent/v1"), vec![0x99; 32], big(4), spends, vec![0x88; 8], outputs(&native, &asset, &key, &[0; 64])].concat())),
    });
    let specifications = [
        ("sig_hash_all", 0, 256),
        ("session_index", 0, 64),
        ("block_count", 0, 64),
        ("current_amount", 0, 64),
        ("current_cmr", 0, 256),
        ("current_state", 0, 256),
        ("current_index", 0, 32),
        ("input_count", 0, 32),
        ("output_count", 0, 32),
        ("output_amount", 32, 64),
        ("output_cmr", 32, 256),
        ("output_state", 32, 256),
        ("output_hash", 32, 256),
        ("output_module", 32, 16),
        ("creation_session", 0, 64),
        ("creation_block_count", 0, 64),
        ("input_amount", 32, 64),
        ("input_cmr", 32, 256),
        ("input_state", 32, 256),
        ("input_outpoint_hash", 32, 256),
        ("input_asset_quantity", 288, 64),
        ("output_asset_quantity", 288, 64),
        ("input_authority", 288, 1),
        ("output_authority", 288, 1),
        ("issued_quantity", 256, 64),
        ("burned_quantity", 256, 64),
        ("input_asset_count", 32, 32),
        ("output_asset_count", 32, 32),
        ("input_authority_count", 32, 32),
        ("output_authority_count", 32, 32),
        ("input_asset_id", 64, 256),
        ("output_asset_id", 64, 256),
        ("input_authority_id", 64, 256),
        ("output_authority_id", 64, 256),
        ("input_version", 32, 32),
        ("output_version", 32, 32),
    ];
    let jets = specifications
        .iter()
        .enumerate()
        .map(|(opcode, (name, source, target))| {
            json!({
                "name": format!("fm_{name}"),
                "encoding": hex(&(((256 + opcode) << 7) as u16).to_be_bytes()),
                "source": source, "target": target,
                "cmr": hex(&sha(format!("fedimint/simplicity/jet/v0/fm_{name}").as_bytes())),
                "cost": 1000,
            })
        })
        .collect::<Vec<Value>>();
    let unit = tagged("unit");
    let session = sha(b"fedimint/simplicity/jet/v0/fm_session_index");
    let issuance = sha(b"fedimint/simplicity/jet/v0/fm_issued_quantity");
    let programs = json!([
        {"name": "unit", "program": "24", "witness": "", "cmr": hex(&unit), "cost": 100, "cells": 0, "frames": 0, "fee": 102},
        {"name": "session", "program": pack("1011110000000101001000001000"), "witness": "", "cmr": hex(&comp(session, unit)), "cost": 1364, "cells": 64, "frames": 1, "fee": 106},
        {"name": "issuance", "program": pack(concat!("110001", "0111", "11100011000", "00000", "100", "0", "01001", "00000", "100", "0")), "witness": hex(&[0x44; 32]), "cmr": hex(&comp(comp(tagged("witness"), issuance), unit)), "cost": 2076, "cells": 576, "frames": 2, "fee": 141},
    ]);
    let mut reference = json!({"wire": wire, "jets": jets, "programs": programs});
    reference.sort_all_objects();
    println!(
        "{}",
        serde_json::to_string_pretty(&reference).expect("fixed reference serializes")
    );
}

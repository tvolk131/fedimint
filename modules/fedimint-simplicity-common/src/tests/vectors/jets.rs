use simplicity::jet::{Jet, JetEnvironment};
use simplicity::{BitIter, BitWriter, Cost};
use simplicity_sys::c_jets::c_frame::uword_width;
use simplicity_sys::c_jets::frame_ffi::{CFrameItem, c_readBit, c_writeBit};
use simplicity_sys::ffi::UWORD;

use super::*;
use crate::jet::{ContextJet, FedimintJet};

fn bits(bytes: &[u8]) -> Vec<bool> {
    bytes
        .iter()
        .flat_map(|byte| (0..8).rev().map(move |i| byte & (1 << i) != 0))
        .collect()
}

fn index(i: u32) -> Vec<bool> {
    bits(&i.to_be_bytes())
}

fn indexed_id(i: u32, id: u8) -> Vec<bool> {
    let mut result = index(i);
    result.extend(bits(&[id; 32]));
    result
}

fn indexed_entry(i: u32, entry: u32) -> Vec<bool> {
    let mut result = index(i);
    result.extend(index(entry));
    result
}

/// Exercise the actual FFI entry point with a guarded destination. The C frame
/// writer may clear bits ahead of its cursor within a machine word, so assert
/// the exact cursor movement and *outside* guard words, not unused padding
/// bits.
fn run(jet: ContextJet, source: &[bool], target: usize, env: &Environment) -> Option<Vec<bool>> {
    let jet = FedimintJet::Context(jet);
    assert_eq!(jet.source_ty().to_final().bit_width(), source.len());
    assert_eq!(jet.target_ty().to_final().bit_width(), target);
    const GUARD: usize = 64;
    let src_width = source.len() + GUARD;
    let dst_width = target + GUARD;
    let src_words = uword_width(src_width);
    let dst_words = uword_width(dst_width);
    let mut src = vec![UWORD::MAX; src_words + 2];
    let mut dst = vec![UWORD::MAX; dst_words + 2];
    // SAFETY: both frame ranges are fully backed by aligned UWORD allocations,
    // with an extra word on each side. CFrame's lengths are measured in bits.
    // Read/write pointers designate the beginning/one-past-end of those ranges.
    unsafe {
        let mut writer = CFrameItem::new_write(src_width, src.as_mut_ptr().add(1 + src_words));
        for bit in source {
            c_writeBit(&mut writer, *bit);
        }
        for i in 0..GUARD {
            c_writeBit(&mut writer, i % 2 == 0);
        }
        let reader = CFrameItem::new_read(src_width, src.as_ptr().add(1));
        let mut writer = CFrameItem::new_write(dst_width, dst.as_mut_ptr().add(1 + dst_words));
        let success = Environment::c_jet_ptr(&jet)(&mut writer, reader, env);
        assert_eq!(writer.len, if success { GUARD } else { dst_width }, "{jet}");
        assert_eq!(
            [src[0], src[src_words + 1], dst[0], dst[dst_words + 1]],
            [UWORD::MAX; 4]
        );
        if !success {
            return None;
        }
        let mut reader = CFrameItem::new_read(dst_width, dst.as_ptr().add(1));
        Some((0..target).map(|_| c_readBit(&mut reader)).collect())
    }
}

fn cases() -> Vec<(ContextJet, Vec<bool>, Vec<bool>)> {
    use ContextJet::*;
    vec![
        (SigHashAll, vec![], bits(&[0xab; 32])),
        (
            SessionIndex,
            vec![],
            bits(&0x0123456789abcdefu64.to_be_bytes()),
        ),
        (
            BlockCount,
            vec![],
            bits(&0x1020304050607080u64.to_be_bytes()),
        ),
        (CurrentAmount, vec![], bits(&65536u64.to_be_bytes())),
        (CurrentCmr, vec![], bits(&[0x11; 32])),
        (CurrentState, vec![], bits(&[0x22; 32])),
        (CurrentIndex, vec![], index(1)),
        (InputCount, vec![], index(2)),
        (OutputCount, vec![], index(4)),
        (OutputAmount, index(0), bits(&65536u64.to_be_bytes())),
        (OutputCmr, index(0), bits(&[0x11; 32])),
        (OutputState, index(0), bits(&[0x22; 32])),
        (OutputHash, index(0), bits(&[0xaa; 32])),
        (OutputModule, index(0), bits(&4u16.to_be_bytes())),
        (
            CreationSession,
            vec![],
            bits(&0x8877665544332211u64.to_be_bytes()),
        ),
        (
            CreationBlockCount,
            vec![],
            bits(&0xffeeddccbbaa0099u64.to_be_bytes()),
        ),
        (InputAmount, index(0), bits(&65536u64.to_be_bytes())),
        (InputCmr, index(0), bits(&[0x11; 32])),
        (InputState, index(0), bits(&[0x22; 32])),
        (
            InputOutpoint,
            index(0),
            bits(&bytes(
                fixtures()["wire"]["outpoint_hash"].as_str().unwrap(),
            )),
        ),
        (
            InputAssetQuantity,
            indexed_id(0, 0x44),
            bits(&253u64.to_be_bytes()),
        ),
        (
            OutputAssetQuantity,
            indexed_id(0, 0x44),
            bits(&253u64.to_be_bytes()),
        ),
        (InputAuthority, indexed_id(0, 0x44), vec![true]),
        (OutputAuthority, indexed_id(0, 0x44), vec![true]),
        (
            IssuedQuantity,
            bits(&[0x44; 32]),
            bits(&10u64.to_be_bytes()),
        ),
        (
            BurnedQuantity,
            bits(&[0x55; 32]),
            bits(&11u64.to_be_bytes()),
        ),
        (InputAssetCount, index(0), index(2)),
        (OutputAssetCount, index(0), index(2)),
        (InputAuthorityCount, index(0), index(2)),
        (OutputAuthorityCount, index(0), index(2)),
        (InputAssetId, indexed_entry(0, 1), bits(&[0x55; 32])),
        (OutputAssetId, indexed_entry(0, 1), bits(&[0x55; 32])),
        (InputAuthorityId, indexed_entry(0, 1), bits(&[0x55; 32])),
        (OutputAuthorityId, indexed_entry(0, 1), bits(&[0x55; 32])),
        (InputVersion, index(0), index(1)),
        (OutputVersion, index(0), index(1)),
    ]
}

#[test]
fn every_context_jet_matches_fixed_encoding_identity_type_cost_and_ffi_result() {
    let fixture = fixtures();
    let vectors = fixture["jets"].as_array().unwrap();
    assert_eq!(vectors.len(), ContextJet::ALL.len());
    let cases = cases();
    assert_eq!(cases.len(), vectors.len());
    for (opcode, ((context, source, expected), vector)) in cases.iter().zip(vectors).enumerate() {
        let jet = FedimintJet::Context(*context);
        assert_eq!(ContextJet::ALL[opcode], *context);
        assert_eq!(*context as usize, opcode);
        assert_eq!(jet.to_string(), vector["name"].as_str().unwrap());
        assert_eq!(
            FedimintJet::parse(vector["name"].as_str().unwrap()).unwrap(),
            jet
        );
        assert_eq!(
            jet.cmr().to_byte_array().as_slice(),
            bytes(vector["cmr"].as_str().unwrap())
        );
        assert_eq!(
            jet.cost(),
            Cost::from_milliweight(vector["cost"].as_u64().unwrap() as u32)
        );
        assert_eq!(source.len(), vector["source"].as_u64().unwrap() as usize);
        assert_eq!(expected.len(), vector["target"].as_u64().unwrap() as usize);
        let encoded = bytes(vector["encoding"].as_str().unwrap());
        let mut decoded = BitIter::from(encoded.iter().copied());
        assert_eq!(FedimintJet::decode(&mut decoded).unwrap(), jet);
        assert_eq!(decoded.n_total_read(), 9);
        let mut written = vec![];
        let mut writer = BitWriter::new(&mut written as &mut dyn std::io::Write);
        assert_eq!(jet.encode(&mut writer).unwrap(), 9);
        writer.flush_all().unwrap();
        assert_eq!(written, encoded);
        assert!(FedimintJet::decode(&mut BitIter::from(encoded[..1].iter().copied())).is_err());
        assert_eq!(
            run(*context, source, expected.len(), &environment()),
            Some(expected.clone()),
            "{jet}"
        );
    }
    for opcode in 36u16..=255 {
        let encoded = ((256 + opcode) << 7).to_be_bytes();
        assert!(FedimintJet::decode(&mut BitIter::from(encoded.into_iter())).is_err());
    }
}

#[test]
fn indexed_jets_reject_missing_foreign_and_action_outputs_and_respect_version_gates() {
    use ContextJet::*;
    for (jet, source, expected) in cases() {
        let mut env = environment();
        if jet as u8 >= 16 {
            env.current.version = 0;
            assert_eq!(
                run(jet, &source, expected.len(), &env),
                None,
                "legacy {jet:?}"
            );
            env.current.version = 1;
        }
        if source.len() >= 32 && !matches!(jet, IssuedQuantity | BurnedQuantity) {
            // Check both the first missing index and the largest representable
            // index. The source suffix remains valid for asset/entry lookups.
            for missing in [4, u32::MAX] {
                let mut invalid = index(missing);
                invalid.extend_from_slice(&source[32..]);
                assert_eq!(run(jet, &invalid, expected.len(), &env), None, "{jet:?}");
            }
        }
        if matches!(
            jet,
            OutputAmount
                | OutputCmr
                | OutputState
                | OutputAssetQuantity
                | OutputAuthority
                | OutputAssetCount
                | OutputAuthorityCount
                | OutputAssetId
                | OutputAuthorityId
                | OutputVersion
        ) {
            let mut foreign = index(1);
            foreign.extend_from_slice(&source[32..]);
            assert_eq!(
                run(jet, &foreign, expected.len(), &env),
                None,
                "foreign {jet:?}"
            );
            if jet as u8 >= 16 {
                let mut action = index(3);
                action.extend_from_slice(&source[32..]);
                assert_eq!(
                    run(jet, &action, expected.len(), &env),
                    None,
                    "action {jet:?}"
                );
            }
        }
    }
    let env = environment();
    assert_eq!(
        run(OutputHash, &index(1), 256, &env),
        Some(bits(&[0xbb; 32]))
    );
    assert_eq!(
        run(OutputModule, &index(1), 16, &env),
        Some(bits(&0x1234u16.to_be_bytes()))
    );
}

#[test]
fn asset_lookups_distinguish_absent_assets_entries_and_legacy_bundles() {
    use ContextJet::*;
    let env = environment();
    for jet in [InputAssetQuantity, OutputAssetQuantity] {
        assert_eq!(
            run(jet, &indexed_id(0, 0x99), 64, &env),
            Some(vec![false; 64])
        );
        assert_eq!(
            run(jet, &indexed_id(0, 0x55), 64, &env),
            Some(bits(&65536u64.to_be_bytes()))
        );
    }
    for jet in [InputAuthority, OutputAuthority] {
        assert_eq!(run(jet, &indexed_id(0, 0x99), 1, &env), Some(vec![false]));
        assert_eq!(run(jet, &indexed_id(0, 0x55), 1, &env), Some(vec![true]));
    }
    for jet in [IssuedQuantity, BurnedQuantity] {
        assert_eq!(
            run(jet, &bits(&[0x99; 32]), 64, &env),
            Some(vec![false; 64])
        );
    }
    for jet in [
        InputAssetId,
        OutputAssetId,
        InputAuthorityId,
        OutputAuthorityId,
    ] {
        assert_eq!(
            run(jet, &indexed_entry(0, 0), 256, &env),
            Some(bits(&[0x44; 32]))
        );
        for entry in [2, u32::MAX] {
            assert_eq!(run(jet, &indexed_entry(0, entry), 256, &env), None);
        }
    }
    for (jet, i) in [
        (InputAssetCount, 1),
        (InputAuthorityCount, 1),
        (InputVersion, 1),
        (OutputAssetCount, 2),
        (OutputAuthorityCount, 2),
        (OutputVersion, 2),
    ] {
        assert_eq!(run(jet, &index(i), 32, &env), Some(index(0)));
    }
    for (quantity, authority, entry, i) in [
        (InputAssetQuantity, InputAuthority, InputAssetId, 1),
        (OutputAssetQuantity, OutputAuthority, OutputAssetId, 2),
    ] {
        assert_eq!(
            run(quantity, &indexed_id(i, 0x44), 64, &env),
            Some(vec![false; 64])
        );
        assert_eq!(
            run(authority, &indexed_id(i, 0x44), 1, &env),
            Some(vec![false])
        );
        assert_eq!(run(entry, &indexed_entry(i, 0), 256, &env), None);
    }
}

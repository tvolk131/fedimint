//! Version-zero jet encoding: a family bit, followed by the upstream Core
//! encoding (0) or an eight-bit Fedimint operation number (1).
//! The deliberately small Core allowlist is part of this experimental version.

use std::io::Write;

use bitcoin::hashes::{Hash, sha256};
use simplicity::jet::type_name::TypeName;
use simplicity::jet::{Core, CoreEnv, Jet, JetEnvironment};
use simplicity::{BitIter, BitWriter, Cmr, Cost, decode};
use simplicity_sys::c_jets::frame_ffi::{CFrameItem, c_readBit, c_writeBit};

use crate::runtime::Environment;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FedimintJet {
    Core(Core),
    Context(ContextJet),
}

macro_rules! context_jets {
    ($($variant:ident = $index:literal, $name:literal, $source:literal, $target:literal;)+) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(u8)]
        pub enum ContextJet { $($variant = $index,)+ }

        impl ContextJet {
            pub const ALL: &'static [Self] = &[$(Self::$variant,)+];
            pub fn name(self) -> &'static str { match self { $(Self::$variant => $name,)+ } }
            fn source(self) -> TypeName { match self { $(Self::$variant => TypeName($source),)+ } }
            fn target(self) -> TypeName { match self { $(Self::$variant => TypeName($target),)+ } }
            fn from_index(index: u8) -> Option<Self> { match index { $($index => Some(Self::$variant),)+ _ => None } }
        }
    };
}

context_jets! {
    SigHashAll = 0, "fm_sig_hash_all", b"1", b"h";
    SessionIndex = 1, "fm_session_index", b"1", b"l";
    BlockCount = 2, "fm_block_count", b"1", b"l";
    CurrentAmount = 3, "fm_current_amount", b"1", b"l";
    CurrentCmr = 4, "fm_current_cmr", b"1", b"h";
    CurrentState = 5, "fm_current_state", b"1", b"h";
    CurrentIndex = 6, "fm_current_index", b"1", b"i";
    InputCount = 7, "fm_input_count", b"1", b"i";
    OutputCount = 8, "fm_output_count", b"1", b"i";
    OutputAmount = 9, "fm_output_amount", b"i", b"l";
    OutputCmr = 10, "fm_output_cmr", b"i", b"h";
    OutputState = 11, "fm_output_state", b"i", b"h";
    OutputHash = 12, "fm_output_hash", b"i", b"h";
    OutputModule = 13, "fm_output_module", b"i", b"s";
    CreationSession = 14, "fm_creation_session", b"1", b"l";
    CreationBlockCount = 15, "fm_creation_block_count", b"1", b"l";
    InputAmount = 16, "fm_input_amount", b"i", b"l";
    InputCmr = 17, "fm_input_cmr", b"i", b"h";
    InputState = 18, "fm_input_state", b"i", b"h";
    InputOutpoint = 19, "fm_input_outpoint_hash", b"i", b"h";
    InputAssetQuantity = 20, "fm_input_asset_quantity", b"*ih", b"l";
    OutputAssetQuantity = 21, "fm_output_asset_quantity", b"*ih", b"l";
    InputAuthority = 22, "fm_input_authority", b"*ih", b"2";
    OutputAuthority = 23, "fm_output_authority", b"*ih", b"2";
    IssuedQuantity = 24, "fm_issued_quantity", b"h", b"l";
    BurnedQuantity = 25, "fm_burned_quantity", b"h", b"l";
    InputAssetCount = 26, "fm_input_asset_count", b"i", b"i";
    OutputAssetCount = 27, "fm_output_asset_count", b"i", b"i";
    InputAuthorityCount = 28, "fm_input_authority_count", b"i", b"i";
    OutputAuthorityCount = 29, "fm_output_authority_count", b"i", b"i";
    InputAssetId = 30, "fm_input_asset_id", b"*ii", b"h";
    OutputAssetId = 31, "fm_output_asset_id", b"*ii", b"h";
    InputAuthorityId = 32, "fm_input_authority_id", b"*ii", b"h";
    OutputAuthorityId = 33, "fm_output_authority_id", b"*ii", b"h";
    InputVersion = 34, "fm_input_version", b"i", b"i";
    OutputVersion = 35, "fm_output_version", b"i", b"i";

}

macro_rules! core_jets {
    ($($variant:ident),+ $(,)?) => {
        pub const CORE_JETS: &[Core] = &[$(Core::$variant,)+];
        fn core_ptr(jet: Core) -> fn(&mut CFrameItem, CFrameItem, &Environment) -> bool {
            match jet {
                $(Core::$variant => |dst, src, _| CoreEnv::c_jet_ptr(&Core::$variant)(dst, src, &()),)+
                // Unsupported jets cannot be decoded or produced by our compiler.
                _ => |_, _, _| false,
            }
        }
    };
}
core_jets!(
    Verify,
    Eq8,
    Eq16,
    Eq32,
    Eq64,
    Eq256,
    Le32,
    Le64,
    Lt32,
    Lt64,
    Add32,
    Add64,
    Subtract32,
    Subtract64,
    Bip0340Verify,
    Sha256Iv,
    Sha256Block,
    Multiply64
);

impl std::fmt::Display for FedimintJet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Core(core) => core.fmt(f),
            Self::Context(jet) => f.write_str(jet.name()),
        }
    }
}

impl Jet for FedimintJet {
    fn cmr(&self) -> Cmr {
        match self {
            Self::Core(core) => core.cmr(),
            Self::Context(jet) => {
                // Provisional, domain-separated primitive identities. No claim
                // is made that these new primitives have an upstream formal
                // proof.
                let name = format!("fedimint/simplicity/jet/v0/{}", jet.name());
                Cmr::from_byte_array(sha256::Hash::hash(name.as_bytes()).to_byte_array())
            }
        }
    }

    fn source_ty(&self) -> TypeName {
        match self {
            Self::Core(core) => core.source_ty(),
            Self::Context(jet) => jet.source(),
        }
    }
    fn target_ty(&self) -> TypeName {
        match self {
            Self::Core(core) => core.target_ty(),
            Self::Context(jet) => jet.target(),
        }
    }
    fn cost(&self) -> Cost {
        match self {
            Self::Core(core) => core.cost(),
            Self::Context(_) => Cost::from_milliweight(1_000),
        }
    }
    fn encode(&self, writer: &mut BitWriter<&mut dyn Write>) -> std::io::Result<usize> {
        match self {
            Self::Core(core) => {
                writer.write_bits_be(0, 1)?;
                core.encode(writer).map(|n| n + 1)
            }
            Self::Context(jet) => {
                writer.write_bits_be(1, 1)?;
                writer.write_bits_be(*jet as u64, 8).map(|n| n + 1)
            }
        }
    }
    fn decode<I: Iterator<Item = u8>>(bits: &mut BitIter<I>) -> Result<Self, decode::Error> {
        if bits.read_bit()? {
            ContextJet::from_index(bits.read_u8()?)
                .map(Self::Context)
                .ok_or(decode::Error::InvalidJet)
        } else {
            let core = Core::decode(bits)?;
            if CORE_JETS.contains(&core) {
                Ok(Self::Core(core))
            } else {
                Err(decode::Error::InvalidJet)
            }
        }
    }
    fn parse(name: &str) -> Result<Self, simplicity::Error> {
        if let Some(jet) = ContextJet::ALL.iter().find(|jet| jet.name() == name) {
            return Ok(Self::Context(*jet));
        }
        let core = Core::parse(name)?;
        if CORE_JETS.contains(&core) {
            Ok(Self::Core(core))
        } else {
            Err(simplicity::Error::InvalidJetName(name.to_owned()))
        }
    }
}

impl JetEnvironment for Environment {
    type Jet = FedimintJet;
    type CJetEnvironment = Self;

    fn c_jet_env(&self) -> &Self {
        self
    }
    fn c_jet_ptr(jet: &FedimintJet) -> fn(&mut CFrameItem, CFrameItem, &Self) -> bool {
        match jet {
            FedimintJet::Core(core) => core_ptr(*core),
            FedimintJet::Context(jet) => match jet {
                ContextJet::InputAmount => {
                    |dst, src, env| asset_jet(ContextJet::InputAmount, dst, src, env)
                }
                ContextJet::InputCmr => {
                    |dst, src, env| asset_jet(ContextJet::InputCmr, dst, src, env)
                }
                ContextJet::InputState => {
                    |dst, src, env| asset_jet(ContextJet::InputState, dst, src, env)
                }
                ContextJet::InputOutpoint => {
                    |dst, src, env| asset_jet(ContextJet::InputOutpoint, dst, src, env)
                }
                ContextJet::InputAssetQuantity => {
                    |dst, src, env| asset_jet(ContextJet::InputAssetQuantity, dst, src, env)
                }
                ContextJet::OutputAssetQuantity => {
                    |dst, src, env| asset_jet(ContextJet::OutputAssetQuantity, dst, src, env)
                }
                ContextJet::InputAuthority => {
                    |dst, src, env| asset_jet(ContextJet::InputAuthority, dst, src, env)
                }
                ContextJet::OutputAuthority => {
                    |dst, src, env| asset_jet(ContextJet::OutputAuthority, dst, src, env)
                }
                ContextJet::IssuedQuantity => {
                    |dst, src, env| asset_jet(ContextJet::IssuedQuantity, dst, src, env)
                }
                ContextJet::BurnedQuantity => {
                    |dst, src, env| asset_jet(ContextJet::BurnedQuantity, dst, src, env)
                }
                ContextJet::InputAssetCount => {
                    |dst, src, env| asset_jet(ContextJet::InputAssetCount, dst, src, env)
                }
                ContextJet::OutputAssetCount => {
                    |dst, src, env| asset_jet(ContextJet::OutputAssetCount, dst, src, env)
                }
                ContextJet::InputAuthorityCount => {
                    |dst, src, env| asset_jet(ContextJet::InputAuthorityCount, dst, src, env)
                }
                ContextJet::OutputAuthorityCount => {
                    |dst, src, env| asset_jet(ContextJet::OutputAuthorityCount, dst, src, env)
                }
                ContextJet::InputAssetId => {
                    |dst, src, env| asset_jet(ContextJet::InputAssetId, dst, src, env)
                }
                ContextJet::OutputAssetId => {
                    |dst, src, env| asset_jet(ContextJet::OutputAssetId, dst, src, env)
                }
                ContextJet::InputAuthorityId => {
                    |dst, src, env| asset_jet(ContextJet::InputAuthorityId, dst, src, env)
                }
                ContextJet::OutputAuthorityId => {
                    |dst, src, env| asset_jet(ContextJet::OutputAuthorityId, dst, src, env)
                }
                ContextJet::InputVersion => {
                    |dst, src, env| asset_jet(ContextJet::InputVersion, dst, src, env)
                }
                ContextJet::OutputVersion => {
                    |dst, src, env| asset_jet(ContextJet::OutputVersion, dst, src, env)
                }
                ContextJet::SigHashAll => |dst, _, env| write_bytes(dst, &env.signature_hash),
                ContextJet::SessionIndex => {
                    |dst, _, env| write_bytes(dst, &env.session_index.to_be_bytes())
                }
                ContextJet::BlockCount => {
                    |dst, _, env| write_bytes(dst, &env.block_count.to_be_bytes())
                }
                ContextJet::CurrentAmount => {
                    |dst, _, env| write_bytes(dst, &env.current.amount.msats.to_be_bytes())
                }
                ContextJet::CurrentCmr => |dst, _, env| write_bytes(dst, &env.current.cmr),
                ContextJet::CurrentState => |dst, _, env| write_bytes(dst, &env.current.state),
                ContextJet::CurrentIndex => {
                    |dst, _, env| write_bytes(dst, &env.input_index.to_be_bytes())
                }
                ContextJet::InputCount => {
                    |dst, _, env| write_bytes(dst, &env.input_count.to_be_bytes())
                }
                ContextJet::OutputCount => {
                    |dst, _, env| write_bytes(dst, &(env.outputs.len() as u32).to_be_bytes())
                }
                ContextJet::OutputAmount => |dst, src, env| {
                    let Some(output) = env
                        .outputs
                        .get(read_index(src))
                        .and_then(|o| o.contract.as_ref())
                    else {
                        return false;
                    };
                    write_bytes(dst, &output.amount.msats.to_be_bytes())
                },
                ContextJet::OutputCmr => |dst, src, env| {
                    let Some(output) = env
                        .outputs
                        .get(read_index(src))
                        .and_then(|o| o.contract.as_ref())
                    else {
                        return false;
                    };
                    write_bytes(dst, &output.cmr)
                },
                ContextJet::OutputState => |dst, src, env| {
                    let Some(output) = env
                        .outputs
                        .get(read_index(src))
                        .and_then(|o| o.contract.as_ref())
                    else {
                        return false;
                    };
                    write_bytes(dst, &output.state)
                },
                ContextJet::OutputHash => |dst, src, env| {
                    let Some(output) = env.outputs.get(read_index(src)) else {
                        return false;
                    };
                    write_bytes(dst, &output.hash)
                },
                ContextJet::OutputModule => |dst, src, env| {
                    let Some(output) = env.outputs.get(read_index(src)) else {
                        return false;
                    };
                    write_bytes(dst, &output.module_id.to_be_bytes())
                },
                ContextJet::CreationSession => {
                    |dst, _, env| write_bytes(dst, &env.creation_session.to_be_bytes())
                }
                ContextJet::CreationBlockCount => {
                    |dst, _, env| write_bytes(dst, &env.creation_block_count.to_be_bytes())
                }
            },
        }
    }
}

fn read_index(mut frame: CFrameItem) -> usize {
    let mut index = 0u32;
    for _ in 0..32 {
        // SAFETY: every indexed context jet has exactly a u32 source type;
        // the Bit Machine supplies a read frame of that verified width.
        index = (index << 1) | u32::from(unsafe { c_readBit(&mut frame) });
    }
    index as usize
}

fn write_bytes(frame: &mut CFrameItem, bytes: &[u8]) -> bool {
    for byte in bytes {
        for bit in (0..8).rev() {
            // SAFETY: each caller writes exactly its jet's declared target
            // width into the write frame allocated by the Bit
            // Machine for that type.
            unsafe {
                c_writeBit(frame, byte & (1 << bit) != 0);
            }
        }
    }
    true
}

fn asset_jet(
    jet: ContextJet,
    dst: &mut CFrameItem,
    mut src: CFrameItem,
    env: &Environment,
) -> bool {
    use ContextJet::*;
    use fedimint_core::encoding::Encodable;

    use crate::assets::AssetId;
    if env.current.version != crate::assets::ASSET_VERSION {
        return false;
    }
    if matches!(jet, IssuedQuantity | BurnedQuantity) {
        let id = AssetId(read_bytes::<32>(&mut src));
        let values = if jet == IssuedQuantity {
            &env.actions.issuance
        } else {
            &env.actions.burns
        };
        let quantity = values
            .iter()
            .find(|value| value.asset == id)
            .map(|value| value.quantity)
            .unwrap_or(0);
        return write_bytes(dst, &quantity.to_be_bytes());
    }
    let index = u32::from_be_bytes(read_bytes::<4>(&mut src)) as usize;
    let input = env.inputs.get(index);
    if jet == InputOutpoint {
        return input.is_some_and(|input| {
            write_bytes(dst, &input.outpoint.consensus_hash_sha256().to_byte_array())
        });
    }
    let output = if matches!(
        jet,
        OutputAssetQuantity
            | OutputAuthority
            | OutputAssetCount
            | OutputAuthorityCount
            | OutputAssetId
            | OutputAuthorityId
            | OutputVersion
    ) {
        env.outputs
            .get(index)
            .and_then(|output| output.contract.as_ref())
            .filter(|output| output.actions().is_none())
    } else {
        input.map(|input| &input.contract)
    };
    let Some(output) = output else {
        return false;
    };
    match jet {
        InputAmount => write_bytes(dst, &output.amount.msats.to_be_bytes()),
        InputCmr => write_bytes(dst, &output.cmr),
        InputState => write_bytes(dst, &output.state),
        InputVersion | OutputVersion => write_bytes(dst, &output.version.to_be_bytes()),
        InputAssetQuantity | OutputAssetQuantity => {
            let id = AssetId(read_bytes::<32>(&mut src));
            let quantity = output
                .bundle()
                .and_then(|bundle| bundle.balances.iter().find(|value| value.asset == id))
                .map(|value| value.quantity)
                .unwrap_or(0);
            write_bytes(dst, &quantity.to_be_bytes())
        }
        InputAuthority | OutputAuthority => {
            let id = AssetId(read_bytes::<32>(&mut src));
            let present = output
                .bundle()
                .is_some_and(|bundle| bundle.authorities.contains(&id));
            // SAFETY: authority membership jets have a one-bit target.
            unsafe {
                c_writeBit(dst, present);
            }
            true
        }
        InputAssetCount | OutputAssetCount => write_bytes(
            dst,
            &(output
                .bundle()
                .map(|bundle| bundle.balances.len())
                .unwrap_or(0) as u32)
                .to_be_bytes(),
        ),
        InputAuthorityCount | OutputAuthorityCount => write_bytes(
            dst,
            &(output
                .bundle()
                .map(|bundle| bundle.authorities.len())
                .unwrap_or(0) as u32)
                .to_be_bytes(),
        ),
        InputAssetId | OutputAssetId | InputAuthorityId | OutputAuthorityId => {
            let entry = u32::from_be_bytes(read_bytes::<4>(&mut src)) as usize;
            let id = output.bundle().and_then(|bundle| {
                if matches!(jet, InputAssetId | OutputAssetId) {
                    bundle.balances.get(entry).map(|value| value.asset)
                } else {
                    bundle.authorities.get(entry).copied()
                }
            });
            id.is_some_and(|id| write_bytes(dst, &id.0))
        }
        _ => false,
    }
}

fn read_bytes<const N: usize>(frame: &mut CFrameItem) -> [u8; N] {
    let mut bytes = [0; N];
    for byte in &mut bytes {
        for _ in 0..8 {
            // SAFETY: asset_jet dispatch consumes exactly its declared source
            // width: u32, u256, (u32,u256), or (u32,u32).
            *byte = (*byte << 1) | u8::from(unsafe { c_readBit(frame) });
        }
    }
    bytes
}

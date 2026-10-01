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
    Sha256Block
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
                // is made that these new primitives have an upstream formal proof.
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
            // SAFETY: each caller writes exactly its jet's declared target width
            // into the write frame allocated by the Bit Machine for that type.
            unsafe {
                c_writeBit(frame, byte & (1 << bit) != 0);
            }
        }
    }
    true
}

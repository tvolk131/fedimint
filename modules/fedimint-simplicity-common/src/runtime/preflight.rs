//! Allocation-free structural scan of the pinned Simplicity 0.9 wire grammar.
//!
//! Upstream reserves node storage and allocates constant words before
//! discovering truncated payloads. Check those declarations against the actual
//! encoded bits first. This adds no limits to valid encodings: even the
//! shortest node takes four bits, and constant words must be present in full.
//! Upstream remains responsible for canonical encoding, sharing, type checking,
//! and witnesses. Keep this scan in sync when changing the pinned decoder
//! dependency.

use simplicity::jet::Jet;
use simplicity::{BitIter, decode};

use crate::jet::FedimintJet;

#[cfg(test)]
mod tests;

pub(super) fn check(program: &[u8]) -> Result<(), decode::Error> {
    let mut bits = BitIter::from(program.iter().copied());
    let available = program.len() * 8;
    let nodes = bits.read_natural::<usize>(None)?;
    if nodes > (available - bits.n_total_read()) / 4 {
        return Err(decode::Error::EndOfStream);
    }
    for index in 0..nodes {
        if bits.read_bit()? {
            if bits.read_bit()? {
                FedimintJet::decode(&mut bits)?;
            } else {
                let exponent = bits.read_natural::<u32>(Some(32))? - 1;
                let width = 1u64 << exponent;
                if width > (available - bits.n_total_read()) as u64 {
                    return Err(decode::Error::EndOfStream);
                }
                skip(&mut bits, width as usize)?;
            }
        } else {
            match two_bits(&mut bits)? {
                // Binary and unary combinators; every subcode is assigned.
                0 => {
                    two_bits(&mut bits)?;
                    bits.read_natural(Some(index))?;
                    bits.read_natural(Some(index))?;
                }
                1 => {
                    two_bits(&mut bits)?;
                    bits.read_natural(Some(index))?;
                }
                2 => match two_bits(&mut bits)? {
                    0 | 1 => {}                 // iden, unit
                    2 => skip(&mut bits, 512)?, // fail entropy
                    _ => {
                        bits.read_natural(Some(index))?;
                    } // disconnect1
                },
                _ => {
                    if !bits.read_bit()? {
                        skip(&mut bits, 256)?; // hidden CMR; otherwise witness
                    }
                }
            }
        }
    }
    Ok(())
}

fn two_bits<I: Iterator<Item = u8>>(bits: &mut BitIter<I>) -> Result<u8, decode::Error> {
    Ok(u8::from(bits.read_bit()?) * 2 + u8::from(bits.read_bit()?))
}

fn skip<I: Iterator<Item = u8>>(bits: &mut BitIter<I>, count: usize) -> Result<(), decode::Error> {
    for _ in 0..count {
        bits.read_bit()?;
    }
    Ok(())
}

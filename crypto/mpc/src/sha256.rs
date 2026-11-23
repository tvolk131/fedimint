//! Pure-Rust low-depth SHA-256 Boolean circuit builder for 32-byte messages.
//!
//! Uses 1-AND carry-save adders (CSA) to keep multi-operand sums unpropagated,
//! depth-6 Sklansky parallel-prefix adders on the critical compression path
//! (`e_new`, `a_new`, final additions), and 16-bit-block carry-skip adders on
//! the off-critical message schedule (`W[16..63]`). Public constants (the
//! SHA-256 IV, round constants `K`, and 32-byte padding block) are folded
//! automatically at circuit construction time.

use anyhow::{Result, ensure};

use crate::circuit::{Circuit, Gate};

const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

const IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// Fixed second half of the 512-bit SHA-256 block for a 32-byte message:
/// `0x80`, zeros, then bit-length `256`.
const PADDING_WORDS: [u32; 8] = [0x8000_0000, 0, 0, 0, 0, 0, 0, 256];

#[derive(Clone, Copy, Debug)]
enum Bit {
    Const(bool),
    Wire(usize),
}

/// 32-bit word stored LSB-first (`word[0]` is bit 0, `word[31]` is bit 31).
type Word = [Bit; 32];

struct Builder<'a> {
    circuit: &'a mut Circuit,
    zero: usize,
    one: usize,
}

impl<'a> Builder<'a> {
    fn new(circuit: &'a mut Circuit, zero: usize, one: usize) -> Self {
        Self { circuit, zero, one }
    }

    fn not(&mut self, a: Bit) -> Bit {
        match a {
            Bit::Const(v) => Bit::Const(!v),
            Bit::Wire(w) => Bit::Wire(self.circuit.add(Gate::Not(w))),
        }
    }

    fn xor(&mut self, a: Bit, b: Bit) -> Bit {
        match (a, b) {
            (Bit::Const(false), x) | (x, Bit::Const(false)) => x,
            (Bit::Const(true), x) | (x, Bit::Const(true)) => self.not(x),
            (Bit::Wire(x), Bit::Wire(y)) if x == y => Bit::Const(false),
            (Bit::Wire(x), Bit::Wire(y)) => Bit::Wire(self.circuit.add(Gate::Xor(x, y))),
        }
    }

    fn and(&mut self, a: Bit, b: Bit) -> Bit {
        match (a, b) {
            (Bit::Const(false), _) | (_, Bit::Const(false)) => Bit::Const(false),
            (Bit::Const(true), x) | (x, Bit::Const(true)) => x,
            (Bit::Wire(x), Bit::Wire(y)) if x == y => Bit::Wire(x),
            (Bit::Wire(x), Bit::Wire(y)) => Bit::Wire(self.circuit.add(Gate::And(x, y))),
        }
    }

    fn materialize(&self, bit: Bit) -> usize {
        match bit {
            Bit::Const(false) => self.zero,
            Bit::Const(true) => self.one,
            Bit::Wire(w) => w,
        }
    }

    fn word_const(val: u32) -> Word {
        std::array::from_fn(|i| Bit::Const((val >> i) & 1 != 0))
    }

    fn rotr(w: Word, n: usize) -> Word {
        std::array::from_fn(|i| w[(i + n) % 32])
    }

    fn shr(w: Word, n: usize) -> Word {
        std::array::from_fn(|i| {
            if i + n < 32 {
                w[i + n]
            } else {
                Bit::Const(false)
            }
        })
    }

    fn word_xor(&mut self, a: Word, b: Word) -> Word {
        std::array::from_fn(|i| self.xor(a[i], b[i]))
    }

    fn word_xor3(&mut self, a: Word, b: Word, c: Word) -> Word {
        let ab = self.word_xor(a, b);
        self.word_xor(ab, c)
    }

    /// `Ch(e, f, g) = g ^ (e & (f ^ g))` — 1 AND per bit, depth 1.
    fn ch(&mut self, e: Word, f: Word, g: Word) -> Word {
        std::array::from_fn(|i| {
            let fg = self.xor(f[i], g[i]);
            let efg = self.and(e[i], fg);
            self.xor(g[i], efg)
        })
    }

    /// `Maj(a, b, c) = c ^ ((a ^ c) & (b ^ c))` — 1 AND per bit, depth 1.
    fn maj(&mut self, a: Word, b: Word, c: Word) -> Word {
        std::array::from_fn(|i| {
            let ac = self.xor(a[i], c[i]);
            let bc = self.xor(b[i], c[i]);
            let prod = self.and(ac, bc);
            self.xor(c[i], prod)
        })
    }

    /// 3-to-2 Carry-Save Adder: `a + b + c == sum + carry (mod 2^32)`.
    /// Costs 31 AND gates total (bit 31 carry overflows mod 2^32), depth 1.
    fn csa(&mut self, a: Word, b: Word, c: Word) -> (Word, Word) {
        let mut sum = [Bit::Const(false); 32];
        let mut carry = [Bit::Const(false); 32];

        for i in 0..32 {
            let ac = self.xor(a[i], c[i]);
            let bc = self.xor(b[i], c[i]);
            sum[i] = self.xor(ac, b[i]);
            if i < 31 {
                let prod = self.and(ac, bc);
                carry[i + 1] = self.xor(c[i], prod);
            }
        }

        (sum, carry)
    }

    /// Depth-6 Sklansky parallel-prefix adder (`mod 2^32`).
    /// Since `G` and `P` are mutually exclusive for every prefix interval,
    /// `G_H | (P_H & G_L) == G_H ^ (P_H & G_L)`.
    fn add_sklansky(&mut self, a: Word, b: Word) -> Word {
        let p: [Bit; 32] = std::array::from_fn(|i| self.xor(a[i], b[i]));
        let mut g: [Bit; 31] = std::array::from_fn(|i| self.and(a[i], b[i]));
        let mut p_cur: [Bit; 31] = std::array::from_fn(|i| p[i]);

        for k in 0..5 {
            let half = 1usize << k;
            let step = half << 1;

            let mut start = 0;
            while start < 31 {
                let src = start + half - 1;
                if src >= 31 {
                    break;
                }
                let end = (start + step).min(31);
                for dst in (start + half)..end {
                    let pg = self.and(p_cur[dst], g[src]);
                    g[dst] = self.xor(g[dst], pg);
                    if start > 0 {
                        p_cur[dst] = self.and(p_cur[dst], p_cur[src]);
                    }
                }
                start += step;
            }
        }

        std::array::from_fn(|i| {
            if i == 0 {
                p[0]
            } else {
                self.xor(p[i], g[i - 1])
            }
        })
    }

    /// 16-bit-block carry-skip/prefix adder (`mod 2^32`): ~60 ANDs, depth ~17.
    /// Used on the message schedule `W[16..63]`, which runs well off the
    /// compression critical path and saves ~4,300 ANDs at zero depth cost.
    fn add_carry_skip_16(&mut self, a: Word, b: Word) -> Word {
        let p: [Bit; 32] = std::array::from_fn(|i| self.xor(a[i], b[i]));
        let mut g: [Bit; 31] = std::array::from_fn(|i| self.and(a[i], b[i]));
        let mut p_cur: [Bit; 31] = std::array::from_fn(|i| p[i]);

        // Block 0: bits 0..16 (anchor at bit 15, anchored at bit 0 so no P needed).
        for idx in 1..16 {
            let pg = self.and(p_cur[idx], g[idx - 1]);
            g[idx] = self.xor(g[idx], pg);
        }

        // Block 1: bits 16..31 (track group propagate so block-0 carry injects in 1 layer).
        for idx in 17..31 {
            let pg = self.and(p_cur[idx], g[idx - 1]);
            g[idx] = self.xor(g[idx], pg);
            p_cur[idx] = self.and(p_cur[idx], p_cur[idx - 1]);
        }

        // Inject carry out of bit 15 into block 1 in 1 parallel layer.
        let carry_15 = g[15];
        for idx in 16..31 {
            let pg = self.and(p_cur[idx], carry_15);
            g[idx] = self.xor(g[idx], pg);
        }

        std::array::from_fn(|i| {
            if i == 0 {
                p[0]
            } else {
                self.xor(p[i], g[i - 1])
            }
        })
    }
}

/// Append a low-depth SHA-256 circuit for a 32-byte (256-bit, big-endian)
/// message, returning the 256 digest wires in big-endian bit order.
pub fn append_low_depth(
    circuit: &mut Circuit,
    message: &[usize],
    zero: usize,
    one: usize,
) -> Result<Vec<usize>> {
    ensure!(message.len() == 256, "SHA-256 input must be 32 bytes");

    let mut b = Builder::new(circuit, zero, one);

    // Load 8 message words (big-endian bytes -> LSB-first word bits) + 8 constant padding words.
    let mut w = Vec::with_capacity(64);
    for wi in 0..8 {
        w.push(std::array::from_fn(|bit| {
            Bit::Wire(message[wi * 32 + (31 - bit)])
        }));
    }
    for pad in PADDING_WORDS {
        w.push(Builder::word_const(pad));
    }

    // Message schedule W[16..63].
    for t in 16..64 {
        let s0 = b.word_xor3(
            Builder::rotr(w[t - 15], 7),
            Builder::rotr(w[t - 15], 18),
            Builder::shr(w[t - 15], 3),
        );
        let s1 = b.word_xor3(
            Builder::rotr(w[t - 2], 17),
            Builder::rotr(w[t - 2], 19),
            Builder::shr(w[t - 2], 10),
        );
        let (u1, v1) = b.csa(w[t - 16], w[t - 7], s0);
        let (u2, v2) = b.csa(u1, v1, s1);
        w.push(b.add_carry_skip_16(u2, v2));
    }

    let [mut a, mut b_reg, mut c, mut d, mut e, mut f, mut g, mut h] =
        std::array::from_fn(|i| Builder::word_const(IV[i]));

    for (t, &k_t) in K.iter().enumerate() {
        // Keep pre-sums in carry-save form so they stay completely off the critical path.
        let (ptu, ptv) = b.csa(h, w[t], Builder::word_const(k_t));
        let (peu, pev) = b.csa(ptu, ptv, d);

        let sigma1 = b.word_xor3(
            Builder::rotr(e, 6),
            Builder::rotr(e, 11),
            Builder::rotr(e, 25),
        );
        let ch = b.ch(e, f, g);
        let sigma0 = b.word_xor3(
            Builder::rotr(a, 2),
            Builder::rotr(a, 13),
            Builder::rotr(a, 22),
        );
        let maj = b.maj(a, b_reg, c);

        // e_new = d + h + W[t] + K[t] + Sigma1(e) + Ch(e, f, g)
        let (eu1, ev1) = b.csa(peu, pev, sigma1);
        let (eu2, ev2) = b.csa(eu1, ev1, ch);
        let e_new = b.add_sklansky(eu2, ev2);

        // a_new = h + W[t] + K[t] + Sigma1(e) + Ch(e, f, g) + Sigma0(a) + Maj(a, b, c)
        let (t1u, t1v) = b.csa(ptu, ptv, sigma1);
        let (t2u, t2v) = b.csa(t1u, t1v, ch);
        let (au1, av1) = b.csa(t2u, t2v, sigma0);
        let (au2, av2) = b.csa(au1, av1, maj);
        let a_new = b.add_sklansky(au2, av2);

        h = g;
        g = f;
        f = e;
        e = e_new;
        d = c;
        c = b_reg;
        b_reg = a;
        a = a_new;
    }

    let final_state = [a, b_reg, c, d, e, f, g, h];
    let mut digest = Vec::with_capacity(256);

    for (i, state_word) in final_state.into_iter().enumerate() {
        let sum = b.add_sklansky(Builder::word_const(IV[i]), state_word);
        // Emit MSB-first big-endian digest bits.
        for bit in (0..32).rev() {
            digest.push(b.materialize(sum[bit]));
        }
    }

    Ok(digest)
}

#[cfg(test)]
mod tests;

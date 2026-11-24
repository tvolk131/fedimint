//! GF(2^8) base field from `gf256` (constant-time `no-tables`, polynomial
//! `0x11d`) and its degree-16 extension `Gf128 = GF((2^8)^16)` modulo the
//! irreducible polynomial `Y^16 + Y^3 + Y + 0x06`.
//!
//! Because `GF(2^8)` embeds directly into `Gf128` as constant polynomials
//! `[x, 0, ..., 0]`, every degree-`t` Shamir sharing over `GF(2^8)` at points
//! `1..=n` is automatically a degree-`t` Shamir sharing over `Gf128` with the
//! exact same Lagrange weights.

use std::ops::{Add, AddAssign, Mul, MulAssign};

pub use gf256::gf::gf256 as F;
use zeroize::Zeroize;

/// The field element for evaluation point `point` (`0..=255`).
pub fn point(point: usize) -> F {
    F(u8::try_from(point).expect("evaluation points fit in GF(2^8)"))
}

pub fn inverse(x: F) -> F {
    assert_ne!(x, F(0), "interpolation points must be distinct");

    F(1) / x
}

fn assert_distinct_points(points: &[usize]) {
    for (idx, &a) in points.iter().enumerate() {
        for &b in &points[idx + 1..] {
            assert_ne!(a, b, "interpolation points must be distinct");
        }
    }
}

/// Lagrange weights that evaluate, at `target`, the polynomial through the
/// values at `points`.
pub fn weights(points: &[usize], target: usize) -> Vec<F> {
    assert_distinct_points(points);

    points
        .iter()
        .map(|&i| {
            points
                .iter()
                .filter(|&&j| j != i)
                .fold(F(1), |w, &j| w * point(target ^ j) * inverse(point(i ^ j)))
        })
        .collect()
}

/// Evaluate the polynomial with `coefficients`, lowest degree first.
pub fn evaluate(coefficients: &[F], at: F) -> F {
    coefficients.iter().rev().fold(F(0), |acc, &c| acc * at + c)
}

/// An element of `GF((2^8)^16) = GF(2^8)[Y] / (Y^16 + Y^3 + Y + 0x06)`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Gf128(pub [F; 16]);

impl Gf128 {
    pub const ZERO: Self = Self([F(0); 16]);

    pub const fn embed(x: F) -> Self {
        let mut limbs = [F(0); 16];
        limbs[0] = x;
        Self(limbs)
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(std::array::from_fn(|i| F(bytes[i])))
    }

    pub fn to_bytes(self) -> [u8; 16] {
        std::array::from_fn(|i| self.0[i].0)
    }

    /// Multiply by a base-field scalar `s ∈ GF(2^8)` (16× cheaper than full
    /// `Gf128 * Gf128`).
    pub fn scale(self, s: F) -> Self {
        Self(std::array::from_fn(|i| self.0[i] * s))
    }

    /// Evaluate the Lagrange basis polynomials for base-field nodes `points`
    /// at an extension-field point `at`.
    pub fn lagrange_basis(points: &[usize], at: Self) -> Vec<Self> {
        assert_distinct_points(points);

        points
            .iter()
            .map(|&i| {
                let mut denom = F(1);
                let mut num = Self::embed(F(1));
                for &j in points {
                    if j != i {
                        num *= at + Self::embed(point(j));
                        denom *= point(i ^ j);
                    }
                }
                num.scale(inverse(denom))
            })
            .collect()
    }
}

impl Zeroize for Gf128 {
    fn zeroize(&mut self) {
        for limb in &mut self.0 {
            limb.0.zeroize();
        }
    }
}

impl Add for Gf128 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self(std::array::from_fn(|i| self.0[i] + rhs.0[i]))
    }
}

impl AddAssign for Gf128 {
    fn add_assign(&mut self, rhs: Self) {
        for (a, b) in self.0.iter_mut().zip(rhs.0) {
            *a += b;
        }
    }
}

impl Mul for Gf128 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        let mut prod = [F(0); 31];
        for (i, &a) in self.0.iter().enumerate() {
            for (j, &b) in rhs.0.iter().enumerate() {
                prod[i + j] += a * b;
            }
        }
        // Reduce modulo Y^16 + Y^3 + Y + 0x06.
        for i in (16..31).rev() {
            let c = prod[i];
            prod[i - 13] += c;
            prod[i - 15] += c;
            prod[i - 16] += c * F(0x06);
        }
        Self(std::array::from_fn(|i| prod[i]))
    }
}

impl MulAssign for Gf128 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

/// Evaluate an extension-field polynomial at a base-field point `at`.
pub fn evaluate_ext(coefficients: &[Gf128], at: F) -> Gf128 {
    coefficients
        .iter()
        .rev()
        .fold(Gf128::ZERO, |acc, &c| acc.scale(at) + c)
}

#[cfg(test)]
mod tests;

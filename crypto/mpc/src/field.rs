//! GF(2^64) arithmetic from `gf256`, built without lookup tables so it runs in
//! constant time. Party `i` evaluates every sharing at point `i + 1`.

pub use gf256::gf::gf2p64 as F;

/// The field element for evaluation point `point`.
pub fn point(point: usize) -> F {
    F(u64::try_from(point).expect("evaluation points are small"))
}

pub fn inverse(x: F) -> F {
    assert_ne!(x, F(0), "interpolation points must be distinct");

    F(1) / x
}

/// Lagrange weights that evaluate, at `target`, the polynomial through the
/// values at `points`.
pub fn weights(points: &[usize], target: usize) -> Vec<F> {
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

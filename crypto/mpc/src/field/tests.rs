use rand::{RngCore as _, SeedableRng as _};
use rand_chacha::ChaCha20Rng;

use super::{F, Gf128, evaluate_ext, point, weights};

fn random_ext(rng: &mut ChaCha20Rng) -> Gf128 {
    let mut b = [0u8; 16];
    rng.fill_bytes(&mut b);
    Gf128::from_bytes(b)
}

#[test]
fn gf128_field_axioms_and_embedding() {
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);

    for _ in 0..64 {
        let a = random_ext(&mut rng);
        let b = random_ext(&mut rng);
        let c = random_ext(&mut rng);

        assert_eq!(a + b, b + a);
        assert_eq!(a + a, Gf128::ZERO);
        assert_eq!(a * b, b * a);
        assert_eq!((a * b) * c, a * (b * c));
        assert_eq!(a * (b + c), a * b + a * c);
        assert_eq!(a * Gf128::embed(F(1)), a);

        let u = F(rng.next_u32() as u8);
        let v = F(rng.next_u32() as u8);
        assert_eq!(Gf128::embed(u) + Gf128::embed(v), Gf128::embed(u + v));
        assert_eq!(Gf128::embed(u) * Gf128::embed(v), Gf128::embed(u * v));
        assert_eq!(a * Gf128::embed(u), a.scale(u));
    }

    // Verify Fermat's little theorem for Y: Y^(2^128) == Y (and Y^(2^64) != Y).
    let mut y = Gf128::ZERO;
    y.0[1] = F(1);
    let mut cur = y;
    for _ in 0..64 {
        cur = cur * cur;
    }
    assert_ne!(cur, y, "Y^(2^64) must not equal Y in a degree-16 extension");
    for _ in 0..64 {
        cur = cur * cur;
    }
    assert_eq!(cur, y, "Y^(2^128) must equal Y in GF((2^8)^16)");
}

#[test]
fn gf128_lagrange_interpolation_matches_base_weights() {
    let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
    let coeffs: Vec<Gf128> = (0..4).map(|_| random_ext(&mut rng)).collect();
    let pts = [0usize, 1, 2, 3];
    let evals: Vec<Gf128> = pts
        .iter()
        .map(|&p| evaluate_ext(&coeffs, point(p)))
        .collect();

    // Base-field target using base weights.
    let w6 = weights(&pts, 6);
    let interp6 = evals
        .iter()
        .zip(&w6)
        .fold(Gf128::ZERO, |acc, (&e, &w)| acc + e.scale(w));
    assert_eq!(interp6, evaluate_ext(&coeffs, point(6)));

    // Extension-field target using extension Lagrange basis.
    let r = random_ext(&mut rng);
    let basis = Gf128::lagrange_basis(&pts, r);
    let interp_r = evals
        .iter()
        .zip(&basis)
        .fold(Gf128::ZERO, |acc, (&e, &b)| acc + e * b);
    let direct_r = coeffs.iter().rev().fold(Gf128::ZERO, |acc, &c| acc * r + c);
    assert_eq!(interp_r, direct_r);
}

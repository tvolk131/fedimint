# fedimint-mpc

Experimental, unreviewed honest-majority MPC with abort. A committee of
`parties >= 2 * degree + 1` guardians (up to `MAX_PARTIES = 32`, supporting
federations up to `N = 46`) jointly picks random preimages `r`, publishes
`SHA256(r)` and hands each member one Shamir share of `r` with threshold
`degree + 1`. Up to `degree` members may be malicious.

- `engine`: Shamir sharing over `GF(2^8)`, seed-expanded double-random
  sharings with Vandermonde extraction, load-balanced parallel-king DN07
  online multiplication (`O(1)` per-guardian egress and CPU per gate), and
  active security with abort via a 4-way recursive BBCGI19 inner-product check
  over `GF((2^8)^16)`. Because the check power-batches `M` multiplication
  triples with a single `GF(2^128)` challenge `r` and folds across `k`
  recursion rounds, the composed Schwartz–Zippel soundness error is at most
  `(M + 6k + 2) / 2^128` (~110-bit soundness at `batch = 4`, ~103-bit at
  `MAX_TRIPLES = 30_000_000`). Every message a party sends is a deterministic
  function of its seed and the messages it received, so an aborted run can be
  replayed to find who deviated.
- `sha256`: pure-Rust low-depth SHA-256 circuit (CSA + Sklansky + carry-skip,
  depth 456) evaluated in SIMD lanes with live-wire slot recycling.
- `direct`: batched preimage generator circuit and polynomial-time
  Berlekamp–Welch share reconstruction (with subset fallback).
- `memory`: an in-process transport for tests.

Not for real funds. See `docs/federated_bolt12.md` for how the federation uses
it.

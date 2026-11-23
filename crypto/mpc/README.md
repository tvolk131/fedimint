# fedimint-mpc

Experimental, unreviewed honest-majority MPC with abort. A committee of
`parties >= 2 * degree + 1` guardians (up to `MAX_PARTIES = 32`, supporting
federations up to `N = 46`) jointly picks random preimages `r`, publishes
`SHA256(r)` and hands each member one Shamir share of `r` with threshold
`degree + 1`. Up to `degree` members may be malicious.

- `engine`: Shamir sharing over `GF(2^8)`, seed-expanded double-random
  sharings with Vandermonde extraction, load-balanced parallel-king DN07
  online multiplication (`O(1)` per-guardian egress and CPU per gate), and
  128-bit active security via a 4-way recursive BBCGI19 inner-product check
  over `GF((2^8)^16)`. Every message a party sends is a deterministic function
  of its seed and the messages it received, so an aborted run can be replayed
  to find who deviated.
- `sha256`: pure-Rust low-depth SHA-256 circuit (CSA + Sklansky + carry-skip,
  depth 456) evaluated in SIMD lanes with live-wire slot recycling.
- `direct`: batched preimage generator circuit and polynomial-time
  Berlekamp–Welch share reconstruction (with subset fallback).
- `memory`: an in-process transport for tests.

Not for real funds. See `docs/federated_bolt12.md` for how the federation uses
it.

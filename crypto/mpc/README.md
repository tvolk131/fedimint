# fedimint-mpc

Experimental, unreviewed honest-majority MPC with abort. A committee of
`parties >= 2 * degree + 1` guardians jointly picks a random preimage `r`,
publishes `SHA256(r)` and hands each member one Shamir share of `r` with
threshold `degree + 1`. Up to `degree` members may be malicious.

- `engine`: Shamir sharing over GF(2^64), triples checked by sacrifice, Beaver
  multiplication, and degree checks on every opening. Every message a party
  sends is a deterministic function of its seed and the messages it received,
  so an aborted run can be replayed to find who deviated.
- `direct`: the one-hash generator circuit and share reconstruction.
- `memory`: an in-process transport for tests.

Not for real funds. See `docs/federated_bolt12.md` for how the federation uses
it.

The SHA-256 Bristol circuit in `circuits/sha256.txt` is MP-SPDZ 0.4.4
`Programs/Circuits/sha256.txt` with trailing whitespace removed; its notices are in
`circuits/MP-SPDZ-LICENSE.txt`.

# Consensus reference vectors

`consensus.json` is a fixed compatibility fixture. Tests must not regenerate it
from the implementation under test. A changed expectation requires review of the
consensus change, including its execution-version implications.

`reference.py` derives the fixture using only Python's standard library, without
calling or importing Fedimint, rust-simplicity, or the compiler. It spells out
BigSize framing, enum/dynamic-output framing, the v0/v1 signing preimages,
namespace/asset derivation, and all 36 custom jet identities and type widths.
Its standalone SHA-256 compression routine derives Simplicity tagged midstates
and program CMRs; it checks itself against `hashlib` on a padded test block.
The three execution vectors use literal DAG encodings and independently
calculated static bounds and fees.

To inspect the reference without changing the fixture:

```sh
python3 modules/fedimint-simplicity-common/tests/vectors/reference.py > /tmp/simplicity-reference.json
diff -u modules/fedimint-simplicity-common/tests/vectors/consensus.json /tmp/simplicity-reference.json
cargo test -p fedimint-simplicity-common
```

The Rust tests exercise every custom jet through its actual C-frame entry point,
checking output bits, declared widths, exact destination cursor movement and
outside guard words. They cover absent assets, invalid indices, foreign outputs,
action outputs and execution-version gates. These are regression tests, not an
independent implementation of the full Simplicity interpreter or a memory-safety
proof. Cross-platform execution and deeper unsafe-code review remain separate
hardening work.

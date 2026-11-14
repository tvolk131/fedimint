# Contract template vectors

`templates.json` pins the commitment Merkle root (CMR) and execution version that
the one template this crate ships, `owner`, compiles to for the fixed key in
`src/tests/template_vectors.rs`. `BuiltinTemplates` returns exactly these values.
Application templates (top-up, binary market, limit and partial orders, the
constant-product pool) pin their own vectors with their application; this crate's
vectors no longer cover them.

Wallet recovery recompiles every decrypted descriptor with the current compiler
and keeps an output only if both values match its stored output; a mismatch is
treated like a descriptor copied onto an unrelated policy. A changed vector
therefore makes recovery skip outputs created by earlier releases, **without an
error**. (A descriptor naming a template or descriptor version the wallet does not
support does fail recovery.)

Do not edit an existing entry to make a failing test pass. Keep each released
template's source, argument encoding and SimplicityHL output unchanged, and ship a
new template version with its own entry instead. A SimplicityHL or rust-simplicity
upgrade that changes any entry is a breaking change for recovery. Change an
existing entry only when no released wallet can hold outputs under it.

Freeze these vectors with the first deployed candidate; later compatible releases
must keep its template versions. Earlier predeployment template resets (see the
[evidence index](../../../../docs/simplicity/release/evidence-index.md#beta-and-release-history))
discarded only disposable prototype state and do not authorize replacing a
deployed template or abandoning its recovery support.

Tests must not regenerate this file from the implementation under test.

# Contract template vectors

`templates.json` pins the commitment Merkle root (CMR) and execution version that
the one template this crate ships, `owner`, compiles to for the fixed key in
`src/tests/template_vectors.rs`. `BuiltinTemplates` returns exactly these values.

Application templates (top-up, binary market, limit and partial orders, the
constant-product pool) are maintained with their application and pin their own
vectors there. Their earlier entries were moved unchanged: this crate's vectors
no longer cover them.

Wallet recovery recompiles every decrypted descriptor with the current compiler
and keeps an output only if both values match its stored output. Application
templates recover their covenants the same way. A changed vector
therefore means outputs created by earlier releases are skipped during recovery,
without an error.

Do not edit an existing entry to make a failing test pass. Keep each released
template's source, argument encoding and SimplicityHL output unchanged, and
ship a new template version with its own entry instead. A SimplicityHL or
rust-simplicity upgrade that changes any entry is a breaking change for
recovery. Change an existing entry only when no released wallet can hold
outputs under it.

The [historical evidence index](../../EVIDENCE.md#beta-and-release-history)
preserves the earlier predeployment template resets. Those discarded only
disposable prototype state, not the compatibility baseline for the fresh
execution-v1 deployment. They do not authorize replacing a deployed template
or silently abandoning its recovery support. No prototype wallet migration is
supported by the current deployment.

Freeze these vectors with the first deployed candidate; subsequent compatible
releases must retain its template versions.

Tests must not regenerate this file from the implementation under test.

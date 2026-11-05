# Contract template vectors

`templates.json` pins the commitment Merkle root (CMR) that each contract
template in this crate compiles to, for the fixed keys and terms in
`src/tests/template_vectors.rs`. Builtin descriptor templates also pin the
execution version that `BuiltinTemplates` returns.

Wallet recovery recompiles every decrypted descriptor with the current compiler
and keeps an output only if both values match its stored output. Application
templates recover the exchange covenants the same way. A changed vector
therefore means outputs created by earlier releases are skipped during recovery,
without an error.

Do not edit an existing entry to make a failing test pass. Keep each released
template's source, argument encoding and SimplicityHL output unchanged, and
ship a new template version with its own entry instead. A SimplicityHL or
rust-simplicity upgrade that changes any entry is a breaking change for
recovery. Change an existing entry only when no released wallet can hold
outputs under it.

The predeployment beta.1 market/AMM reset documented in the
[runbook](../../RUNBOOK.md#historical-beta1-prototype-transition) is a scoped
exception: those prototypes are disposable test state, not the compatibility
baseline for the fresh v0.13.0 deployment. That exception does not authorize
replacing a deployed template or silently abandoning its recovery support.
Freeze these vectors with the first deployed candidate; subsequent compatible
releases must retain its template versions.

Tests must not regenerate this file from the implementation under test.

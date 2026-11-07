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

The predeployment beta.1 market/AMM reset documented in the
[runbook](../../RUNBOOK.md#historical-beta1-prototype-transition) is a scoped
exception: those prototypes are disposable test state, not the compatibility
baseline for the fresh v0.13.0 deployment. That exception does not authorize
replacing a deployed template or silently abandoning its recovery support.
The fresh v0.13.0 execution-v1 reset also changes the undeployed
`top-up-or-release/v1` execution identifier from 0 to 1 while preserving its CMR.
Native outputs now carry empty asset bundles and use the v1 signing intent.
No deployed wallet state is migrated.

Freeze these vectors with the first deployed candidate; subsequent compatible
releases must retain its template versions.

Tests must not regenerate this file from the implementation under test.

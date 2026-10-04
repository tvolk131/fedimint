# Simplicity resource measurements

This is a data-gathering harness, not a fee policy or a throughput guarantee.
It does not change consensus limits, fees, or guardian execution. It uses Divan,
as do existing Fedimint benchmarks. No benchmark is added to PR CI.

The minimum guardian performance target is **Raspberry Pi 5**. Calibration needs
measurements on that hardware, including the full admission/consensus path. Record
RAM, storage, cooling, clock settings and thermal throttling alongside each Pi
run. Results from faster machines establish comparisons, not Pi latency or safe
production limits.

## Running

From the repository root, in the normal development environment:

```sh
# Check decoding, execution, preflight, module and core-processing outcomes.
cargo bench --locked -p fedimint-simplicity-server --bench resources -- --test

# Deterministic sizes, static bounds, fees, expected errors and transaction hashes.
FM_SIMPLICITY_BENCH_MANIFEST=1 cargo bench --locked \
  -p fedimint-simplicity-server --bench resources > manifest.json

# Timing: ordinary System allocator, no allocation instrumentation.
cargo bench --locked -p fedimint-simplicity-server --bench resources -- \
  --sample-count 100 --sample-size 1 --color never > timing.txt

# Allocations: separate executable; do not use its timings for comparisons.
cargo bench --locked -p fedimint-simplicity-server --bench resources \
  --features bench-alloc -- \
  --sample-count 100 --sample-size 1 --color never > allocations.txt

# Focus on the aggregate caps and complete in-memory submission checks.
cargo bench --locked -p fedimint-simplicity-server --bench resources -- \
  'transaction_preflight|core_submission' \
  --sample-count 100 --sample-size 1 --color never > caps-timing.txt

# Cap-fitting workload families and early/late invalidity probes.
cargo bench --locked -p fedimint-simplicity-server --bench resources -- \
  'adversarial_' --sample-count 100 --sample-size 1 --color never > adversarial.txt

# Deterministic bit mutations; single-sample timings rank candidates only.
FM_SIMPLICITY_BENCH_MUTATIONS=1 cargo bench --locked \
  -p fedimint-simplicity-server --bench resources > mutations.json
```

Use the default optimized bench profile for measurements. `--profile dev` is
useful only for fixture smoke checks. Divan accepts name filters, e.g.
`guardian_validation::recovery_32`. Run on an otherwise idle machine, repeat the
timing run, and keep the full output, manifest, compiler/OS/CPU/RAM, source
revision, compiler flags and allocator details. Do not run builds alongside the
measurements. The manifest pins fixture transactions, not only case labels.

Fixture construction, SimplicityHL compilation, signing, database seeding,
warm-up and manifest generation are outside timing. Ordinary Divan/manifest runs first
checks all fixtures against the real decoder, executor, preflight, guardian hook
and core submission processor, including exact rejection reasons. It also checks
the fully signed transaction's
encoded size against `Transaction::MAX_TX_SIZE` (49,968 bytes at this revision).
The same fixed keys, nonce, votes and contract outpoints reproduce the same cases.

## Concurrent validation

`FM_SIMPLICITY_BENCH_LOAD=workload,workers,iterations,backend` runs one fresh
process and prints JSON. For example:

```sh
FM_SIMPLICITY_BENCH_LOAD=mixed,4,80,rocks cargo bench --locked \
  -p fedimint-simplicity-server --bench resources
```

Workloads: `owner`, `constants_packed`, `chain_768x2`, `mixed_33_bad_last`,
`context_asset_missing`, `mint`, `mixed`. Backends: `mem`, `rocks`. Caller threads
are bounded to 1–16; each runs 10–2,000 validations sequentially, starting at a
barrier. The mixed case alternates packed constants and a real Mint v2 one-note
input/output transaction (zero mint fees, coherent seeded issuance state).
Every result must match its prechecked outcome. Writes are always dropped.

This is closed-loop core validation against a small warm database, excluding
network queues, repeated pending-submission revalidation, consensus scheduling,
database commits and sustained history growth. Scoped caller threads drive a
shared two-worker Tokio runtime; this does not reproduce the production API
executor. Mint config generation, selected fixture construction and warm-up are
outside timing. CPU seconds include all process threads during the measured
interval. Nearest-rank latency percentiles are reported separately for Mint and
Simplicity. Short runs and small per-class samples do not establish tail bounds.

On Unix, `getrusage` supplies process CPU and lifetime peak RSS. RSS includes
setup, warm-up, database caches, stacks and C allocations; the two peak readings
must not be subtracted to claim incremental validation memory. Only the selected
workload is constructed. Use the normal allocator, run cells sequentially in
fresh processes, repeat, and retain raw JSON outside the branch.

## Persistent storage

`FM_SIMPLICITY_BENCH_STORAGE=scenario,count` commits 1–10,000 operations to a
fresh RocksDB and prints JSON. For example:

```sh
FM_SIMPLICITY_BENCH_STORAGE=churn,1000 cargo bench --locked \
  -p fedimint-simplicity-server --bench resources
```

Scenarios: `bare` creates empty contracts; `live` adds unique, incompressible
1 KiB annotations; `receipt` puts those annotations in action outputs with no
UTXO; `churn` creates and spends annotated contracts; `assets1`/`assets32` create
a namespace and one/32 authorities per operation. Every transaction passes real
core/module validation and pays exact module fees through synthetic dummy
funding. Churn has two accepted transactions per operation. Record-count
assertions check live contracts, namespaces, origins, accepted indexes and
history batches. This is storage sizing, not a throughput benchmark.

The harness persists the core accepted-transaction index and real signed session
outcomes in 100-transaction batches, verifying their signatures. It does not run
networking, Aleph consensus or a wallet recovery scan. Logical module bytes omit
the module prefix; full database bytes include it, synthetic funding bookkeeping,
accepted indexes and signed history. Checkpoint/SST sizes include RocksDB
compression and metadata after flushing; they are not fully compacted steady-state
sizes or a production disk bound. Session occupancy and real funding change the
overhead. Only annotations are randomized: shared fixture policies/state may
compress more than real contracts. Retain raw results outside the branch.

## What each stage measures

| Stage | Scope |
| --- | --- |
| `decode` | Production `decode_program`: length checks, structural preflight, type inference/limits, redemption decoding and static bounds, including dropping its result. |
| `vm_cached` | A predecoded program: allocate a fresh BitMachine, execute, and drop the machine/result. Excludes decoding, CMR and execution-version checks. |
| `runtime_execute` | Production `execute`, including decode, CMR/version checks, VM allocation/execution and fee calculation. |
| `intent_hash` | One production v0/v1 transaction intent hash. |
| `environment_clone` | Clone and drop one already constructed environment. Shares immutable input/output/action data through `Arc` and copies the current contract snapshot. It is **not** a measurement of the entire context-building path. The first baseline predates sharing and copied the full context. |
| `guardian_validation` | The production structural, state-resolution, kind-preparation and instance-validation hooks: limits, decoding/commitments, output hashing, conservation, clocks, intent hashes, environments and VM execution. Includes current-thread executor entry and dropping preparations/results. |
| `transaction_preflight` | Production `resources::check_transaction`: combined byte/count checks, creation-signature charges, structural checks and sequential redemption decoding/static cost accumulation. This unsigned client preflight omits the outer signature envelope. Stops on the first error, before VM execution or database access. |
| `core_submission` | Production `process_transaction_with_dbtx` in submission mode: kind-wide preflight, input verification, module validation, outer signatures, native funding checks and processing hooks. Includes creation of a fresh warm MemDatabase transaction and dropping all writes after each iteration. |
| `adversarial_preflight` | Production `resources::check_signed_structure`: cheap structural checks and signature scheme/count, without decoding or database access. |
| `retained_decode` | Decode all inputs of each adversarial case's unmutated workload and retain every graph until the end, then drop them. An allocation probe for the retention decision, not production cache behavior or full guardian memory. |
| `adversarial_core` | The same core submission path and rollback methodology, on the adversarial matrix. Invalid cases must fail for their explicitly asserted reason. |

Per-input stages use the first input. The guardian stage measures all inputs in
the transaction. Its database is a small, seeded MemDatabase with a warm,
read-only transaction. No database snapshot construction is timed. Asset records
are seeded directly; these fixtures measure transitions from ledger state, not
asset genesis.

The guardian stage is **module validation**, not end-to-end acceptance. It omits
foreign-module verification, outer cryptographic signature verification, native
bitcoin funding checks, processing hooks, database commits, RocksDB I/O, network admission and consensus. Transactions have
outer signatures but do not include fee/collateral sponsorship. In particular,
`market_issue` needs foreign funding to pass core conservation. Benchmark success
must not be interpreted as full transaction acceptance.

The core stage adds a dummy-module funding input and regenerates outer
signatures outside measurement. This does not alter the inner Simplicity intent.
It seeds state separately and runs all core submission checks, but does not
commit writes, exercise RocksDB, mint funding, network admission or consensus.
Accepted fixtures are rolled back between iterations. The schema-2 manifest
records both the original and funded transaction hashes/sizes and the expected
preflight error. The isolated runtime stages retain over-budget workloads for
historical comparisons. The guardian stage now includes preparation and therefore enforces
the aggregate caps; its scope differs from reports before preparation was added.

The helper environment is for isolated runtime/clone measurements. The guardian
measurement constructs its own context using production code; it does not use
that helper. Do not subtract stage medians to infer an exact unmeasured stage:
allocation lifetimes and caches differ.

Divan's `max alloc` measures peak additional live bytes requested through Rust's
global allocator on the measured thread, and `alloc` measures allocation count
and bytes. These are **not RSS**. They exclude pre-existing fixtures/database,
stack, allocator overhead and allocations made directly by C or other threads.
Timing and profiling use separate builds to avoid profiler overhead in reported
latency. Outputs and temporaries are dropped inside measurement; sample size one
keeps peak allocation associated with one operation.

## Cases

- `unit_v0` / `unit_v1`: minimal programs, exposing fixed overhead.
- Adversarial `context_*` cases repeat a context jet 512 times with full
  32-entry balance, authority, issuance and burn lists. They cover first/last/
  missing asset searches, authority absence, outpoint hashing, a scalar-read
  control and an invalid index on the final call. Each is a funded transaction
  within both caps, with asserted outcomes and dropped-write checks in submission
  and consensus modes. The same cases run in `tests/resource_workloads.rs`.
- `owner`: one valid transaction-bound BIP340 signature.
- `market_issue` / `market_resolve`: the actual binary-market template, including
  asset accounting or an external oracle's signature. `bad_oracle` signs the
  wrong outcome and is rejected by the program.
- `inputs_8` / `inputs_32`: increasing input counts with no successors;
  `context_32` adds 32 successors; `recovery_32` adds 1 KiB to every consumed
  contract and successor; `assets_32` holds all 32 assets in every one of 32
  consumed contracts and 32 successors. `foreign_outputs_128` hashes the maximum
  outer-output count with 32 module inputs.
- `cost_near_limit`: a tiny shared DAG describing 49,152 unit executions, near
  the 10,000,000 milliweight cap. `signature_cost_near_limit` instead repeats
  192 valid BIP340 checks against a fixed message, at a similar static bound.
  These synthetic policies are workload probes, not usable authorization
  contracts. `cost_32` and `signature_cost_32` put 32 copies of each workload in
  one transaction, respectively. All four exceed the new 2,000,000 milliweight
  transaction budget and are rejected by preflight.
- `signature_budget` executes 32 valid signature checks in one input;
  `signature_split_budget` spreads those checks over four inputs. Both fit the
  shared budget. `signature_budget_over` doubles the single-input workload and
  is rejected before execution.
- `constants_3` / `constants_4`: three or four copies of the 4 KiB constant
  program, respectively. The first is decoder-heavy but accepted; the second
  exceeds the combined 16 KiB redemption limit and is rejected before decoding.
- `creation_19` / `creation_20`: a minimal contract spend plus 19 or 20 asset
  creation signatures. The latter exceeds the shared budget, since each creation
  consumes 100,000 milliweight and the contract also has nonzero cost.
- `wide_value`: a shared DAG builds a 1,048,576-bit intermediate value before
  discarding it. `large_constant` embeds a 4 KiB word. `large_witness` hashes
  128 SHA256 blocks, consuming exactly 8 KiB of witness data.
- `asset_failure` fails conservation in a large asset context;
  `late_bad_signature` executes 31 valid owner programs before the last fails.
  These show work performed for rejected transactions, which pay no accepted
  transaction fee.
- Decoder rejection cases cover excessive static cost, exponential inferred
  types, a truncated huge word, an impossible declared node count, byte limits,
  and a trailing witness. The existing allocation regression tests remain the
  correctness checks for rejecting hostile declarations before allocation.

## Adversarial exploration

The separate `adversarial` manifest array pins 34 cases' submitted transaction
hashes, outer/redemption sizes, per-input cost/cell/frame bounds and expected
outcomes. Their unmutated workloads all fit both aggregate caps. Cases cover:

- Constants packed to exactly 16 KiB, plus different constant sizes/input counts.
- Deep composition chains and balanced graphs with unique constants, separately
  and in pairs; wide intermediate values; and witness-heavy SHA256 workloads.
- 38 signature checks near the weight cap, and mixtures of constants plus 33
  signature checks near both caps. Fixed-message signatures are synthetic work,
  not application authorization examples.
- Missing/duplicate inputs, wrong CMRs, invalid output versions, trailing witness
  bytes, invalid or missing outer signatures, and insufficient native funding.
- First/last failing signature jets and creation signatures, and an invalid
  creation-authority destination with otherwise valid signatures.

Before timing, every case asserts its outcome in both submission and consensus
modes. Both modes discard the transaction; full database snapshots verify that
no writes escaped. This is an in-memory drop check, not a crash-durability test.
Malformed-witness cases reserve room below the byte cap but have no valid static
cost themselves; their unmutated baselines have valid bounded costs. The mixed
late-failure case needs a larger signature program, so it removes another small
constant to stay under the byte cap. Compare its manifest, not just its label.

The mutation mode flips individual encoded-program bits at deterministic strides
across five workload families (668 probes at this revision). Each probe invokes
the production stateless checker; a successful result means only that preflight
accepted, not that the changed transaction is authorized. It does not execute
mutated programs. One timing sample per probe is for triage, not a benchmark or
a worst-case bound. Source case plus bit index reproduces each mutation; bit zero
is the least significant bit of byte zero. No PR fuzz/smoke job is added.

This is a targeted exploration, not an exhaustive adversarial maximum search. It does not
exercise every combination of frame/cell/type limits, worst-case canonical
sharing/type inference, all market branches, large historical databases,
recovery scans or multiple module instances at once.
Those remain relevant before production calibration, alongside measurements on
guardian-class Linux hardware and concurrent invalid-submission load.

[Results and optimization history](RESULTS.md) consolidate the measured baseline,
context sharing, aggregate caps, adversarial exploration and validation ordering.
Keep the harness, fixtures and methodology as regression tools. Retain key
comparisons and archive their evidence; routine raw runs need not all be committed.
Fee coefficients or limit changes should be reviewed separately after examining
the measurements.

The original raw data and reports are preserved by the published tag
`codex/simplicity-benchmarks-2026-10-03` at
`39102ef2040d3c4dd6b0027132a5ddb4ba46c553`.
[Browse the archived data](https://github.com/tvolk131/fedimint/tree/39102ef2040d3c4dd6b0027132a5ddb4ba46c553/modules/fedimint-simplicity-server/benches/resources/2026-10-02-m4-pro).
Keep this tag when squashing or rebasing the feature branch. To retrieve it:

```sh
git fetch origin tag codex/simplicity-benchmarks-2026-10-03
git show codex/simplicity-benchmarks-2026-10-03:modules/fedimint-simplicity-server/benches/resources/2026-10-02-m4-pro/metadata.json
```

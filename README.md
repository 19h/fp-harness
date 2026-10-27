# fp-harness

`fp-harness` executes selected functions from the supplied arm64e Mach-O in a
RAX AArch64 user-mode machine and records the control transfers that occur. It
is an evidence-collection tool for reconstructing paths through flattened or
indirect control flow. The output is conditional on the initial state, the
external-call models, and the emulated CPU. It is not a complete decompiler or
a proof of reachability.

The target used for the included reports is the **thin** Mach-O
`../fairplayd.arm64e`, SHA-256
`4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`.
Addresses below refer to that exact image at its preferred base, `0x100000000`.
The RAX dependency is a source-only archive of commit
`ee96791b42237862178f1774afaf0f1ee8570ce9` under `.deps/rax`. It is extracted
from the local RAX repository without modifying or incorporating its dirty
working tree. The pinned source is approximately 63 MiB.

## Build and verify

```sh
# Once, if .deps/rax is absent; requires the commit in this local repository.
./scripts/prepare_rax.sh /Users/int/dev/rax
cargo build --locked --offline
cargo test --locked --offline
./target/debug/fp-harness selftest ../fairplayd.arm64e
python3 tests/compare_dyld_fixups.py ./target/debug/fp-harness ../fairplayd.arm64e
../.venv/bin/python tests/differential_unicorn.py ./target/debug/fp-harness ../fairplayd.arm64e
python3 tests/integration.py ./target/debug/fp-harness ../fairplayd.arm64e
python3 tests/semantic_pipeline.py ./target/debug/fp-harness ../fairplayd.arm64e
python3 tests/checkpoint.py ./target/debug/fp-harness ../fairplayd.arm64e
python3 tests/checkpoint_model.py ./target/debug/fp-harness ../fairplayd.arm64e
python3 tests/regions.py reports/reconstruction/baseline.jsonl
../.venv/bin/python tests/semantic_differential.py \
  reports/reconstruction/baseline.jsonl reports/reconstruction/target-proof.json
```

`z3` must be on `PATH` for the semantic commands and symbolic unit tests.
The Unicorn checks use the existing `.venv` and do not install packages.

The comparison against Xcode `dyld_info -fixups` covered 61,737 rows and found
no mismatches in address, kind, rebase target, or bind symbol and addend. It
does not validate PAC signatures, imported object contents, or dyld process
startup. The Unicorn test compares instruction-PC sequences and final `x0`
for two paths through `0x1000044fc`; these fixtures use neither PAC operations
nor imports. The self-test also exercises one PAC-disabled pointer-return
case, but does not establish equivalence to hardware pointer authentication.
The target-slice Unicorn test compares the generated expression against 256
seeded values under the captured memory snapshot.
`differential_unicorn.py` requires Unicorn in the selected Python environment;
the other Python checks use the standard library and Xcode's `dyld_info`.

## Interrogate a function

```sh
./target/debug/fp-harness run ../fairplayd.arm64e \
  --entry 0x100e18c0c \
  --x1 0x530000000 --x3 0x530000800 --x4 0x530001000 \
  --max-insns 5000 --heap-size 0x4000000 \
  --json /tmp/control.json --dot /tmp/control.dot --trace /tmp/control.trace
python3 scripts/summarize_path.py /tmp/control.json
```

The default mapped scratch region is `[0x530000000, 0x530010000)`; use
`--w32 ADDRESS=VALUE` or `--w64 ADDRESS=VALUE` to initialize caller memory.
The initial stack pointer is `0x5207ff000`; stack argument slots above it are
mapped and can also be written with those options. `--x0` through `--x7` seed
argument registers. All other general registers begin in the RAX default
state except `x29`, `x30`, and `sp`, which the harness initializes.

| Option | Meaning |
|---|---|
| `--read ADDRESS:BYTES` | Capture a memory range after every run in JSON; at most 1 MiB per range, 16 ranges. Invalid reads carry an error. |
| `--max-insns N` | Maximum instructions per execution; a budget stop is incomplete. |
| `--heap-size BYTES` | Synthetic heap capacity; 4,096-byte aligned, 4,096 B to 4 GiB. Default 64 MiB. |
| `--runs N` | Repeat with deterministic XOR variations to `x1..x7`; `x0` stays fixed. These are not ABI-validity-aware. |
| `--explore-depth N` | Enumerate prefixes of conditional outcomes, up to N occurrences. |
| `--explore-runs N` | Bound the prefix scheduler, including its initial empty-prefix run. |
| `--dot PATH` | Graph with observed edges and encoded but unobserved conditional successors. |
| `--simple-dot PATH` | Hide some unobserved conditional successors; this is a visualization filter, not an infeasibility proof. |
| `--json PATH` | Run inputs, ordered control events and modeled calls, stop reasons, blocks and aggregate edges. |
| `--trace PATH` | Ordered instructions and control events for the first baseline run. |
| `--observe PATH` | Capture baseline instruction state, guest data accesses and model-call events as JSONL. |
| `--observe-range START:END` | Restrict captured instruction PCs to the half-open range. |
| `--observe-pages` | Capture readable pages containing selected data reads. |
| `--checkpoint-at PC --checkpoint PATH` | Save the first matching baseline state and write journal. |
| `--restore PATH` | Restore a checkpoint into a fresh image; executable and image hashes must match. |
| `--set-reg N=VALUE` | Intervene on XN after restoration; resulting events are speculative. |
| `--quiet` | Suppress the textual graph; status remains on stderr. |

`inspect`, `funcs`, and `fixups` report image metadata, function-start entries,
and a tab-separated dump of decoded/materialized fixups. `--entry` defaults to
`LC_MAIN` when present. For repeated runs, the graph's fields named `runs` on
edges and branches count **occurrences**, including repeated visits within a
run; the top-level `runs` counts executions.

### Included reconstruction

`reports/sub_100e18c0c.control.txt` is a compact ordered projection of the
baseline run. It omits only indirect transfers whose target equals the next
instruction; the full event stream remains in the accompanying JSON and the
instruction stream in the trace. The baseline returned after 2,516 retired
instructions with `x0 = 0xffff5035`. A modeled `malloc(0x40000000)` request
failed because the synthetic heap was 67,108,864 B. `reports/sub_100e18c0c-large-heap.control.txt`
uses the same entry state with a 1,090,519,040 B heap: that allocation succeeds,
and the run reaches its 5,000-instruction budget at `0x100e1dc64`. The latter
is an incomplete path, and neither result establishes the target's native
behavior. Both JSON files include per-call results and ordered control events.

`reports/sub_100004530.json` illustrates conditional exploration; its
`requested_prefix` specifies desired outcomes, `redirects` counts actual PC
changes, and every event at or after the first change has `speculative: true`.
A forced path can be inconsistent with the input and earlier predicates.
The graph's `forced` edge count includes such counterfactual-dependent events,
not just the branches where a PC was redirected. The trace is the baseline
only. The older files in `examples/` predate these evidence corrections.

## Semantic reconstruction workflow

Capture state around the selected instruction range, including page snapshots
for successful reads. The baseline JSONL includes instruction bytes, pre/post
X0-X30, SP, PC, PSTATE, V0-V31, FPCR/FPSR and thread registers, guest data
accesses, and modeled external-call state and accesses. Page snapshots are
opt-in because they can be large.

```sh
./target/debug/fp-harness run ../fairplayd.arm64e \
  --entry 0x100e18c0c --x1 0x530000000 --x3 0x530000800 --x4 0x530001000 \
  --max-insns 5000 --observe /tmp/fp.jsonl \
  --observe-range 0x100e18e74:0x100e18e9c --observe-pages --quiet
./target/debug/fp-harness analyze /tmp/fp.jsonl \
  --start 0x100e18e78 --end 0x100e18e94 --symbolic-reg 0 --result-reg 8 \
  --out /tmp/target-proof.json
```

The analyzer verifies the image SHA-256 and instruction bytes, invokes the RAX
strict AArch64 SMIR lifter, and lowers its supported operations to SMT
bit-vectors. It fixes all initial state except one selected X register, checks
all recorded GPR and NZCV transitions for the concrete input, enumerates at
most 16 outcomes, and asks Z3 whether the enumeration and a candidate zero
test are exhaustive. It can model bounded scalar loads by enumerating their
addresses and substituting captured page bytes. Those bytes are **assumptions**
about memory, not invariants. Stores, unsupported operations, noncontiguous or
speculative paths, missing snapshots, solver errors and unknown results are
rejected or reported as incomplete. The actual supported operation set is in
`src/semantic.rs`; it is not a complete AArch64 symbolic executor.

`reports/reconstruction/index-proof.json` proves the local table-index
relation for `0x100e18e98` and cross-checks two recorded entry executions.
`target-proof.json` includes the table load under its captured-page assumption.
`semantic-cfg.json` and `semantic-cfg.dot` are a conditional overlay, built by:

```sh
python3 scripts/semantic_cfg.py reports/reconstruction/index-proof.json \
  --json /tmp/semantic-cfg.json --dot /tmp/semantic-cfg.dot
./target/debug/fp-harness slice reports/reconstruction/baseline.jsonl \
  --at 0x100e18e98 --out /tmp/backward-slice.json
```

The backward slice follows supported SMIR register, flag and observed byte
dependencies. A model call or unsupported dependency is an explicit boundary;
this is dynamic provenance, not a proof over unseen executions. The target
example reaches the `_malloc` model as the source of `x0`.

## Checkpoints and interventions

```sh
./target/debug/fp-harness run ../fairplayd.arm64e \
  --entry 0x100e18c0c --x1 0x530000000 --x3 0x530000800 --x4 0x530001000 \
  --checkpoint-at 0x100e18e78 --checkpoint /tmp/fp-checkpoint.json --quiet
./target/debug/fp-harness run ../fairplayd.arm64e \
  --restore /tmp/fp-checkpoint.json --set-reg 0=0 --observe /tmp/intervention.jsonl \
  --observe-range 0x100e18e78:0x100e18e9c --quiet
```

The checkpoint stores user registers, full modeled RAX system-register state,
synthetic allocator state, and the ordered successful guest and model writes.
Restoration constructs a fresh image and applies the initial and journaled
writes. The file is tied to the SHA-256 of the image and the exact harness
executable. Checkpoints with an active exclusive reservation or after modeled
wait/event hints are refused. Other unexported core state remains a validation
limit; this is a single-thread model without asynchronous events.
`tests/checkpoint.py` compares all 2,361 subsequent instruction states and
three model calls against uninterrupted execution for the supplied fixture.
`tests/checkpoint_model.py` additionally patches a temporary copy of the image
to verify restoration of a guest stack write and a modeled `memcpy` write.

A `--set-reg` override is an intervention: downstream events are marked
speculative. `scripts/concolic_replay.py` runs solver witnesses from a
checkpoint with this labeling; it does not solve for an entry input.
`scripts/replay_checkpoint.py` offers a separate, slower replay-from-entry
verification of a full recorded prefix.

## VM investigation

`python3 scripts/vm_scan.py FULL_OBSERVATION` ranks correlations between
repeated one-byte reads and nearby indirect transfers.
`python3 scripts/handler_trace.py FULL_OBSERVATION --dispatch ADDRESS
--vpc-reg N` summarizes concrete regions between repeated dispatch-site visits;
the virtual-PC register is analyst supplied. Both require full observations.
`scripts/infer_effects.py` fits simple register-effect hypotheses to at least
three observations of the same native path; it labels them finite-sample
hypotheses and does not infer memory effects or prove equivalence.

These tools emit hypotheses and observed state effects only. The current target trace
does not establish a virtual instruction stream, a VM context, or general
handler semantics, and these tools do not yet reconstruct virtual bytecode or
a whole-program virtual CFG. Absence of a candidate is not evidence of absence
of a VM.

## Architecture and evidence boundaries

1. `image.rs` reads the Mach-O and chained fixups. For safety it accepts only
   chained pointer format 12 (`DYLD_CHAINED_PTR_ARM64E_USERLAND24`); it does
   not implement a general dyld loader. The target's encoded addends are
   applied, but external symbols are assigned synthetic addresses.
2. `machine.rs` maps segments, scratch, stack and heap, materializes fixups,
   and single-steps the RAX software CPU. PAC key-enable bits are cleared and
   authenticated fixups are materialized as raw addresses. This is a specific
   emulation policy, not an assertion about device PAC keys or failure behavior.
3. `runtime.rs` models a limited set of calls. Allocation is a bounded bump
   allocator, free does not reclaim memory, locks and retain/release are
   approximations, and time/random values are deterministic. A data import is
   represented by a synthetic slot and shadow object. Unknown calls and failed
   memory-model operations stop the run. A supported model is still an
   assumption; `modeled: true` is not a native-equivalence certificate. The
   virtual heap limit and RAX's 1 GiB frame arena are separate: a successful
   modeled allocation does not guarantee physical backing for all its pages.
4. `observed.rs` supplies an independently instrumented RAX CPU adapter. It
   records data accesses through the ArmMemory interface. The adapter uses a
   fixed core counter rather than the standard adapter's host-clock refresh;
   equivalence is established only for the tested executions.
5. `semantic.rs` lifts a supported straight-line subset to bit-vector formulas;
   `slice.rs` traces concrete dependencies. Unsupported effects stop analysis.
6. `cfg.rs` merges executions using leaders from all recorded runs, retains
   encoded alternate conditional successors as unobserved candidates, and
   records execution counts and counterfactual provenance. Basic blocks and
   the compact projection do not remove data operations, solve predicates, or
   establish semantic equivalence. JSON event order is the evidence for each
   run; aggregate edges can combine paths from different runs.

There is no dyld startup, system library loading, initializer execution,
threading, signal delivery, hardware PAC verification, or native comparison of
`0x100e18c0c`. The argument meanings and the function's intended contract are
unknown. The provided initialization is a synthetic probe, not a recovered
caller context. Concrete runs discover indirect targets they execute; bounded
symbolic slices can also enumerate target candidates from captured memory. The
conditional scheduler does not solve constraints back to function-entry inputs. Graph construction retains all runs in memory; edge lookup is
linear in the number of distinct edges, so worst-case reconstruction time can
scale as O(T * E) for T recorded events and E distinct edges, in addition to
instruction/block indexing and path storage.

## Assumption register and falsification probes

| Assumption | Dependent result | Stress test / falsification probe |
|---|---|---|
| Image bytes and preferred base match the recorded target. | All addresses and reports. | Recompute SHA-256; compare segment layout and fixups with `dyld_info`. |
| The SMIR lift and supported SMT lowering preserve the slice's instruction semantics. | Slice proofs and solver candidates. | Compare every recorded GPR/NZCV transition; independently run the target slice on Unicorn across seeded inputs and boundary values. |
| Captured page bytes remain the applicable memory contents for each symbolic input. | Table-derived target formulas. | Compare snapshots across independent runs and replay each candidate; treat mutable or uncaptured memory as unresolved. |
| The checkpoint captures all state relevant to the continuation. | Direct restored runs. | Compare the entire resumed suffix, including instruction state, memory events and model calls, with uninterrupted execution; reject active reservations and wait/event hints. |
| RAX instruction semantics match the relevant target instructions under the configured CPU. | All observed control flow. | Compare traces and registers with independent emulation or native execution; the included Unicorn test covers only the two small dispatcher paths. |
| Disabled PAC and raw pointers preserve the target transfer being investigated. | Authenticated indirect targets. | Compare authenticated transfers with a correctly configured arm64e device and its real pointer context. |
| Synthetic arguments, zero-initialized memory, and import models approximate a chosen caller. | Target-specific path and outputs. | Capture caller registers and memory; replay against real libraries or stronger per-import models. Vary heap capacity and input fields. |
| A redirected branch yields a useful counterfactual execution. | Exploration edges marked speculative. | Satisfy its prefix using actual inputs or a solver, then reproduce it without redirection. |
| A never-observed branch edge is uninteresting in the displayed sample. | Simplified DOT only. | Vary inputs or execute the other branch. Absence of observation cannot prove impossibility. |

## Bounded scope expansion

- High impact: the chosen sample establishes obfuscated native dispatch, not a
  bytecode VM. Automated VM recognition, general handler synthesis and
  whole-program devirtualization remain unimplemented.
- High impact: the instrumented adapter's fixed counter and the synthetic
  runtime can change paths. A native arm64e and real-caller comparison was not
  performed.
- Medium impact: symbolic slices currently support one symbolic X register,
  at most 16 enumerated outcomes/addresses, bounded snapshot-backed loads, and
  no symbolic stores or whole-path input solving. Unsupported cases stop.

## Provenance

The local Xcode SDK `usr/include/mach-o/fixup-chains.h` specifies the pointer
and import layouts; the executable's `LC_DYLD_CHAINED_FIXUPS` and Apple's
`dyld_info` supply the image-specific facts. The RAX and Unicorn executions are
separate software emulators; no active IDA database for this image or native
arm64e runtime was available for the included validation.

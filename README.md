# Cerebras simtracer

Tools for inspecting Cerebras simulator CTF traces. Three complementary commands:

- **`simflame`** — converts a trace into a [speedscope](https://www.speedscope.app/) flamegraph for whole-program / multi-tile call-stack visualization.
- **`simperfetto`** — converts a trace into a [Perfetto](https://ui.perfetto.dev) protobuf trace: the same flamegraph plus configurable counter/instant channels (dispatch & wavelet rates, fabric backpressure, wavelets, router state, operands).
- **`simtrace`** — interactive per-PE instruction trace viewer: cycle ranges, function-entry hits, per-task / per-mnemonic stats, and resolved operand values from the pipeline trace.

They share a metadata-driven CTF parser (`ctf.py`), the call-stack reconstruction (`callstack.py`), and an ELF symbol cache.

## Install

```
pip install .
```

## simflame — whole-program flamegraph

```
simflame <out_dir> -o trace.speedscope.json [--tiles 16,17,18] [--trace-dir DIR]
```

- `out_dir` — simulator `out/` directory containing `bin/*.elf`
- `--trace-dir` — override path to `simfab_traces/` when it does not live inside `out_dir`
- `--tiles` — comma-separated tile indices to include (default: all)

`simfab_traces/` is auto-discovered in `<out_dir>/simfab_traces`, the current working directory, or next to `<out_dir>`. Use `--trace-dir` to set it explicitly.

Open the output in https://www.speedscope.app/.

![simflame example](media/simtracer.gif)

## simperfetto — Perfetto trace with extra channels

```
simperfetto <out_dir> -o trace.pftrace [--tiles 16,17] [--cycles A:B] [--all]
```

Open the output at https://ui.perfetto.dev (use a `.pftrace.gz` output name to gzip it). Each tile becomes a process group; channels add tracks under it. The same options as `simflame` apply (`--tiles`, `--trace-dir`, `--bin-root`), plus `--cycles A:B` and `--bin-cycles N` (counter window, default 1000).

Timestamps are simulator **cycles** written directly — the Perfetto axis labels them "ns", but 1 tick = 1 cycle.

### Channels

| channel | flag | default | track(s) per tile |
| --- | --- | --- | --- |
| Call-stack flamegraph | `--calls` / `--no-calls` | on | `calls` (slices) |
| Dispatch rate | `--dispatch-rate` / `--no-` | on | `dispatch/bin` (counter) |
| Wavelet rate | `--wavelet-rate` / `--no-` | on | `wavelets/bin` (counter) |
| Fabric backpressure | `--backpressure` / `--no-` | on | `backpressure L<link>` (counter, binned max) |
| — full-resolution backpressure | `--backpressure-raw` | off | every sample instead of the binned max |
| Per-wavelet markers | `--wavelet-events` / `--no-` | on | `wavelets` (instant; id=5 and id=6) |
| Wavelet flow arrows | `--flow` / `--no-flow` | on | links each wavelet's hops by ident (id=6) / color (id=5) |
| Router switch position | `--switch-pos` | off | `router` (instant) |
| Resolved operands | `--regs` | off | `reg.dest/src0/src1/src2` (counters) |
| Debug wavelet counters | `--debug-counters` | off | `dbg.count_w/t/s c<color>` (counters) |
| Everything | `--all` | — | enables the remaining opt-in channels (except `--backpressure-raw`) |

`--flow` keys the flow id on the wavelet's full 64-bit `ident` (id=6) or color (id=5), so a wavelet forwarded across the fabric — a "train" — shows as a connected chain of arrows. Click a wavelet marker in the Perfetto UI to highlight its train. Needs `--wavelet-events` (the markers the arrows attach to).

The defaults are a cheap, low-clutter set. Backpressure dominates a typical trace (millions of samples), so it is downsampled to a per-window max envelope by default; `--backpressure-raw` emits every sample (much larger output). Which event types a given trace actually contains varies — channels with no matching events simply produce no tracks.

## simtrace — per-PE instruction trace viewer

```
simtrace <out_dir> <subcommand> [options]
```

### Subcommands

| command | what it does |
| --- | --- |
| `tiles`  | List tiles that have trace events, with their ELF and event count. |
| `funcs`  | List functions in the ELF for a tile (optionally filtered by pattern). |
| `show`   | Print the instruction trace for a tile in a cycle range, with ELF disassembly and (optionally) operand values. |
| `find`   | List cycles where a function (substring or fnmatch) was entered. |
| `stats`  | Per-task / per-function / per-mnemonic counts for a tile. |
| `regs`   | Per-instruction resolved operand values (`dest`, `src0`, `src1`, `src2`) from the pipe trace. |

`--tile N` accepts a raw tile index or an `x.y` coordinate. `--cycles A:B` accepts open ranges (`A:`, `:B`) and a single cycle (`A`).

### Examples

List active tiles:

```
$ simtrace out/ tiles
Available tiles (grid 8x3):
   tile  coord       events  ELF
      9  P1.1              6  out_1_0.elf
     12  P4.1            567  out_0_0.elf
     ...
```

Find every cycle where `compute_step` was entered on tile 12:

```
$ simtrace out/ find --tile 12 --func compute_step
     cycle  task  function  (uid)
       734    24  compute_step  (uid=120)
      1287    24  compute_step  (uid=412)
      ...
```

Show the trace for cycles 360–400 with resolved operands:

```
$ simtrace out/ show --tile 12 --cycles 360:400 --regs
   cycle  task    ip          flags  function          inst_bin   trace_op    elf@ip                      operands
     366    1  0x00000448  E        f_memcpyh2d       0x0d804990 JMP         movri  r7 = 384            s1=0x1a imm=0x1a
     372    1  0x00000464           f_memcpyh2d       0x66440820 EQ32        mov16  r12 = r6            s0=...
     ...
```

Statistics:

```
$ simtrace out/ stats --tile 17 --top 5
Tile 17:  events=10,776  cycles 167..17987 (span 17821)

Tasks (top 5):
  task   9:      4,697  ( 43.6%)  terms=28
  task  22:      2,848  ( 26.4%)  terms=116
  ...
Functions by dispatched instructions (top 5):
       1,744  ( 16.2%)  f_state
       1,612  ( 15.0%)  __fiber_runtime__worker_entry
  ...
Instruction mnemonics (top 5):
       1,468  ( 13.6%)  ADD16
  ...
```

## CTF event mapping

`ctf.py` reads the field layout of every event from the trace's CTF `metadata`
file (barectf format) and decodes by name, so it is not tied to hand-coded
offsets. The simulator emits these event types (not all appear in every trace):

| id | event | used by | key fields |
| --- | --- | --- | --- |
| 0 | `backpressure_trace_entry` | simperfetto | `cycle`, `tile_index`, `back_pressure` (level), `link` |
| 1 | `debug_counters_wavelet` | simperfetto | `PE_x/y`, `color`, `count_w/t/s` |
| 2 | `hwm_dispatch_trace_entry` | all | `cycle`, `inst_ptr` (word addr), `inst_bin`, `task_color`, `term_op`, mnemonic |
| 3 | `hwm_pipe_trace_entry` | simtrace, simperfetto | `uid`, `dest/src0/src1/src2` (stage 6 only) |
| 4 | `switch_pos_trace_entry` | simperfetto | `tile_index`, `color`, `input/output_pos/mask` |
| 5 | `wavelet_entry` | simtrace, simperfetto | `PE_x/y`, `color`, `wvlt_cnt/idx/data`, `event_type` |
| 6 | `wavelet_trace_entry` | simperfetto | `cycle`, `ident`, `tile_index`, `index`, `data`, `fields` |

- **id 2** (dispatch) is the source for the flamegraph and `simtrace`'s instruction views.
- **id 3** (pipe) emits several records per instruction, one per pipeline stage; only **stage 6** (writeback) carries resolved operand values (`dest`, `src0`, `src1`, `src2`) — earlier stages are `0xFFFFFFFF` sentinels. `uid` links a pipe record back to its dispatch.
- **wavelets** come as either id 5 (`wavelet_entry`) or id 6 (`wavelet_trace_entry`) depending on the simulator build; `simperfetto` handles both, while `simtrace wavelets` covers id 5.

## Coroutine-enabled CSL
Vanilla CSL has no coroutines: a task runs to its termination, and the next activation of that task re-enters it at its entry point. The transpiler developed at TU Darmstadt adds support for coroutines to CSL, significantly simplifying  programming the WSE. Its stackful backend gives each `async task` its own stack. Users can suspend the current task with `@suspend()`, which spills registers,  saves the stack pointer and resume address and terminates the current task. When the task is resumed, the stack and registers are restored and the program  continues after the `@suspend()` call as usual. The transpiler and the extended  language standard are expected to be released soon. 

## Notes

- Instruction pointers in the trace are **word addresses** (1 word = 2 bytes). `simtrace` multiplies by 2 when looking up the byte address used by llvm-objdump / ELF symbols.
- The `elf@ip` column is the static disassembly at the trace's `inst_ptr`. It can be empty for addresses below `.text` (where the runtime injects code dynamically) and can disagree with the trace's `trace_op` at branch boundaries due to pipeline-stage offsets in how the simulator reports `inst_ptr`. The trace's `inst_bin` + `trace_op` are authoritative for "what was actually executed".
- The `elf@ip` column is populated by `llvm-objdump`. Because the Cerebras CSL toolchain ships its own `llvm-objdump` (a stock LLVM binary will not decode CS instructions), the column is **off by default**. Pass `--objdump /path/to/cerebras-llvm-objdump` to enable it; `simtrace` will hard-error if the path is wrong. Without it, the trace's `inst_bin` (raw bytes) and `trace_op` (mnemonic) still give you the full picture of what executed.

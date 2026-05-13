# Cerebras simtracer

Tools for inspecting Cerebras simulator CTF traces. Two complementary commands:

- **`simflame`** — converts a trace into a [speedscope](https://www.speedscope.app/) flamegraph for whole-program / multi-tile call-stack visualization.
- **`simtrace`** — interactive per-PE instruction trace viewer: cycle ranges, function-entry hits, per-task / per-mnemonic stats, and resolved operand values from the pipeline trace.

Both share a CTF parser (`ctf.py`) and an ELF symbol cache.

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

`simtrace` uses two CTF event types from the simulator:

- **`hwm_dispatch_trace_entry`** (id 2) — one record per dispatched instruction; carries `cycle`, `inst_ptr` (word address), `inst_bin` (raw bytes), `task_color`, `term_op`, and the mnemonic. This is the same source `simflame` uses.
- **`hwm_pipe_trace_entry`** (id 3) — several records per dispatched instruction, one per pipeline stage. Stage 6 (writeback) carries the resolved operand values (`dest`, `src0`, `src1`, `src2`). Earlier stages contain `0xFFFFFFFF` sentinels and are ignored. The `uid` field links these back to the dispatch event.

## Notes

- Instruction pointers in the trace are **word addresses** (1 word = 2 bytes). `simtrace` multiplies by 2 when looking up the byte address used by llvm-objdump / ELF symbols.
- The `elf@ip` column is the static disassembly at the trace's `inst_ptr`. It can be empty for addresses below `.text` (where the runtime injects code dynamically) and can disagree with the trace's `trace_op` at branch boundaries due to pipeline-stage offsets in how the simulator reports `inst_ptr`. The trace's `inst_bin` + `trace_op` are authoritative for "what was actually executed".
- The `elf@ip` column is populated by `llvm-objdump`. Because the Cerebras CSL toolchain ships its own `llvm-objdump` (a stock LLVM binary will not decode CS instructions), the column is **off by default**. Pass `--objdump /path/to/cerebras-llvm-objdump` to enable it; `simtrace` will hard-error if the path is wrong. Without it, the trace's `inst_bin` (raw bytes) and `trace_op` (mnemonic) still give you the full picture of what executed.

#!/usr/bin/env python3
"""
simtrace: Inspect a Cerebras simulator instruction trace for a specific PE.

Subcommands:
  tiles    — list tiles that have trace events, with their ELF
  show     — print the instruction trace for a tile in a cycle range, with
             disassembly (via llvm-objdump) and optional operand values
  find     — list cycles where a given function was entered (or any
             instruction matched a filter)
  stats    — per-task / per-function / per-instruction breakdowns for a tile
  regs     — dump resolved operand values (dest/src0/src1/src2) per instruction

Instruction pointers in the CTF trace are word addresses (one word = 2 bytes).
llvm-objdump prints byte addresses, so we multiply by 2 when looking up an
instruction by trace inst_ptr.

The pipe-trace events (id=3) emit several entries per dispatched instruction
(one per pipeline stage). Only stage=6 carries resolved operand values; the
earlier stages contain 0xFFFFFFFF / 0xFF sentinels. We always use stage=6
when correlating with a dispatch by uid.
"""

import argparse
import fnmatch
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass

from tqdm import tqdm

import ctf
from ctf import (
    DispatchEvent,
    PipeEvent,
    WaveletTraceEvent,
    PIPE_WRITEBACK_STAGE,
    PIPE_NO_VALUE_U32,
    PIPE_NO_VALUE_U8,
    parse_ctf_stream,
    parse_ctf_trace,
    parallel_streams,
    load_all_elf_lookups,
    build_elf_mapping,
    read_grid_dims,
    resolve_bin_root,
    resolve_trace_dir,
    stream_paths,
    streams_for_tiles,
    streams_total_size,
)


# --------------------------------------------------------------------------- #
#  llvm-objdump disassembly cache
# --------------------------------------------------------------------------- #

# Disassembly line emitted by llvm-objdump, e.g.:
#     2a8: 38 e0        	movri	r7 = 384
# Address (hex) at the front, then the raw bytes, then a tab, then the asm.
_DISASM_LINE = re.compile(r"^\s*([0-9a-fA-F]+):\s+([0-9a-fA-F]{2}(?:\s[0-9a-fA-F]{2})*)\s+(.*)$")
_SECTION_LINE = re.compile(r"^Disassembly of section (\S+):")

# Sections we trust to contain real instructions. Cerebras ELFs put their code
# in .text plus a family of task-table sections used for HW-dispatched
# trampolines / boot stubs.
_CODE_SECTION_PREFIXES = (".text", ".task_table", ".section.task_table",
                          ".section.sys_mod", ".entry_ival")


@dataclass
class DisasmLine:
    byte_addr: int
    raw_bytes: str   # space-separated hex like "38 e0"
    asm: str         # e.g. "movri\tr7 = 384"


class Disassembler:
    """Cached, full-file disassembly of an ELF for fast byte-address lookup.

    `objdump` may be None — in that case `lookup()` always returns None and
    callers should fall back to the trace's own mnemonic + inst_bin.
    """

    def __init__(self, elf_path, objdump):
        self.elf_path = elf_path
        self.objdump = objdump
        self._by_addr = {}   # byte_addr -> DisasmLine
        self._loaded = False

    def _load(self):
        if self._loaded:
            return
        self._loaded = True
        if self.objdump is None:
            return
        try:
            out = subprocess.check_output(
                [self.objdump, "-D", self.elf_path],
                text=True, errors="replace",
            )
        except (FileNotFoundError, subprocess.CalledProcessError) as e:
            raise SystemExit(
                f"--objdump {self.objdump!r} failed to disassemble "
                f"{self.elf_path}: {e}"
            )
        in_code = False
        for line in out.splitlines():
            ms = _SECTION_LINE.match(line)
            if ms:
                section = ms.group(1)
                in_code = any(section.startswith(p) for p in _CODE_SECTION_PREFIXES)
                continue
            if not in_code:
                continue
            m = _DISASM_LINE.match(line)
            if not m:
                continue
            addr = int(m.group(1), 16)
            asm = m.group(3).rstrip()
            # Normalize tabs -> spaces for clean column alignment.
            asm = "  ".join(s for s in asm.split("\t") if s)
            # Disassemble-all produces duplicates when sections overlap at low
            # addresses; the first match (lowest section) wins. Prefer .text
            # by overwriting only when we don't have an entry yet.
            self._by_addr.setdefault(addr, DisasmLine(addr, m.group(2), asm))

    def lookup(self, byte_addr):
        """Return DisasmLine or None."""
        self._load()
        return self._by_addr.get(byte_addr)


# --------------------------------------------------------------------------- #
#  Per-tile collection
# --------------------------------------------------------------------------- #

def resolve_tile(tile_arg, grid_width):
    """Accept either an int tile index or 'x.y' coordinate string."""
    if "." in tile_arg or "," in tile_arg:
        sep = "." if "." in tile_arg else ","
        x_str, y_str = tile_arg.split(sep, 1)
        return int(y_str) * grid_width + int(x_str)
    return int(tile_arg)


def parse_cycle_range(s):
    """Parse 'A:B', 'A:', ':B', or 'A' into (start, end) — both inclusive-start, exclusive-end."""
    if s is None:
        return None
    if ":" not in s:
        c = int(s)
        return (c, c + 1)
    a, b = s.split(":", 1)
    start = int(a) if a else None
    end = int(b) if b else None
    if start is None:
        start = 0
    return (start, end)


@dataclass
class TileTrace:
    """All dispatch (and optionally pipe) events for a single tile in cycle range."""
    tile_index: int
    dispatch: list   # list[DispatchEvent], in cycle order
    pipe_by_uid: dict  # uid -> PipeEvent at stage=PIPE_WRITEBACK_STAGE (or None)

    def __post_init__(self):
        # Some indexes for fast queries.
        self._cycle_index = [e.cycle for e in self.dispatch]


def collect_tile_trace(trace_dir, tile_index, *, cycle_range=None,
                       want_pipe=False, show_progress=True):
    """Stream the relevant CTF file once, keeping only events for `tile_index`.

    Reads only the stream file holding `tile_index` (from the streamMap)."""
    paths = streams_for_tiles(trace_dir, {tile_index})
    file_size = streams_total_size(paths)
    pbar = (tqdm(total=file_size, unit="B", unit_scale=True, desc="reading trace",
                 file=sys.stderr) if show_progress else None)

    dispatch = []
    pipe_by_uid = {}

    want_ids = (2, 3) if want_pipe else (2,)
    for evt in parse_ctf_trace(
        trace_dir, want_ids=want_ids, tile_filter={tile_index}, progress=pbar,
        cycle_range=cycle_range,
    ):
        if isinstance(evt, DispatchEvent):
            dispatch.append(evt)
        elif want_pipe and isinstance(evt, PipeEvent):
            if evt.stage == PIPE_WRITEBACK_STAGE:
                pipe_by_uid[evt.uid] = evt

    if pbar is not None:
        pbar.close()

    return TileTrace(tile_index=tile_index, dispatch=dispatch,
                     pipe_by_uid=pipe_by_uid)


# --------------------------------------------------------------------------- #
#  Setup shared by subcommands
# --------------------------------------------------------------------------- #

@dataclass
class Context:
    out_dir: str
    trace_dir: str
    grid_width: int
    grid_height: int
    elf_lookups: dict       # elf_path -> SymbolLookup
    tile_elf_mapping: dict  # tile_index -> elf_path
    objdump: str

    def lookup_for(self, tile_index):
        path = self.tile_elf_mapping.get(tile_index)
        if path is None:
            raise SystemExit(f"No ELF mapped for tile {tile_index}")
        return path, self.elf_lookups[path]


def setup_context(args):
    if not os.path.isdir(args.out_dir):
        raise SystemExit(f"Not a directory: {args.out_dir}")
    try:
        trace_dir = resolve_trace_dir(args.out_dir, args.trace_dir)
        bin_root = resolve_bin_root(args.out_dir, args.bin_root)
    except FileNotFoundError as e:
        raise SystemExit(str(e))
    grid_width, grid_height = read_grid_dims(trace_dir)
    elf_lookups, _arch = load_all_elf_lookups(bin_root, verbose=args.verbose)
    if not elf_lookups:
        raise SystemExit("No ELF files with function symbols found")
    tile_elf_mapping = build_elf_mapping(elf_lookups, grid_width,
                                         verbose=args.verbose, quiet=args.quiet)
    return Context(
        out_dir=args.out_dir, trace_dir=trace_dir,
        grid_width=grid_width, grid_height=grid_height,
        elf_lookups=elf_lookups, tile_elf_mapping=tile_elf_mapping,
        objdump=args.objdump,
    )


# --------------------------------------------------------------------------- #
#  Subcommand: tiles
# --------------------------------------------------------------------------- #

def _count_tiles_worker(path, metadata_path):
    """Count dispatch events per tile in one stream (runs in a worker process)."""
    counts = Counter()
    for evt in parse_ctf_stream(path, want_ids=(2,), metadata_path=metadata_path):
        counts[evt.tile_index] += 1
    return counts


def cmd_tiles(args, ctx):
    """List tiles that appear in the trace (with their ELF and event count)."""
    paths = stream_paths(ctx.trace_dir)
    metadata_path = os.path.join(ctx.trace_dir, "metadata")
    counts = Counter()
    # Pure per-tile count aggregation — each stream is counted in its own
    # process and the per-stream Counters are summed here.
    pbar = (tqdm(total=len(paths), unit="stream", desc="scanning",
                 file=sys.stderr) if not args.quiet else None)
    for _path, c in parallel_streams(paths, _count_tiles_worker,
                                     args=(metadata_path,), jobs=args.jobs):
        counts.update(c)
        if pbar is not None:
            pbar.update(1)
    if pbar is not None:
        pbar.close()

    print(f"Available tiles (grid {ctx.grid_width}x{ctx.grid_height}):")
    print(f"  {'tile':>5}  {'coord':<7} {'events':>10}  ELF")
    for tile_idx in sorted(counts):
        x = tile_idx % ctx.grid_width
        y = tile_idx // ctx.grid_width
        elf_path = ctx.tile_elf_mapping.get(tile_idx)
        elf_name = os.path.basename(elf_path) if elf_path else "<unmapped>"
        print(f"  {tile_idx:>5}  P{x}.{y:<5} {counts[tile_idx]:>10,}  {elf_name}")


# --------------------------------------------------------------------------- #
#  Subcommand: show
# --------------------------------------------------------------------------- #

def _fmt_operand_value(v, width=8):
    if v == PIPE_NO_VALUE_U32:
        return "-".rjust(width)
    return f"0x{v:0{width}x}"


def _fmt_pipe_operands(pe):
    """Compact operand summary like 'd=0x.. s0=0x.. s1=0x..'."""
    if pe is None:
        return ""
    parts = []
    if pe.dest != PIPE_NO_VALUE_U32:
        parts.append(f"d={pe.dest:#x}")
    if pe.src0 != PIPE_NO_VALUE_U32:
        parts.append(f"s0={pe.src0:#x}")
    if pe.src1 != PIPE_NO_VALUE_U32:
        parts.append(f"s1={pe.src1:#x}")
    if pe.src2 != PIPE_NO_VALUE_U32:
        parts.append(f"s2={pe.src2:#x}")
    if pe.imm != PIPE_NO_VALUE_U8:
        parts.append(f"imm={pe.imm:#x}")
    return " ".join(parts)


def cmd_show(args, ctx):
    tile = resolve_tile(args.tile, ctx.grid_width)
    cyc_range = parse_cycle_range(args.cycles)
    elf_path, lookup = ctx.lookup_for(tile)
    disasm = (None if args.no_disasm or ctx.objdump is None
              else Disassembler(elf_path, objdump=ctx.objdump))

    trace = collect_tile_trace(
        ctx.trace_dir, tile, cycle_range=cyc_range,
        want_pipe=args.regs, show_progress=not args.quiet,
    )

    if args.func:
        pat = args.func
        keep = lambda fn: fnmatch.fnmatchcase(fn, pat) or pat in fn
    else:
        keep = None

    # Header. Flags column: E = function-entry hit; T = task terminator.
    # `trace_op`  = mnemonic reported by the simulator (what was executed)
    # `elf@ip`    = static disassembly at byte address ip in the ELF
    # These can differ at branches / for runtime-injected code (init below .text).
    print(f"{'cycle':>8}  {'task':>3}  {'ip':>10}  {'flags':<5}  "
          f"{'function':<42}  {'inst_bin':>10}  {'trace_op':<10}  "
          f"{'elf@ip':<32}{'operands' if args.regs else ''}".rstrip())

    # Limit
    n_emitted = 0
    last_func = None
    for evt in trace.dispatch:
        fn, is_entry = lookup.lookup(evt.inst_ptr * 2)
        if keep is not None and not keep(fn):
            continue

        # Show function header line when function changes (callsite hint)
        if args.group_funcs and fn != last_func:
            print(f"  --- {fn} ---")
            last_func = fn

        dl = disasm.lookup(evt.inst_ptr * 2) if disasm else None
        ip_str = f"0x{evt.inst_ptr * 2:08x}"
        flags = ("E" if is_entry else " ") + ("T" if evt.term_op == 1 else " ")
        inst_bin_str = f"0x{evt.inst_bin:08x}"
        asm_str = dl.asm if dl else "—"
        row = (f"{evt.cycle:>8}  {evt.task_color:>3}  {ip_str:>10}  "
               f"{flags:<5}  {fn:<42}  {inst_bin_str:>10}  {evt.name:<10}  "
               f"{asm_str:<32}")
        if args.regs:
            pe = trace.pipe_by_uid.get(evt.uid)
            row += _fmt_pipe_operands(pe)
        print(row.rstrip())

        n_emitted += 1
        if args.limit and n_emitted >= args.limit:
            print(f"  ... (limit {args.limit} reached)", file=sys.stderr)
            break

    if not n_emitted:
        print("(no events match filter)", file=sys.stderr)


# --------------------------------------------------------------------------- #
#  Subcommand: find
# --------------------------------------------------------------------------- #

def cmd_find(args, ctx):
    tile = resolve_tile(args.tile, ctx.grid_width)
    cyc_range = parse_cycle_range(args.cycles)
    _elf_path, lookup = ctx.lookup_for(tile)

    pattern = args.func
    candidates = lookup.find_by_pattern(pattern)
    if not candidates:
        print(f"No function matching '{pattern}' in tile {tile}'s ELF", file=sys.stderr)
        # Show near matches
        print("Nearest names:", file=sys.stderr)
        for f in sorted(lookup.functions, key=lambda f: f.name)[:10]:
            print(f"  {f.name}", file=sys.stderr)
        return 1

    entry_addrs = {f.start: f.name for f in candidates}
    print(f"Tracking {len(candidates)} function(s) matching '{pattern}' on tile {tile}:",
          file=sys.stderr)
    for f in candidates:
        print(f"  {f.name}  @ 0x{f.start:06x}  (size {f.size})", file=sys.stderr)

    paths = streams_for_tiles(ctx.trace_dir, {tile})
    pbar = (tqdm(total=streams_total_size(paths), unit="B", unit_scale=True,
                 desc="scanning", file=sys.stderr) if not args.quiet else None)

    print(f"{'cycle':>10}  {'task':>4}  function  (uid)")
    last_func_per_cycle = None
    hit_count = 0
    for evt in parse_ctf_trace(ctx.trace_dir, tile_filter={tile}, progress=pbar,
                               cycle_range=cyc_range):
        addr = evt.inst_ptr * 2
        if addr in entry_addrs:
            fn = entry_addrs[addr]
            print(f"{evt.cycle:>10}  {evt.task_color:>4}  {fn}  (uid={evt.uid})")
            hit_count += 1
            if args.limit and hit_count >= args.limit:
                break
    if pbar is not None:
        pbar.close()
    print(f"Total entries: {hit_count}", file=sys.stderr)


# --------------------------------------------------------------------------- #
#  Subcommand: stats
# --------------------------------------------------------------------------- #

def cmd_stats(args, ctx):
    tile = resolve_tile(args.tile, ctx.grid_width)
    cyc_range = parse_cycle_range(args.cycles)
    _elf_path, lookup = ctx.lookup_for(tile)
    trace = collect_tile_trace(
        ctx.trace_dir, tile, cycle_range=cyc_range,
        want_pipe=False, show_progress=not args.quiet,
    )

    if not trace.dispatch:
        print("No dispatch events in selected range", file=sys.stderr)
        return 1

    first = trace.dispatch[0].cycle
    last = trace.dispatch[-1].cycle
    total = len(trace.dispatch)

    # Per-task counts (count of dispatch cycles per task_color)
    by_task = Counter()
    by_func = Counter()
    by_mnemonic = Counter()
    by_task_terms = Counter()
    for evt in trace.dispatch:
        by_task[evt.task_color] += 1
        fn, _ = lookup.lookup(evt.inst_ptr * 2)
        by_func[fn] += 1
        by_mnemonic[evt.name] += 1
        if evt.term_op == 1:
            by_task_terms[evt.task_color] += 1

    print(f"Tile {tile}:  events={total:,}  cycles {first}..{last} (span {last-first+1})")
    print()
    print(f"Tasks (top {args.top}):")
    for color, n in by_task.most_common(args.top):
        print(f"  task {color:>3}: {n:>10,}  ({100*n/total:5.1f}%)  terms={by_task_terms.get(color, 0)}")
    print()
    print(f"Functions by dispatched instructions (top {args.top}):")
    for name, n in by_func.most_common(args.top):
        print(f"  {n:>10,}  ({100*n/total:5.1f}%)  {name}")
    print()
    print(f"Instruction mnemonics (top {args.top}):")
    for name, n in by_mnemonic.most_common(args.top):
        print(f"  {n:>10,}  ({100*n/total:5.1f}%)  {name}")

    if args.func_timeline:
        # Count entries (first-instruction hits) per function, useful for hot loops
        entries_by_func = Counter()
        prev_func = None
        for evt in trace.dispatch:
            fn, is_entry = lookup.lookup(evt.inst_ptr * 2)
            if is_entry and fn != prev_func:
                entries_by_func[fn] += 1
            prev_func = fn
        print()
        print(f"Function entry hits (top {args.top}):")
        for name, n in entries_by_func.most_common(args.top):
            print(f"  {n:>10,}  {name}")


# --------------------------------------------------------------------------- #
#  Subcommand: regs
# --------------------------------------------------------------------------- #

def cmd_regs(args, ctx):
    """Dump per-instruction operand values (from pipe-trace stage=6)."""
    tile = resolve_tile(args.tile, ctx.grid_width)
    cyc_range = parse_cycle_range(args.cycles)
    elf_path, lookup = ctx.lookup_for(tile)
    disasm = (Disassembler(elf_path, objdump=ctx.objdump)
              if ctx.objdump is not None else None)

    trace = collect_tile_trace(
        ctx.trace_dir, tile, cycle_range=cyc_range,
        want_pipe=True, show_progress=not args.quiet,
    )

    n_with_values = sum(1 for pe in trace.pipe_by_uid.values()
                        if pe.dest != PIPE_NO_VALUE_U32 or
                           pe.src0 != PIPE_NO_VALUE_U32 or
                           pe.src1 != PIPE_NO_VALUE_U32 or
                           pe.src2 != PIPE_NO_VALUE_U32)
    print(f"# {len(trace.dispatch):,} dispatched, "
          f"{len(trace.pipe_by_uid):,} pipe records, "
          f"{n_with_values:,} with resolved values", file=sys.stderr)

    print(f"{'cycle':>8}  {'ip':>8}  {'mnemonic':<10}  {'dest':>10}  "
          f"{'src0':>10}  {'src1':>10}  {'src2':>10}  function / asm")

    for evt in trace.dispatch:
        pe = trace.pipe_by_uid.get(evt.uid)
        if pe is None:
            continue
        if args.only_values and (pe.dest == PIPE_NO_VALUE_U32 and
                                 pe.src0 == PIPE_NO_VALUE_U32 and
                                 pe.src1 == PIPE_NO_VALUE_U32 and
                                 pe.src2 == PIPE_NO_VALUE_U32):
            continue
        fn, _ = lookup.lookup(evt.inst_ptr * 2)
        dl = disasm.lookup(evt.inst_ptr * 2) if disasm else None
        asm = dl.asm if dl else ""
        print(f"{evt.cycle:>8}  0x{evt.inst_ptr*2:06x}  {evt.name:<10}  "
              f"{_fmt_operand_value(pe.dest)}  {_fmt_operand_value(pe.src0)}  "
              f"{_fmt_operand_value(pe.src1)}  {_fmt_operand_value(pe.src2)}  "
              f"{fn} | {asm}")


# --------------------------------------------------------------------------- #
#  Subcommand: funcs
# --------------------------------------------------------------------------- #

def cmd_wavelets(args, ctx):
    """Show per-wavelet fabric events (`wavelet_trace_entry`, id=6) for a tile."""
    tile = resolve_tile(args.tile, ctx.grid_width)
    pe_x = tile % ctx.grid_width
    pe_y = tile // ctx.grid_width
    cyc_range = parse_cycle_range(args.cycles)

    colors = None
    if args.colors:
        colors = set(int(c, 0) for c in args.colors.split(","))

    paths = streams_for_tiles(ctx.trace_dir, {tile})
    pbar = (tqdm(total=streams_total_size(paths), unit="B", unit_scale=True,
                 desc="scanning", file=sys.stderr) if not args.quiet else None)

    print(f"# tile P{pe_x}.{pe_y} (PE_x={pe_x}, PE_y={pe_y})  tile_index={tile}")
    print(f"{'cycle':>10}  {'index':>6}  {'data':>6}  {'fields':>12}  {'ident':>20}")

    # SDK 2.1+ emits the wavelet stream as id=6 `wavelet_trace_entry`, keyed by
    # tile_index. `index` is the color/route slot; honour --colors against it.
    count = 0
    for evt in parse_ctf_trace(ctx.trace_dir, want_ids=(6,), progress=pbar,
                               tile_filter={tile}, cycle_range=cyc_range):
        if not isinstance(evt, WaveletTraceEvent):
            continue
        if colors is not None and evt.index not in colors:
            continue
        print(f"{evt.cycle:>10}  {evt.index:>6}  0x{evt.data:04x}  "
              f"0x{evt.fields:010x}  0x{evt.ident:016x}")
        count += 1
        if args.limit and count >= args.limit:
            break

    if pbar is not None:
        pbar.close()
    print(f"# {count} wavelet event(s)", file=sys.stderr)


def cmd_funcs(args, ctx):
    """List functions known in the ELF for a given tile (optionally matching a pattern)."""
    tile = resolve_tile(args.tile, ctx.grid_width)
    _elf_path, lookup = ctx.lookup_for(tile)
    pat = args.pattern
    matches = [f for f in lookup.functions
               if pat is None or pat in f.name or fnmatch.fnmatchcase(f.name, pat)]
    matches.sort(key=lambda f: f.start)
    print(f"{'start':>10}  {'size':>6}  name")
    for f in matches:
        print(f"  0x{f.start:06x}  {f.size:>6}  {f.name}")
    print(f"({len(matches)} function(s))", file=sys.stderr)


# --------------------------------------------------------------------------- #
#  Subcommand: which  (coordinate -> ELF, and edge-vs-interior disassembly diff)
# --------------------------------------------------------------------------- #

def _disasm_by_func(elf_path, objdump):
    """{func_name: [normalized asm lines]} from `objdump -D`. The leading address and
    machine-byte columns are dropped and hex address/immediate literals are masked to `0x_`,
    so two PEs that run the SAME code at different placements compare equal — only real
    instruction differences (edge specialization, a logic change) survive."""
    import subprocess, re
    out = subprocess.run([objdump, "-D", elf_path],
                         capture_output=True, text=True, check=True).stdout
    hdr  = re.compile(r'^[0-9a-fA-F]+\s+<(.+)>:\s*$')
    insn = re.compile(r'^\s*[0-9a-fA-F]+:\s+(?:[0-9a-fA-F]{2} )+\s*(\S.*?)\s*$')
    # Mask operands that legitimately differ between two identical-logic PEs at different
    # placements: hex literals, bracketed addresses [N], and any decimal >= 100 (data/code
    # addresses). Small decimals (shift amounts, lane counts) are kept — a change there is real.
    hexl = re.compile(r'0x[0-9a-fA-F]+')
    addr = re.compile(r'\[\s*\d+\s*\]')
    dec  = re.compile(r'(?<![\w.])\d{3,}(?![\w.])')
    def norm(s):
        s = hexl.sub("0x_", s)
        s = addr.sub("[_]", s)
        s = dec.sub("_", s)
        return s
    funcs, cur = {}, None
    for line in out.splitlines():
        h = hdr.match(line)
        if h:
            cur = h.group(1); funcs.setdefault(cur, [])
            continue
        m = insn.match(line)
        if m and cur is not None:
            funcs[cur].append(norm(m.group(1)))
    return funcs


def _print_disasm_diff(a, b, objdump, func_pat):
    import difflib, fnmatch
    (ca, _, pa, na), (cb, _, pb, nb) = a, b
    fa, fb = _disasm_by_func(pa, objdump), _disasm_by_func(pb, objdump)
    names = sorted(set(fa) | set(fb))
    if func_pat:
        names = [n for n in names if func_pat in n or fnmatch.fnmatchcase(n, func_pat)]
    any_diff = False
    for name in names:
        la, lb = fa.get(name, []), fb.get(name, [])
        if la == lb:
            continue
        any_diff = True
        print(f"\n=== function {name}: DIFFERS  ({ca}:{na}  vs  {cb}:{nb}) ===")
        for dl in difflib.unified_diff(la, lb, fromfile=f"{ca}:{na}",
                                       tofile=f"{cb}:{nb}", lineterm=""):
            print(dl)
    if not any_diff:
        print(f"\nNo instruction-level differences between {ca}({na}) and {cb}({nb}) "
              f"in the compared function(s) — address/immediate literals masked.")


def cmd_which(args):
    """Map coordinate(s) to the ELF that runs there (works on a bare out/ dir — no trace)."""
    try:
        bin_root = resolve_bin_root(args.out_dir, args.bin_root)
    except FileNotFoundError as e:
        raise SystemExit(str(e))
    gw = args.grid_width or 762   # WSE-3 fabric width; override with --grid-width
    elf_lookups, _arch = load_all_elf_lookups(bin_root, verbose=args.verbose)
    if not elf_lookups:
        raise SystemExit("No ELF files found under " + bin_root)
    mapping = build_elf_mapping(elf_lookups, gw, quiet=True)
    resolved = []
    for c in args.coords:
        tile = resolve_tile(c, gw)
        path = mapping.get(tile)
        name = os.path.basename(path) if path else "?? (unmapped)"
        print(f"  {c:>10}  tile {tile:>8}  (x={tile % gw}, y={tile // gw})  ->  {name}")
        resolved.append((c, tile, path, name))
    if args.diff:
        if len(resolved) != 2:
            raise SystemExit("--diff needs exactly two coordinates")
        if not args.objdump:
            raise SystemExit("--diff needs --objdump (the Cerebras llvm-objdump wrapper)")
        if not resolved[0][2] or not resolved[1][2]:
            raise SystemExit("a coordinate is unmapped — cannot diff")
        _print_disasm_diff(resolved[0], resolved[1], args.objdump, args.func)
    return 0


# --------------------------------------------------------------------------- #
#  Argument parser
# --------------------------------------------------------------------------- #

def build_argparser():
    parser = argparse.ArgumentParser(
        prog="simtrace",
        description="Inspect a Cerebras simulator instruction trace per PE.",
    )
    parser.add_argument("out_dir", help="Path to simulator out/ or workdir")
    parser.add_argument("--trace-dir", default=None,
                        help="Override path to simfab_traces/")
    parser.add_argument("--bin-root", default=None,
                        help="Override the directory containing bin/*.elf "
                             "(plus optional east/, west/)")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--quiet", action="store_true",
                        help="Suppress progress bar")
    parser.add_argument("-j", "--jobs", type=int, default=None,
                        help="Parallel worker processes for whole-trace scans "
                             "(the 'tiles' command). Default: one per stream, "
                             "capped at the CPU count. Use 1 to run serially.")
    parser.add_argument("--objdump", default=None,
                        help="Path to llvm-objdump (Cerebras toolchain). When "
                             "omitted, the disassembly column is left empty "
                             "and the trace's own mnemonic + inst_bin are used.")

    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("tiles", help="List tiles in the trace")
    p.set_defaults(handler=cmd_tiles)

    p = sub.add_parser("show", help="Print instruction trace for a tile")
    p.add_argument("--tile", required=True, help="Tile index N or 'x.y' coord")
    p.add_argument("--cycles", help="Cycle range A:B (e.g. 100:200, 100:, :200, 100)")
    p.add_argument("--func", help="Only show events whose function name matches "
                                  "(substring or fnmatch pattern)")
    p.add_argument("--regs", action="store_true",
                   help="Append resolved operand values from pipe trace")
    p.add_argument("--no-disasm", action="store_true",
                   help="Skip llvm-objdump disassembly column")
    p.add_argument("--group-funcs", action="store_true",
                   help="Print a header line each time the function changes")
    p.add_argument("--limit", type=int, default=0,
                   help="Stop after N rows (0 = no limit)")
    p.set_defaults(handler=cmd_show)

    p = sub.add_parser("find", help="Cycles where a function was entered")
    p.add_argument("--tile", required=True, help="Tile index N or 'x.y' coord")
    p.add_argument("--func", required=True,
                   help="Function-name substring to match")
    p.add_argument("--cycles", help="Restrict to cycle range A:B")
    p.add_argument("--limit", type=int, default=0,
                   help="Stop after N hits (0 = no limit)")
    p.set_defaults(handler=cmd_find)

    p = sub.add_parser("stats", help="Per-task / per-function / per-mnemonic breakdown")
    p.add_argument("--tile", required=True, help="Tile index N or 'x.y' coord")
    p.add_argument("--cycles", help="Restrict to cycle range A:B")
    p.add_argument("--top", type=int, default=15, help="How many rows per table")
    p.add_argument("--func-timeline", action="store_true",
                   help="Also report function-entry hit counts")
    p.set_defaults(handler=cmd_stats)

    p = sub.add_parser("regs", help="Per-instruction operand values (pipe-trace stage=6)")
    p.add_argument("--tile", required=True, help="Tile index N or 'x.y' coord")
    p.add_argument("--cycles", help="Restrict to cycle range A:B")
    p.add_argument("--only-values", action="store_true",
                   help="Skip rows where no operand was resolved")
    p.set_defaults(handler=cmd_regs)

    p = sub.add_parser("funcs", help="List functions in the ELF for a tile")
    p.add_argument("--tile", required=True, help="Tile index N or 'x.y' coord")
    p.add_argument("--pattern", help="Filter by substring or fnmatch pattern")
    p.set_defaults(handler=cmd_funcs)

    p = sub.add_parser("which",
                       help="Map coordinate(s) to their ELF (no trace needed); "
                            "with --diff, compare two PEs' disassembly")
    p.add_argument("coords", nargs="+", help="One or more 'x.y' coordinates (or tile indices)")
    p.add_argument("--grid-width", type=int, default=None,
                   help="Fabric width for tile-index math (default 762 = WSE-3)")
    p.add_argument("--diff", action="store_true",
                   help="Disassemble the two given coordinates' ELFs and print a per-function "
                        "diff (address/immediate literals masked). Requires --objdump and exactly "
                        "two coordinates")
    p.add_argument("--func", default=None,
                   help="Restrict --diff to functions matching this substring/pattern")
    p.set_defaults(handler=cmd_which, no_trace=True)

    p = sub.add_parser("wavelets",
                       help="Show wavelet send/receive events for a tile")
    p.add_argument("--tile", required=True, help="Tile index N or 'x.y' coord")
    p.add_argument("--cycles", help="Restrict to cycle range A:B")
    p.add_argument("--colors",
                   help="Filter to specific color(s), comma-separated (decimal or 0x...)")
    p.add_argument("--limit", type=int, default=0,
                   help="Stop after N matching events (0 = no limit)")
    p.set_defaults(handler=cmd_wavelets)

    return parser


def main():
    parser = build_argparser()
    args = parser.parse_args()
    if getattr(args, "no_trace", False):     # commands that read only the ELFs (no CTF trace)
        rc = args.handler(args) or 0
    else:
        ctx = setup_context(args)
        rc = args.handler(args, ctx) or 0
    sys.exit(rc)


if __name__ == "__main__":
    main()

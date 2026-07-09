#!/usr/bin/env python3
"""
simperfetto: Convert Cerebras simulator CTF traces to a Perfetto protobuf trace.

Where simflame emits a speedscope flamegraph (call stacks only), simperfetto
targets Perfetto's richer model and exposes the rest of the CTF stream as
configurable channels. Open the output at https://ui.perfetto.dev.

Per tile, the trace contains a process group with these tracks:

  calls           flamegraph slices (task color as the outer frame, function
                  frames nested) — the same reconstruction simflame uses.
  dispatch/bin    counter: instructions dispatched per --bin-cycles window.
  wavelets/bin    counter: wavelet events per window (fabric activity).
  backpressure Ln counter: per-link fabric backpressure level. By default the
                  max per window (the trace has millions of samples); use
                  --backpressure-raw for every sample.
  wavelets        instant events per wavelet (id=6), carrying the
                  payload/identifier as annotations (opt-out; high volume).
                  When --flow is on, each wavelet's hops across the fabric are
                  linked by ident, so a forwarded wavelet ("train") shows as a
                  connected chain of arrows.
  router          instant events for switch-position changes (opt-in).
  reg.*           counters: resolved dest/src operand values (opt-in).
  dbg.* c<color>  counters: cumulative per-(PE,color) wavelet counts (opt-in).

Defaults: calls + dispatch/wavelet rate + binned backpressure + per-wavelet
events with flow linking. Disable any with --no-<channel>; enable the opt-in
ones individually or with --all.

Timestamps are simulator cycles written directly (the UI axis reads "ns";
1 tick = 1 cycle). Each tile is its own packet sequence, emitted in cycle
order, so per-track slice nesting and counter samples stay ordered.

Usage:
    python3 simperfetto.py <out_dir> -o trace.pftrace [--tiles 16,17] [--all]
"""

import argparse
import gzip
import os
import shutil
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass

from tqdm import tqdm

import perfetto_pb as pb
from callstack import reconstruct
from ctf import (
    DispatchEvent,
    WaveletTraceEvent,
    PipeEvent,
    BackpressureEvent,
    SwitchPosEvent,
    DebugCountersEvent,
    PIPE_WRITEBACK_STAGE,
    PIPE_NO_VALUE_U32,
    parse_ctf_stream,
    parallel_streams,
    load_all_elf_lookups,
    build_elf_mapping,
    read_grid_dims,
    resolve_bin_root,
    resolve_trace_dir,
    stream_paths,
    streams_for_tiles,
)


# --------------------------------------------------------------------------- #
#  Channel configuration
# --------------------------------------------------------------------------- #

@dataclass
class Channels:
    calls: bool = True
    dispatch_rate: bool = True
    wavelet_rate: bool = True
    backpressure: bool = True
    backpressure_raw: bool = False
    wavelet_events: bool = True
    switch_pos: bool = False
    regs: bool = False
    debug_counters: bool = False
    flow: bool = True

    @property
    def want_wavelets(self):
        return self.wavelet_rate or self.wavelet_events or self.flow

    def want_ids(self):
        ids = set()
        if self.calls or self.dispatch_rate:
            ids.add(2)
        if self.backpressure:
            ids.add(0)
        if self.want_wavelets:
            ids.add(6)
        if self.regs:
            ids.add(3)
        if self.switch_pos:
            ids.add(4)
        if self.debug_counters:
            ids.add(1)
        ids.add(2)  # always need dispatch for tile discovery / a non-empty trace
        return tuple(sorted(ids))


# --------------------------------------------------------------------------- #
#  Per-bin counter accumulator
# --------------------------------------------------------------------------- #

class Binner:
    """Aggregates a value per fixed-width cycle bin and emits counter samples.

    agg="sum" counts events (for rates); agg="max" tracks a level's envelope.
    With gap_zero, the counter drops to 0 across empty windows so rates read
    honestly; levels (max) instead hold their last value.
    """

    def __init__(self, writer, track_uuid, seq, bin_cycles, agg="sum",
                 gap_zero=True):
        self.w = writer
        self.uuid = track_uuid
        self.seq = seq
        self.bin = bin_cycles
        self.is_sum = agg == "sum"
        self.gap_zero = gap_zero
        self.cur_bin = None
        self.acc = 0 if self.is_sum else None

    def _sample(self, bin_idx, value):
        self.w.event(pb.track_event(self.uuid, pb.TYPE_COUNTER,
                                    counter_value=value),
                     self.seq, bin_idx * self.bin)

    def add(self, cycle, value=1):
        b = cycle // self.bin
        if self.cur_bin is None:
            self.cur_bin = b
        elif b != self.cur_bin:
            if self.acc is not None:
                self._sample(self.cur_bin, self.acc)
            if self.gap_zero and b > self.cur_bin + 1:
                self._sample(self.cur_bin + 1, 0)
            self.cur_bin = b
            self.acc = 0 if self.is_sum else None
        if self.is_sum:
            self.acc += value
        else:
            self.acc = value if self.acc is None else max(self.acc, value)

    def close(self):
        if self.cur_bin is not None and self.acc is not None:
            self._sample(self.cur_bin, self.acc)


# --------------------------------------------------------------------------- #
#  Per-tile emitter
# --------------------------------------------------------------------------- #

class TileEmitter:
    """Owns one tile's process group and tracks, writing events to the writer.

    Tracks are allocated lazily so a tile only grows the tracks its events
    actually populate (e.g. a backpressure-only fabric tile gets no `calls`).
    """

    def __init__(self, writer, tile_idx, grid_width, channels, bin_cycles):
        self.w = writer
        self.ch = channels
        self.bin = bin_cycles
        x, y = tile_idx % grid_width, tile_idx // grid_width
        name = f"Tile {tile_idx} (P{x}.{y})"
        self.seq = tile_idx + 1
        self._base = (tile_idx + 1) * 1024
        self._next = self._base + 1
        self._tracks = {}
        writer.descriptor(
            pb.track_descriptor(self._base, name=name,
                                process=pb._process_descriptor(tile_idx + 1, name)),
            self.seq)

        self.calls_uuid = self._track("calls") if channels.calls else None
        self.disp = self._binner("dispatch/bin", "instr") if channels.dispatch_rate else None
        self.wrate = self._binner("wavelets/bin", "wvlt") if channels.wavelet_rate else None
        self.wevents_uuid = self._track("wavelets") if channels.wavelet_events else None
        self.router_uuid = self._track("router") if channels.switch_pos else None
        self._bp = {}    # link -> Binner (or uuid when raw)
        self._reg = {}   # field name -> uuid
        self._dbg = {}   # (color, which) -> uuid

    def _track(self, label, counter=None):
        u = self._tracks.get(label)
        if u is None:
            u = self._next
            self._next += 1
            self.w.descriptor(
                pb.track_descriptor(u, name=label, parent_uuid=self._base,
                                    counter=counter), self.seq)
            self._tracks[label] = u
        return u

    def _binner(self, label, unit, agg="sum", gap_zero=True):
        u = self._track(label, counter=pb._counter_descriptor(unit_name=unit))
        return Binner(self.w, u, self.seq, self.bin, agg=agg, gap_zero=gap_zero)

    # --- event emission ---

    def emit_slice(self, kind, label, cycle):
        type_ = pb.TYPE_SLICE_BEGIN if kind == "O" else pb.TYPE_SLICE_END
        self.w.event(
            pb.track_event(self.calls_uuid, type_, name=(label if kind == "O" else None)),
            self.seq, cycle)

    def emit_backpressure(self, evt):
        link = evt.link
        if self.ch.backpressure_raw:
            u = self._bp.get(link)
            if u is None:
                u = self._bp[link] = self._track(
                    f"backpressure L{link}",
                    counter=pb._counter_descriptor(unit_name="level"))
            self.w.event(pb.track_event(u, pb.TYPE_COUNTER,
                                        counter_value=evt.back_pressure),
                         self.seq, evt.cycle)
        else:
            bn = self._bp.get(link)
            if bn is None:
                bn = self._bp[link] = self._binner(
                    f"backpressure L{link}", "level", agg="max", gap_zero=False)
            bn.add(evt.cycle, evt.back_pressure)

    def emit_wavelet(self, evt):
        # WaveletTraceEvent (id=6) — the SDK 2.1+ per-wavelet fabric event.
        ann = {"ident": evt.ident, "index": evt.index,
               "data": f"0x{evt.data:04x}", "fields": evt.fields}
        name = f"w{evt.index}"
        flow = (evt.ident & 0xFFFFFFFFFFFFFFFF,) if self.ch.flow else ()
        self.w.event(
            pb.track_event(self.wevents_uuid, pb.TYPE_INSTANT, name=name,
                           flow_ids=flow, annotations=ann),
            self.seq, evt.cycle)

    def emit_switch(self, evt):
        ann = {"input_pos": evt.input_pos, "input_mask": evt.input_mask,
               "output_pos": evt.output_pos, "output_mask": evt.output_mask}
        self.w.event(
            pb.track_event(self.router_uuid, pb.TYPE_INSTANT,
                           name=f"c{evt.color}", annotations=ann),
            self.seq, evt.cycle)

    def emit_regs(self, evt):
        for field in ("dest", "src0", "src1", "src2"):
            val = getattr(evt, field)
            if val != PIPE_NO_VALUE_U32:
                u = self._reg.get(field)
                if u is None:
                    u = self._reg[field] = self._track(
                        f"reg.{field}", counter=pb._counter_descriptor(unit_name="value"))
                self.w.event(pb.track_event(u, pb.TYPE_COUNTER, counter_value=val),
                             self.seq, evt.cycle)

    def emit_debug(self, evt):
        for which, val in (("w", evt.count_w), ("t", evt.count_t), ("s", evt.count_s)):
            key = (evt.color, which)
            u = self._dbg.get(key)
            if u is None:
                u = self._dbg[key] = self._track(
                    f"dbg.count_{which} c{evt.color}",
                    counter=pb._counter_descriptor(unit_name="count"))
            self.w.event(pb.track_event(u, pb.TYPE_COUNTER, counter_value=val),
                         self.seq, evt.cycle)

    def close(self):
        for bn in (self.disp, self.wrate):
            if bn:
                bn.close()
        if not self.ch.backpressure_raw:
            for bn in self._bp.values():
                bn.close()


# --------------------------------------------------------------------------- #
#  Build
# --------------------------------------------------------------------------- #

def emit_stream(writer, base_iter, *, grid_width, channels, bin_cycles,
                tile_elf_mapping, elf_lookups):
    """Fold one event stream into ``writer`` as Perfetto packets.

    Each tile (and its per-track binners) lives in a single stream and is
    written as its own packet sequence, so this can run per-stream and the
    sequences concatenate into one valid trace. Returns ``(counts, num_tiles)``.
    """
    emitters = {}

    def emitter_for(tile_idx):
        em = emitters.get(tile_idx)
        if em is None:
            em = emitters[tile_idx] = TileEmitter(
                writer, tile_idx, grid_width, channels, bin_cycles)
        return em

    counts = Counter()

    def dispatch_stream():
        """Yield DispatchEvents while folding every other event into its track
        as a side effect — one pass over the file feeds all channels."""
        for evt in base_iter:
            t = type(evt)
            if t is DispatchEvent:
                counts["dispatch"] += 1
                em = emitter_for(evt.tile_index)
                if em.disp:
                    em.disp.add(evt.cycle)
                if channels.calls:
                    yield evt
            elif t is BackpressureEvent:
                counts["backpressure"] += 1
                emitter_for(evt.tile_index).emit_backpressure(evt)
            elif t is WaveletTraceEvent:
                counts["wavelet"] += 1
                em = emitter_for(evt.tile_index)
                if em.wrate:
                    em.wrate.add(evt.cycle)
                if channels.wavelet_events:
                    em.emit_wavelet(evt)
            elif t is PipeEvent:
                if evt.stage == PIPE_WRITEBACK_STAGE:
                    counts["pipe"] += 1
                    emitter_for(evt.tile_index).emit_regs(evt)
            elif t is SwitchPosEvent:
                counts["switch"] += 1
                emitter_for(evt.tile_index).emit_switch(evt)
            elif t is DebugCountersEvent:
                counts["debug"] += 1
                emitter_for(evt.pe_y * grid_width + evt.pe_x).emit_debug(evt)

    if channels.calls:
        for kind, tile_idx, label, cycle in reconstruct(
                dispatch_stream(), tile_elf_mapping, elf_lookups):
            emitter_for(tile_idx).emit_slice(kind, label, cycle)
    else:
        for _ in dispatch_stream():
            pass

    for em in emitters.values():
        em.close()
    return counts, len(emitters)


# Per-worker read-only state (set once per process by _pf_init).
_PF = {}


def _pf_init(metadata_path, want_ids, tile_filter, pe_filter, cycle_range,
             grid_width, channels, bin_cycles, tile_elf_mapping, elf_lookups,
             tmpdir):
    _PF.update(metadata_path=metadata_path, want_ids=want_ids,
               tile_filter=tile_filter, pe_filter=pe_filter,
               cycle_range=cycle_range, grid_width=grid_width,
               channels=channels, bin_cycles=bin_cycles,
               mapping=tile_elf_mapping, lookups=elf_lookups, tmpdir=tmpdir)


def _pf_worker(path):
    """Emit one stream's Perfetto packets to a temp file; return (path, counts).

    The temp file holds raw (uncompressed) ``TracePacket``s; the parent
    concatenates the per-stream files (optionally gzipping) into the output.
    """
    s = _PF
    fd, tmp = tempfile.mkstemp(prefix="simperf_", suffix=".pftrace",
                               dir=s["tmpdir"])
    os.close(fd)
    writer = pb.TraceWriter(tmp)
    base_iter = parse_ctf_stream(
        path, want_ids=s["want_ids"], tile_filter=s["tile_filter"],
        pe_filter=s["pe_filter"], cycle_range=s["cycle_range"],
        metadata_path=s["metadata_path"])
    counts, n_tiles = emit_stream(
        writer, base_iter, grid_width=s["grid_width"], channels=s["channels"],
        bin_cycles=s["bin_cycles"], tile_elf_mapping=s["mapping"],
        elf_lookups=s["lookups"])
    writer.close()
    return tmp, dict(counts), n_tiles


def build_perfetto(trace_dir, tile_elf_mapping, elf_lookups, *, grid_width,
                   channels, bin_cycles, out_path, tile_filter=None,
                   cycle_range=None, quiet=False, jobs=None):
    pe_filter = None
    if tile_filter is not None:
        pe_filter = {(t % grid_width, t // grid_width) for t in tile_filter}

    paths = (streams_for_tiles(trace_dir, tile_filter) if tile_filter
             else stream_paths(trace_dir))
    metadata_path = os.path.join(trace_dir, "metadata")
    want_ids = channels.want_ids()

    # Each stream is emitted to its own temp file in a worker process; the files
    # are concatenated (tiles are disjoint packet sequences, so order across
    # streams is irrelevant) into the final trace, gzipped if requested.
    tmpdir = tempfile.mkdtemp(prefix="simperfetto_",
                              dir=os.path.dirname(os.path.abspath(out_path)))
    pbar = (tqdm(total=len(paths), unit="stream", desc="Processing",
                 file=sys.stderr) if not quiet else None)
    counts = Counter()
    n_tiles = 0
    tmp_files = []
    try:
        for _path, (tmp, c, nt) in parallel_streams(
                paths, _pf_worker, jobs=jobs, initializer=_pf_init,
                initargs=(metadata_path, want_ids, tile_filter, pe_filter,
                          cycle_range, grid_width, channels, bin_cycles,
                          tile_elf_mapping, elf_lookups, tmpdir)):
            tmp_files.append(tmp)
            n_tiles += nt
            for k, v in c.items():
                counts[k] += v
            if pbar is not None:
                pbar.update(1)

        out = (gzip.open(out_path, "wb") if out_path.endswith(".gz")
               else open(out_path, "wb"))
        with out:
            for tmp in tmp_files:
                with open(tmp, "rb") as src:
                    shutil.copyfileobj(src, out, 8 * 1024 * 1024)
    finally:
        for tmp in tmp_files:
            try:
                os.remove(tmp)
            except OSError:
                pass
        try:
            os.rmdir(tmpdir)
        except OSError:
            pass

    if pbar is not None:
        pbar.close()
    summary = "  ".join(f"{k}: {v:,}" for k, v in sorted(counts.items()))
    print(f"  Tiles: {n_tiles}  {summary}", file=sys.stderr)


# --------------------------------------------------------------------------- #
#  Main
# --------------------------------------------------------------------------- #

def build_argparser():
    p = argparse.ArgumentParser(
        description="Convert Cerebras simulator CTF traces to a Perfetto trace.")
    p.add_argument("out_dir", help="Path to simulator out/ directory or workdir")
    p.add_argument("-o", "--output", default="trace.pftrace",
                   help="Output Perfetto trace (.pftrace, or .gz to compress)")
    p.add_argument("--tiles", default=None,
                   help="Comma-separated tile indices to include (default: all)")
    p.add_argument("--cycles", default=None,
                   help="Restrict to cycle range A:B (e.g. 100:200, 100:, :200)")
    p.add_argument("--bin-cycles", type=int, default=1000,
                   help="Window size for per-bin counters (default 1000)")
    p.add_argument("--trace-dir", default=None, help="Override path to simfab_traces/")
    p.add_argument("--bin-root", default=None,
                   help="Override the directory containing bin/*.elf")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--quiet", action="store_true", help="Suppress progress bar")
    p.add_argument("-j", "--jobs", type=int, default=None,
                   help="Parallel worker processes (default: one per stream, "
                        "capped at the CPU count; 1 = serial)")

    g = p.add_argument_group("channels")
    g.add_argument("--calls", action=argparse.BooleanOptionalAction, default=True,
                   help="Call-stack flamegraph (default: on)")
    g.add_argument("--dispatch-rate", action=argparse.BooleanOptionalAction,
                   default=True, help="Instructions-per-bin counter (default: on)")
    g.add_argument("--wavelet-rate", action=argparse.BooleanOptionalAction,
                   default=True, help="Wavelets-per-bin counter (default: on)")
    g.add_argument("--backpressure", action=argparse.BooleanOptionalAction,
                   default=True, help="Per-link backpressure counter (default: on)")
    g.add_argument("--backpressure-raw", action="store_true",
                   help="Emit every backpressure sample instead of the binned max")
    g.add_argument("--wavelet-events", action=argparse.BooleanOptionalAction,
                   default=True, help="Per-wavelet instant markers (default: on)")
    g.add_argument("--flow", action=argparse.BooleanOptionalAction, default=True,
                   help="Wavelet flow arrows linking a wavelet's hops by ident "
                        "(default: on; needs --wavelet-events)")
    g.add_argument("--switch-pos", action="store_true",
                   help="Router switch-position instant events (off)")
    g.add_argument("--regs", action="store_true",
                   help="Resolved operand values as counters (off)")
    g.add_argument("--debug-counters", action="store_true",
                   help="Per-(PE,color) wavelet counters (off)")
    g.add_argument("--all", action="store_true",
                   help="Enable every channel (except --backpressure-raw)")
    return p


def parse_cycle_range(s):
    if s is None:
        return None
    if ":" not in s:
        c = int(s)
        return (c, c + 1)
    a, b = s.split(":", 1)
    return (int(a) if a else 0, int(b) if b else None)


def main():
    args = build_argparser().parse_args()

    channels = Channels(
        calls=args.calls,
        dispatch_rate=args.dispatch_rate,
        wavelet_rate=args.wavelet_rate,
        backpressure=args.backpressure,
        backpressure_raw=args.backpressure_raw,
        wavelet_events=args.wavelet_events or args.flow or args.all,
        switch_pos=args.switch_pos or args.all,
        regs=args.regs or args.all,
        debug_counters=args.debug_counters or args.all,
        flow=args.flow or args.all,
    )

    try:
        trace_dir = resolve_trace_dir(args.out_dir, args.trace_dir)
        bin_root = resolve_bin_root(args.out_dir, args.bin_root)
    except FileNotFoundError as e:
        raise SystemExit(f"Error: {e}")

    grid_width, grid_height = read_grid_dims(trace_dir)
    elf_lookups, detected_arch = load_all_elf_lookups(bin_root, verbose=args.verbose)
    if not elf_lookups:
        raise SystemExit("Error: No ELF files with function symbols found")
    if not args.quiet:
        print(f"Loaded {len(elf_lookups)} ELF files (WSE{detected_arch.version}), "
              f"grid {grid_width}x{grid_height}", file=sys.stderr)
    tile_elf_mapping = build_elf_mapping(elf_lookups, grid_width,
                                         verbose=args.verbose, quiet=args.quiet)

    tile_filter = None
    if args.tiles:
        tile_filter = set(int(t.strip()) for t in args.tiles.split(","))

    build_perfetto(
        trace_dir, tile_elf_mapping, elf_lookups,
        grid_width=grid_width, channels=channels, bin_cycles=args.bin_cycles,
        out_path=args.output, tile_filter=tile_filter,
        cycle_range=parse_cycle_range(args.cycles), quiet=args.quiet,
        jobs=args.jobs,
    )
    print(f"Done → {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()

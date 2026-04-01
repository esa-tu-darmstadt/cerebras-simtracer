#!/usr/bin/env python3
"""
simtracer: Convert Cerebras simulator CTF traces to speedscope profiles.

Parses CTF trace files (barectf-generated) and ELF symbol tables to produce
a speedscope JSON file showing function-level execution timelines per tile.

Usage:
    python3 simtracer.py <out_dir> -o output.speedscope.json [--tiles 16,17,18]

Where:
    out_dir: Simulator out/ directory (contains simfab_traces/ and bin/)

Requires pyelftools: pip install pyelftools
"""

import argparse
import bisect
import json
import os
import struct
import sys
from dataclasses import dataclass, field

from tqdm import tqdm

from elftools.elf.elffile import ELFFile

# --------------------------------------------------------------------------- #
#  Constants
# --------------------------------------------------------------------------- #

CTF_MAGIC = 0xC1FC1FC1

@dataclass(frozen=True)
class WSEArch:
    """Architecture-specific constants for a WSE generation."""
    version: int
    name: str
    jmp_r15: int       # encoding of `jmp r15` (function return)
    jmp_r15_mask: int  # mask to apply to inst_bin before comparing

# ELF e_flags -> WSE generation: 0x0=WSE1, 0x1=WSE2, 0x2=WSE3
WSE_ARCHS = {
    0x1: WSEArch(version=2, name="neumann",     jmp_r15=0x7C6F,     jmp_r15_mask=0xFFFF),      # 6f 7c
    0x2: WSEArch(version=3, name="schrödinger",  jmp_r15=0x6D8003C0, jmp_r15_mask=0xFFFFFFFF),  # c0 03 80 6d
}

# Struct layouts (all little-endian)
PKT_HDR = struct.Struct("<IQ")       # magic(u32) + stream_id(u64) = 12 bytes
PKT_CTX = struct.Struct("<QQQQQ")    # pkt_size + content_size + ts_begin + ts_end + events_discarded = 40 bytes
EVT_HDR = struct.Struct("<QQ")       # id(u64) + timestamp(u64) = 16 bytes

PKT_OVERHEAD = PKT_HDR.size + PKT_CTX.size  # 52 bytes


# --------------------------------------------------------------------------- #
#  CTF alignment helper
# --------------------------------------------------------------------------- #

def align_up(offset, align_bits):
    """Align offset (bytes) to alignment (bits)."""
    a = align_bits // 8
    if a <= 1:
        return offset
    r = offset % a
    return offset if r == 0 else offset + (a - r)


# --------------------------------------------------------------------------- #
#  ELF symbol table via llvm-objdump
# --------------------------------------------------------------------------- #

@dataclass
class Function:
    name: str
    start: int
    size: int

    @property
    def end(self):
        return self.start + self.size


def parse_elf_symbols(elf_path):
    """Parse function symbols from an ELF file using pyelftools.

    Returns (functions, arch) where arch is a WSEArch instance.
    """
    functions = []
    with open(elf_path, "rb") as f:
        elf = ELFFile(f)
        e_flags = elf["e_flags"]
        arch = WSE_ARCHS.get(e_flags)
        if arch is None:
            raise RuntimeError(
                f"{elf_path}: unsupported ELF e_flags 0x{e_flags:x} "
                f"(supported: {', '.join(f'0x{k:x}=WSE{v.version}' for k, v in WSE_ARCHS.items())})"
            )
        symtab = elf.get_section_by_name(".symtab")
        if symtab is None:
            return functions, arch
        for sym in symtab.iter_symbols():
            if sym["st_info"]["type"] != "STT_FUNC":
                continue
            addr = sym["st_value"]
            size = sym["st_size"]
            name = sym.name
            if "task_table.nops" in name or size < 4:
                continue
            functions.append(Function(name=name, start=addr, size=size))
    functions.sort(key=lambda f: f.start)
    return functions, arch


class SymbolLookup:
    """Fast address -> function name lookup using binary search."""

    def __init__(self, functions, arch):
        self.functions = functions
        self.arch = arch
        # Build sorted arrays for bisect
        self.starts = [f.start for f in functions]
        self.entry_set = set(self.starts)
        # Build gap-filling lookup: extend each function to cover up to the next one
        # This handles addresses in alignment padding or unlabeled code between functions
        self._extended = []
        for i, f in enumerate(functions):
            end = functions[i + 1].start if i + 1 < len(functions) else f.end
            self._extended.append((f.start, end, f.name))

    def lookup(self, addr):
        """Return (function_name, is_entry_point) or ('<init>', False) for unmapped."""
        idx = bisect.bisect_right(self.starts, addr) - 1
        if idx < 0:
            # Below first function - likely init/startup code
            return "<init>", False
        f = self.functions[idx]
        start, end, name = self._extended[idx]
        if start <= addr < end:
            return name, (addr == f.start)
        # After the last function's extended range
        return "<unknown>", False

    def lookup_strict(self, addr):
        """Strict lookup - only match within actual function bounds."""
        idx = bisect.bisect_right(self.starts, addr) - 1
        if idx < 0:
            return None, False
        f = self.functions[idx]
        if f.start <= addr < f.end:
            return f.name, (addr == f.start)
        return None, False

    def score(self, addrs):
        """Score how many addresses fall within known functions (strict)."""
        hits = 0
        for a in addrs:
            name, _ = self.lookup_strict(a)
            if name is not None:
                hits += 1
        return hits


# --------------------------------------------------------------------------- #
#  CTF trace parser
# --------------------------------------------------------------------------- #

@dataclass
class DispatchEvent:
    cycle: int
    tile_index: int
    inst_ptr: int
    inst_bin: int
    term_op: int
    task_color: int
    name: str


def parse_ctf_stream(stream_path, tile_filter=None, progress=None):
    """
    Parse CTF stream file and yield DispatchEvent objects.
    Only yields hwm_dispatch_trace_entry (event id=2) events.
    If progress is provided (a tqdm instance), updates it with bytes consumed.
    """
    file_size = os.path.getsize(stream_path)
    with open(stream_path, "rb") as f:
        # Process in chunks for memory efficiency
        CHUNK = 256 * 1024 * 1024  # 256MB
        file_offset = 0
        leftover = b""
        event_count = 0
        # Track absolute byte position for progress
        abs_pos = 0

        while file_offset < file_size:
            raw = f.read(CHUNK)
            if not raw:
                break
            data = leftover + raw
            file_offset += len(raw)
            offset = 0

            while offset + PKT_HDR.size + PKT_CTX.size < len(data):
                # Read packet header
                magic, stream_id = PKT_HDR.unpack_from(data, offset)
                if magic != CTF_MAGIC:
                    # Try to find next packet
                    offset += 1
                    continue

                pkt_start = offset
                pkt_size_bits = struct.unpack_from("<Q", data, offset + PKT_HDR.size)[0]
                content_size_bits = struct.unpack_from("<Q", data, offset + PKT_HDR.size + 8)[0]
                pkt_size = pkt_size_bits // 8
                content_size = content_size_bits // 8

                if pkt_start + pkt_size > len(data):
                    # Incomplete packet at end of chunk - save as leftover
                    break

                content_end = pkt_start + content_size
                evt_offset = pkt_start + PKT_OVERHEAD

                # Parse events within this packet
                while evt_offset + EVT_HDR.size <= content_end:
                    evt_id, evt_ts = EVT_HDR.unpack_from(data, evt_offset)
                    evt_offset += EVT_HDR.size

                    try:
                        evt_offset = _skip_or_parse_event(
                            data, pkt_start, evt_offset, evt_id, tile_filter
                        )
                    except (struct.error, IndexError, ValueError):
                        evt_offset = content_end
                        break

                    if isinstance(evt_offset, tuple):
                        event, evt_offset = evt_offset
                        event_count += 1
                        yield event

                offset = pkt_start + pkt_size

                # Update progress after each packet
                if progress is not None:
                    new_abs = file_offset - len(data) + offset
                    progress.update(new_abs - abs_pos)
                    abs_pos = new_abs

            # Keep unprocessed data for next iteration
            leftover = data[offset:]

        # Final progress update
        if progress is not None:
            progress.update(file_size - abs_pos)


def _skip_or_parse_event(data, pkt_start, offset, evt_id, tile_filter):
    """
    Parse or skip an event. Returns new offset, or (DispatchEvent, new_offset)
    for dispatch events that pass the tile filter.
    """
    def _align(off, bits):
        return align_up(off - pkt_start, bits) + pkt_start

    if evt_id == 0:  # backpressure_trace_entry
        off = _align(offset, 64)  # cycle u64 align=64
        off += 8 + 4 + 4 + 1     # cycle + tile_index + back_pressure + link
        return off

    elif evt_id == 1:  # debug_counters_wavelet
        off = _align(offset, 32)  # PE_x u32 align=32
        off += 4 + 4 + 4          # PE_x + PE_y + color
        off = _align(off, 64)     # count_w u64 align=64
        off += 8 + 8 + 8          # count_w + count_t + count_s
        return off

    elif evt_id == 2:  # hwm_dispatch_trace_entry
        off = _align(offset, 64)
        cycle = struct.unpack_from("<Q", data, off)[0]; off += 8
        tile_index = struct.unpack_from("<I", data, off)[0]; off += 4

        # Quick tile filter before parsing rest
        if tile_filter is not None and tile_index not in tile_filter:
            off += 4 + 4 + 4 + 4 + 2 + 1 + 1 + 1  # remaining fixed fields
            # Skip null-terminated string
            end = data.index(b'\x00', off)
            return end + 1

        uid = struct.unpack_from("<I", data, off)[0]; off += 4
        inst_bin = struct.unpack_from("<I", data, off)[0]; off += 4
        off += 4 + 4  # num_data + context
        inst_ptr = struct.unpack_from("<H", data, off)[0]; off += 2
        task_color = data[off]; off += 1
        off += 1  # ut_id
        term_op = struct.unpack_from("<b", data, off)[0]; off += 1
        # Read null-terminated name string
        end = data.index(b'\x00', off)
        name = data[off:end].decode('utf-8', errors='replace')
        off = end + 1

        event = DispatchEvent(
            cycle=cycle, tile_index=tile_index, inst_ptr=inst_ptr,
            inst_bin=inst_bin, term_op=term_op, task_color=task_color,
            name=name
        )
        return (event, off)

    elif evt_id == 3:  # hwm_pipe_trace_entry
        off = _align(offset, 64)
        off += 8 + 4 + 4 + 4 + 4 + 4 + 4 + 4 + 1 + 1 + 1 + 1 + 1
        return off

    elif evt_id == 4:  # switch_pos_trace_entry
        off = _align(offset, 64)
        off += 8 + 4 + 1 + 1 + 1 + 1 + 1
        return off

    elif evt_id == 5:  # wavelet_entry
        off = _align(offset, 16)
        off += 2 + 2 + 2 + 1 + 1
        off = _align(off, 64)
        off += 8 + 2 + 2 + 2 + 2
        return off

    elif evt_id == 6:  # wavelet_trace_entry
        off = _align(offset, 64)
        off += 8 + 8 + 4 + 2 + 2
        off = _align(off, 32)
        off += 4
        return off

    else:
        raise ValueError(f"Unknown event id {evt_id}")


# --------------------------------------------------------------------------- #
#  Tile -> ELF mapping via LMA
# --------------------------------------------------------------------------- #

def build_elf_mapping(elf_lookups, grid_width, verbose=False):
    """
    Build tile_index -> elf_path mapping from ELF PT_LOAD segment LMAs.

    Each Cerebras ELF encodes its target tile indices in the LMA (load memory
    address) of its PT_LOAD segments. Specifically:

        tile_index = (segment.p_paddr >> 40) & 0xFFFF

    where tile_index = fabric_y * grid_width + fabric_x.

    An ELF that is shared across multiple tiles has multiple PT_LOAD segments
    with different LMAs — one per tile it applies to. This gives us a complete,
    deterministic mapping without any heuristics.

    Returns dict: tile_index -> elf_path
    """
    mapping = {}
    for elf_path in elf_lookups:
        elf_name = os.path.basename(elf_path)
        tile_indices = set()
        with open(elf_path, "rb") as f:
            elf = ELFFile(f)
            for seg in elf.iter_segments():
                if seg["p_type"] == "PT_LOAD":
                    tile_idx = (seg["p_paddr"] >> 40) & 0xFFFF
                    tile_indices.add(tile_idx)

        for tile_idx in sorted(tile_indices):
            if tile_idx in mapping:
                prev = os.path.basename(mapping[tile_idx])
                raise RuntimeError(
                    f"Tile {tile_idx} claimed by both {prev} and {elf_name}"
                )
            mapping[tile_idx] = elf_path

        if verbose:
            x = min(tile_indices) % grid_width
            y = min(tile_indices) // grid_width
            print(f"  {elf_name}: {len(tile_indices)} tile(s), "
                  f"first = tile {min(tile_indices)} (P{x}.{y})", file=sys.stderr)

    print(f"Mapped {len(mapping)} tiles from LMA segments", file=sys.stderr)
    return mapping


# --------------------------------------------------------------------------- #
#  Call stack reconstruction & speedscope generation
# --------------------------------------------------------------------------- #

@dataclass
class TileState:
    """Tracks the call stack for a single tile."""
    call_stack: list = field(default_factory=list)  # list of func_name
    events: list = field(default_factory=list)       # speedscope events
    first_cycle: int = 0
    last_cycle: int = 0
    prev_func: str = None
    current_task: int = -1  # current task_color, -1 = none

    def open_frame(self, frame_idx, cycle):
        self.events.append({"type": "O", "frame": frame_idx, "at": cycle})

    def close_frame(self, frame_idx, cycle):
        self.events.append({"type": "C", "frame": frame_idx, "at": cycle})


def build_speedscope(trace_path, tile_elf_mapping, elf_lookups, tile_filter=None,
                     grid_width=12):
    """
    Process the full trace and build a speedscope JSON structure.
    """
    # Frame index mapping (shared across all profiles)
    frame_names = []
    frame_index = {}  # name -> index

    def get_frame_idx(name):
        if name not in frame_index:
            frame_index[name] = len(frame_names)
            frame_names.append(name)
        return frame_index[name]

    # Per-tile state
    states = {}

    def get_state(tile_idx):
        if tile_idx not in states:
            states[tile_idx] = TileState()
        return states[tile_idx]

    # Process events
    event_count = 0
    stat_calls = 0
    stat_returns = 0
    stat_task_switches = 0
    stat_task_terms = 0
    file_size = os.path.getsize(trace_path)
    pbar = tqdm(total=file_size, unit="B", unit_scale=True, desc="Processing",
                file=sys.stderr)
    for evt in parse_ctf_stream(trace_path, tile_filter=tile_filter, progress=pbar):
        tile_idx = evt.tile_index
        event_count += 1

        elf_path = tile_elf_mapping.get(tile_idx)
        if not elf_path:
            raise RuntimeError(
                f"Tile {tile_idx} has trace events but no ELF mapping. "
                f"Is the bin/ directory complete?"
            )
        lookup = elf_lookups[elf_path]

        state = get_state(tile_idx)
        if state.first_cycle == 0:
            state.first_cycle = evt.cycle

        # inst_ptr is a word address (16-bit words); ELF symbols use byte addresses
        func_name, is_entry = lookup.lookup(evt.inst_ptr * 2)

        state.last_cycle = evt.cycle

        # --- Task frame management ---
        # task_color changes -> close old task (and its entire call stack), open new
        if evt.task_color != state.current_task:
            stat_task_switches += 1
            # Close all function frames under old task
            for fn in reversed(state.call_stack):
                state.close_frame(get_frame_idx(fn), evt.cycle)
            state.call_stack.clear()
            # Close old task frame
            if state.current_task >= 0:
                task_name = f"task {state.current_task}"
                state.close_frame(get_frame_idx(task_name), evt.cycle)
            # Open new task frame
            state.current_task = evt.task_color
            task_name = f"task {evt.task_color}"
            state.open_frame(get_frame_idx(task_name), evt.cycle)
            state.prev_func = None

        # Detect task termination
        if evt.term_op == 1:
            stat_task_terms += 1
            # .term - close entire function stack + task frame
            for fn in reversed(state.call_stack):
                state.close_frame(get_frame_idx(fn), evt.cycle)
            state.call_stack.clear()
            if state.current_task >= 0:
                task_name = f"task {state.current_task}"
                state.close_frame(get_frame_idx(task_name), evt.cycle)
                state.current_task = -1
            state.prev_func = None
            continue

        # Detect function return (jmp r15)
        arch = lookup.arch
        if evt.inst_bin & arch.jmp_r15_mask == arch.jmp_r15:
            stat_returns += 1
            # Return - pop current function
            if state.call_stack:
                top = state.call_stack[-1]
                state.close_frame(get_frame_idx(top), evt.cycle)
                state.call_stack.pop()
            state.prev_func = state.call_stack[-1] if state.call_stack else None
            continue

        # Detect function changes
        if func_name != state.prev_func:
            if is_entry and state.prev_func is not None:
                # Call to new function - push
                stat_calls += 1
                state.call_stack.append(func_name)
                state.open_frame(get_frame_idx(func_name), evt.cycle)
            elif not state.call_stack:
                # First function or after task end - start fresh
                state.call_stack.append(func_name)
                state.open_frame(get_frame_idx(func_name), evt.cycle)
            elif func_name in state.call_stack:
                # Returned to a function on the stack (e.g. after optimized return)
                while state.call_stack and state.call_stack[-1] != func_name:
                    top = state.call_stack.pop()
                    state.close_frame(get_frame_idx(top), evt.cycle)
            else:
                # Jump to a new function not at entry point and not on stack
                # Treat as a tail call: close current, open new
                if state.call_stack:
                    top = state.call_stack.pop()
                    state.close_frame(get_frame_idx(top), evt.cycle)
                state.call_stack.append(func_name)
                state.open_frame(get_frame_idx(func_name), evt.cycle)

        state.prev_func = func_name

    pbar.close()

    # Close any remaining open frames (functions + task)
    for tile_idx, state in states.items():
        for fn in reversed(state.call_stack):
            state.close_frame(get_frame_idx(fn), state.last_cycle)
        state.call_stack.clear()
        if state.current_task >= 0:
            task_name = f"task {state.current_task}"
            state.close_frame(get_frame_idx(task_name), state.last_cycle)
            state.current_task = -1

    print(f"  Events: {event_count}  calls: {stat_calls}  returns: {stat_returns}  "
          f"task switches: {stat_task_switches}  task terminations: {stat_task_terms}",
          file=sys.stderr)

    # Build speedscope JSON
    profiles = []
    for tile_idx in sorted(states.keys()):
        state = states[tile_idx]
        if not state.events:
            continue
        x = tile_idx % grid_width
        y = tile_idx // grid_width
        profiles.append({
            "type": "evented",
            "name": f"Tile {tile_idx} (P{x}.{y})",
            "unit": "none",
            "startValue": state.first_cycle,
            "endValue": state.last_cycle,
            "events": state.events,
        })

    speedscope = {
        "$schema": "https://www.speedscope.app/file-format-schema.json",
        "version": "0.0.1",
        "shared": {
            "frames": [{"name": n} for n in frame_names]
        },
        "profiles": profiles,
        "name": "Cerebras Simulator Trace",
        "activeProfileIndex": 0,
        "exporter": "simtracer",
    }

    return speedscope


# --------------------------------------------------------------------------- #
#  Main
# --------------------------------------------------------------------------- #

def main():
    parser = argparse.ArgumentParser(
        description="Convert Cerebras simulator CTF traces to speedscope profiles."
    )
    parser.add_argument("out_dir", help="Path to simulator out/ directory")
    parser.add_argument("-o", "--output", default="trace.speedscope.json",
                        help="Output speedscope JSON file")
    parser.add_argument("--tiles", type=str, default=None,
                        help="Comma-separated list of tile indices to include (default: all)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Print per-file details")
    args = parser.parse_args()
    verbose = args.verbose

    trace_dir = os.path.join(args.out_dir, "simfab_traces")
    bin_dir = os.path.join(args.out_dir, "bin")

    # Find trace files
    stream_path = os.path.join(trace_dir, "stream0")
    if not os.path.isfile(stream_path):
        print(f"Error: {stream_path} not found", file=sys.stderr)
        sys.exit(1)

    # Read grid width from global_simdata.json
    simdata_path = os.path.join(trace_dir, "global_simdata.json")
    if not os.path.isfile(simdata_path):
        print(f"Error: {simdata_path} not found", file=sys.stderr)
        sys.exit(1)
    with open(simdata_path) as f:
        simdata = json.load(f)
    grid_width = simdata["xsize"]
    grid_height = simdata["ysize"]

    # Parse tile filter
    tile_filter = None
    if args.tiles:
        tile_filter = set(int(t.strip()) for t in args.tiles.split(","))

    # Load ELF symbol tables from bin/, west/bin/, east/bin/
    elf_lookups = {}
    elf_dirs = [bin_dir]
    for sub in ["west/bin", "east/bin"]:
        d = os.path.join(args.out_dir, sub)
        if os.path.isdir(d):
            elf_dirs.append(d)

    detected_arch = None
    for elf_dir in elf_dirs:
        rel = os.path.relpath(elf_dir, args.out_dir)
        elf_files = sorted(f for f in os.listdir(elf_dir) if f.endswith(".elf"))
        for elf_file in elf_files:
            elf_path = os.path.join(elf_dir, elf_file)
            functions, arch = parse_elf_symbols(elf_path)
            if functions:
                detected_arch = arch
                elf_lookups[elf_path] = SymbolLookup(functions, arch)
                if verbose:
                    print(f"  {rel}/{elf_file}: {len(functions)} functions (WSE{arch.version})", file=sys.stderr)

    if not elf_lookups:
        print("Error: No ELF files with function symbols found", file=sys.stderr)
        sys.exit(1)

    print(f"Loaded {len(elf_lookups)} ELF files (WSE{detected_arch.version}), "
          f"grid {grid_width}x{grid_height}", file=sys.stderr)

    # Build tile -> ELF mapping from LMA
    tile_elf_mapping = build_elf_mapping(elf_lookups, grid_width, verbose)

    # Build speedscope profile
    speedscope = build_speedscope(
        stream_path, tile_elf_mapping, elf_lookups,
        tile_filter=tile_filter, grid_width=grid_width
    )

    # Write output
    with open(args.output, "w") as f:
        json.dump(speedscope, f)

    n_profiles = len(speedscope["profiles"])
    n_frames = len(speedscope["shared"]["frames"])
    total_events = sum(len(p["events"]) for p in speedscope["profiles"])
    print(f"Done: {n_profiles} profiles, {n_frames} frames, {total_events} events → {args.output}",
          file=sys.stderr)


if __name__ == "__main__":
    main()

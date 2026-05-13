#!/usr/bin/env python3
"""
simflame: Convert Cerebras simulator CTF traces to speedscope flamegraph profiles.

Reads CTF dispatch events and ELF symbol tables to produce a speedscope JSON
showing function-level execution timelines per tile.

Usage:
    python3 simflame.py <out_dir> -o output.speedscope.json [--tiles 16,17,18]
"""

import argparse
import json
import os
import sys
from dataclasses import dataclass, field

from tqdm import tqdm

from ctf import (
    parse_ctf_stream,
    load_all_elf_lookups,
    build_elf_mapping,
    read_grid_dims,
    resolve_bin_root,
    resolve_trace_dir,
    stream0_path,
)


# --------------------------------------------------------------------------- #
#  Call stack reconstruction & speedscope generation
# --------------------------------------------------------------------------- #

@dataclass
class TileState:
    """Tracks the call stack for a single tile."""
    call_stack: list = field(default_factory=list)
    events: list = field(default_factory=list)
    first_cycle: int = 0
    last_cycle: int = 0
    prev_func: str = None
    current_task: int = -1

    def open_frame(self, frame_idx, cycle):
        self.events.append({"type": "O", "frame": frame_idx, "at": cycle})

    def close_frame(self, frame_idx, cycle):
        self.events.append({"type": "C", "frame": frame_idx, "at": cycle})


def build_speedscope(trace_path, tile_elf_mapping, elf_lookups, tile_filter=None,
                     grid_width=12):
    """Process the full trace and build a speedscope JSON structure."""
    frame_names = []
    frame_index = {}

    def get_frame_idx(name):
        if name not in frame_index:
            frame_index[name] = len(frame_names)
            frame_names.append(name)
        return frame_index[name]

    states = {}

    def get_state(tile_idx):
        if tile_idx not in states:
            states[tile_idx] = TileState()
        return states[tile_idx]

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

        # Task frame management
        if evt.task_color != state.current_task:
            stat_task_switches += 1
            for fn in reversed(state.call_stack):
                state.close_frame(get_frame_idx(fn), evt.cycle)
            state.call_stack.clear()
            if state.current_task >= 0:
                state.close_frame(get_frame_idx(f"task {state.current_task}"), evt.cycle)
            state.current_task = evt.task_color
            state.open_frame(get_frame_idx(f"task {evt.task_color}"), evt.cycle)
            state.prev_func = None

        if evt.term_op == 1:
            stat_task_terms += 1
            for fn in reversed(state.call_stack):
                state.close_frame(get_frame_idx(fn), evt.cycle)
            state.call_stack.clear()
            if state.current_task >= 0:
                state.close_frame(get_frame_idx(f"task {state.current_task}"), evt.cycle)
                state.current_task = -1
            state.prev_func = None
            continue

        arch = lookup.arch
        if evt.inst_bin & arch.jmp_r15_mask == arch.jmp_r15:
            stat_returns += 1
            if state.call_stack:
                top = state.call_stack[-1]
                state.close_frame(get_frame_idx(top), evt.cycle)
                state.call_stack.pop()
            state.prev_func = state.call_stack[-1] if state.call_stack else None
            continue

        if func_name != state.prev_func:
            if is_entry and state.prev_func is not None:
                stat_calls += 1
                state.call_stack.append(func_name)
                state.open_frame(get_frame_idx(func_name), evt.cycle)
            elif not state.call_stack:
                state.call_stack.append(func_name)
                state.open_frame(get_frame_idx(func_name), evt.cycle)
            elif func_name in state.call_stack:
                while state.call_stack and state.call_stack[-1] != func_name:
                    top = state.call_stack.pop()
                    state.close_frame(get_frame_idx(top), evt.cycle)
            else:
                if state.call_stack:
                    top = state.call_stack.pop()
                    state.close_frame(get_frame_idx(top), evt.cycle)
                state.call_stack.append(func_name)
                state.open_frame(get_frame_idx(func_name), evt.cycle)

        state.prev_func = func_name

    pbar.close()

    for tile_idx, state in states.items():
        for fn in reversed(state.call_stack):
            state.close_frame(get_frame_idx(fn), state.last_cycle)
        state.call_stack.clear()
        if state.current_task >= 0:
            state.close_frame(get_frame_idx(f"task {state.current_task}"), state.last_cycle)
            state.current_task = -1

    print(f"  Events: {event_count}  calls: {stat_calls}  returns: {stat_returns}  "
          f"task switches: {stat_task_switches}  task terminations: {stat_task_terms}",
          file=sys.stderr)

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

    return {
        "$schema": "https://www.speedscope.app/file-format-schema.json",
        "version": "0.0.1",
        "shared": {"frames": [{"name": n} for n in frame_names]},
        "profiles": profiles,
        "name": "Cerebras Simulator Trace",
        "activeProfileIndex": 0,
        "exporter": "simflame",
    }


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
    parser.add_argument("--trace-dir", default=None,
                        help="Override path to simfab_traces/")
    parser.add_argument("--bin-root", default=None,
                        help="Override the directory containing bin/*.elf "
                             "(plus optional east/, west/)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Print per-file details")
    args = parser.parse_args()
    verbose = args.verbose

    try:
        trace_dir = resolve_trace_dir(args.out_dir, args.trace_dir)
        bin_root = resolve_bin_root(args.out_dir, args.bin_root)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    stream_path = stream0_path(trace_dir)
    grid_width, grid_height = read_grid_dims(trace_dir)

    tile_filter = None
    if args.tiles:
        tile_filter = set(int(t.strip()) for t in args.tiles.split(","))

    elf_lookups, detected_arch = load_all_elf_lookups(bin_root, verbose=verbose)
    if not elf_lookups:
        print("Error: No ELF files with function symbols found", file=sys.stderr)
        sys.exit(1)

    print(f"Loaded {len(elf_lookups)} ELF files (WSE{detected_arch.version}), "
          f"grid {grid_width}x{grid_height}", file=sys.stderr)

    tile_elf_mapping = build_elf_mapping(elf_lookups, grid_width, verbose)

    speedscope = build_speedscope(
        stream_path, tile_elf_mapping, elf_lookups,
        tile_filter=tile_filter, grid_width=grid_width
    )

    with open(args.output, "w") as f:
        json.dump(speedscope, f)

    n_profiles = len(speedscope["profiles"])
    n_frames = len(speedscope["shared"]["frames"])
    total_events = sum(len(p["events"]) for p in speedscope["profiles"])
    print(f"Done: {n_profiles} profiles, {n_frames} frames, {total_events} events → {args.output}",
          file=sys.stderr)


if __name__ == "__main__":
    main()

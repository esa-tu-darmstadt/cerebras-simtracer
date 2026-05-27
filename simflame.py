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
from collections import Counter
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
from callstack import reconstruct


# --------------------------------------------------------------------------- #
#  Call stack reconstruction & speedscope generation
# --------------------------------------------------------------------------- #

@dataclass
class TileProfile:
    """Accumulated speedscope events for a single tile."""
    events: list = field(default_factory=list)
    first_cycle: int = 0
    last_cycle: int = 0


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

    tiles = {}  # tile_index -> TileProfile (insertion order = first-seen order)

    file_size = os.path.getsize(trace_path)
    pbar = tqdm(total=file_size, unit="B", unit_scale=True, desc="Processing",
                file=sys.stderr)
    stats = Counter()
    events = parse_ctf_stream(trace_path, tile_filter=tile_filter, progress=pbar)
    for kind, tile_idx, label, cycle in reconstruct(
            events, tile_elf_mapping, elf_lookups, stats=stats):
        prof = tiles.get(tile_idx)
        if prof is None:
            prof = tiles[tile_idx] = TileProfile(first_cycle=cycle)
        prof.last_cycle = cycle
        prof.events.append({"type": kind, "frame": get_frame_idx(label), "at": cycle})

    pbar.close()

    print(f"  Events: {stats['events']}  calls: {stats['calls']}  "
          f"returns: {stats['returns']}  task switches: {stats['task_switches']}  "
          f"task terminations: {stats['task_terms']}", file=sys.stderr)

    profiles = []
    for tile_idx in sorted(tiles.keys()):
        prof = tiles[tile_idx]
        if not prof.events:
            continue
        x = tile_idx % grid_width
        y = tile_idx // grid_width
        profiles.append({
            "type": "evented",
            "name": f"Tile {tile_idx} (P{x}.{y})",
            "unit": "none",
            "startValue": prof.first_cycle,
            "endValue": prof.last_cycle,
            "events": prof.events,
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

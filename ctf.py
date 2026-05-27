"""
ctf: Shared CTF trace + ELF parsing primitives for simtracer / pe_trace.

Parses Cerebras simulator CTF streams (barectf-generated) and provides ELF
symbol lookup utilities. The dispatch trace (event id=2) records every
instruction issue; the pipe trace (event id=3) records the resolved operand
values at later pipeline stages (only stage=6 has real values — earlier
stages contain 0xFFFFFFFF sentinels).
"""

import bisect
import os
import struct
import sys
from dataclasses import dataclass

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
    0x2: WSEArch(version=3, name="schrödinger", jmp_r15=0x6D8003C0, jmp_r15_mask=0xFFFFFFFF),  # c0 03 80 6d
}

# Pipeline stage where dest/src operand values are resolved.
PIPE_WRITEBACK_STAGE = 6

# Sentinel meaning "no value" in pipe events.
PIPE_NO_VALUE_U32 = 0xFFFFFFFF
PIPE_NO_VALUE_U8 = 0xFF

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
#  ELF symbol table
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
    """Fast byte-address -> function name lookup using binary search."""

    def __init__(self, functions, arch):
        self.functions = functions
        self.arch = arch
        # Sorted arrays for bisect
        self.starts = [f.start for f in functions]
        self.entry_set = set(self.starts)
        # Gap-filling lookup: extend each function to cover up to the next one;
        # handles addresses in alignment padding or unlabeled code.
        self._extended = []
        for i, f in enumerate(functions):
            end = functions[i + 1].start if i + 1 < len(functions) else f.end
            self._extended.append((f.start, end, f.name))

    def lookup(self, addr):
        """Return (function_name, is_entry_point) or ('<init>', False) if before first function."""
        idx = bisect.bisect_right(self.starts, addr) - 1
        if idx < 0:
            return "<init>", False
        f = self.functions[idx]
        start, end, name = self._extended[idx]
        if start <= addr < end:
            return name, (addr == f.start)
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

    def find_by_pattern(self, pattern):
        """Return list of Functions whose name contains pattern (substring match)."""
        return [f for f in self.functions if pattern in f.name]


# --------------------------------------------------------------------------- #
#  Tile -> ELF mapping via LMA
# --------------------------------------------------------------------------- #

def build_elf_mapping(elf_lookups, grid_width, verbose=False, quiet=False):
    """
    Build tile_index -> elf_path mapping from ELF PT_LOAD segment LMAs.

    Each Cerebras ELF encodes its target tile indices in the LMA of its PT_LOAD
    segments: tile_index = (segment.p_paddr >> 40) & 0xFFFF, where
    tile_index = fabric_y * grid_width + fabric_x. Shared ELFs have one PT_LOAD
    per target tile.
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

    if not quiet:
        print(f"Mapped {len(mapping)} tiles from LMA segments", file=sys.stderr)
    return mapping


def resolve_bin_root(out_dir, override=None):
    """Return the directory containing `bin/*.elf` (and possibly `east/`, `west/`).

    Depending on how the simulator was invoked, the ELF tree can be either
    directly under the arg the user passed, or one level deeper under `out/`:

      <arg>/bin/*.elf                  (legacy layout)
      <arg>/out/bin/*.elf              (workdir layout — paper-bench style)

    Tries, in order: `override`, `<out_dir>`, `<out_dir>/out`. Returns the
    first directory whose `bin/` contains at least one `.elf`.
    """
    def _has_elfs(d):
        bin_d = os.path.join(d, "bin")
        if not os.path.isdir(bin_d):
            return False
        return any(f.endswith(".elf") for f in os.listdir(bin_d))

    if override:
        d = os.path.abspath(override)
        if not _has_elfs(d):
            raise FileNotFoundError(
                f"--bin-root '{override}' does not contain bin/*.elf"
            )
        return d

    out_dir_abs = os.path.abspath(out_dir)
    candidates = [out_dir_abs, os.path.join(out_dir_abs, "out")]
    for c in candidates:
        if _has_elfs(c):
            return c

    raise FileNotFoundError(
        "Could not locate bin/*.elf. Pass --bin-root <path> to set it "
        "explicitly. Tried:\n  " + "\n  ".join(
            os.path.join(c, "bin") for c in candidates)
    )


def load_all_elf_lookups(bin_root, verbose=False):
    """Load SymbolLookup for every ELF under bin_root/{bin,west/bin,east/bin}.

    Returns (elf_lookups dict {path: SymbolLookup}, detected_arch).
    """
    bin_dir = os.path.join(bin_root, "bin")
    elf_dirs = [bin_dir]
    for sub in ["west/bin", "east/bin"]:
        d = os.path.join(bin_root, sub)
        if os.path.isdir(d):
            elf_dirs.append(d)

    elf_lookups = {}
    detected_arch = None
    for elf_dir in elf_dirs:
        if not os.path.isdir(elf_dir):
            continue
        rel = os.path.relpath(elf_dir, bin_root)
        elf_files = sorted(f for f in os.listdir(elf_dir) if f.endswith(".elf"))
        for elf_file in elf_files:
            elf_path = os.path.join(elf_dir, elf_file)
            functions, arch = parse_elf_symbols(elf_path)
            if functions:
                detected_arch = arch
                elf_lookups[elf_path] = SymbolLookup(functions, arch)
                if verbose:
                    print(f"  {rel}/{elf_file}: {len(functions)} functions "
                          f"(WSE{arch.version})", file=sys.stderr)
    return elf_lookups, detected_arch


# --------------------------------------------------------------------------- #
#  CTF event records
# --------------------------------------------------------------------------- #

@dataclass
class DispatchEvent:
    """hwm_dispatch_trace_entry (event id=2): one entry per dispatched instr."""
    cycle: int
    tile_index: int
    inst_ptr: int       # word address (× 2 = byte address)
    inst_bin: int       # raw instruction bytes (u32; instruction may be 16 or 32 bit)
    term_op: int        # 1 = task terminator (.term)
    task_color: int     # active task color
    name: str           # instruction mnemonic (e.g. 'MOVRI')
    uid: int            # links to PipeEvent.uid


@dataclass
class WaveletEvent:
    """wavelet_entry (event id=5): per-wavelet send/receive event on a PE.

    Emitted by the simulator whenever a wavelet crosses a fabric interface.
    `event_type` distinguishes send vs receive (and other variants); exact enum
    values are not documented in the metadata — print and infer from context.

    `cycle` is the simulator clock at the event (same scale as
    `DispatchEvent.cycle`, so the two streams can be merged for correlation).
    The CTF field is named "timestamp" — that's a misnomer; values appear in
    simulated cycles, matching what the Cerebras profiler GUI displays.
    """
    cycle: int          # simulator cycle (CTF metadata calls this `timestamp`)
    pe_x: int
    pe_y: int
    color: int
    ctrlbit: int
    half_wavelet: int
    wvlt_cnt: int
    wvlt_idx: int
    wvlt_data: int
    event_type: int


@dataclass
class PipeEvent:
    """hwm_pipe_trace_entry (event id=3): per-pipeline-stage operand snapshot.

    Several entries per dispatched instruction (one per pipeline stage).
    Only stage=PIPE_WRITEBACK_STAGE (6) has resolved values; earlier stages
    contain 0xFFFFFFFF (u32) / 0xFF (u8) sentinels.
    """
    cycle: int
    tile_index: int
    uid: int            # matches DispatchEvent.uid
    data: int
    dest: int
    src0: int
    src1: int
    src2: int
    stage: int
    imm: int
    cflag: int


# --------------------------------------------------------------------------- #
#  CTF stream parser
# --------------------------------------------------------------------------- #

def parse_ctf_stream(stream_path, tile_filter=None, progress=None,
                     yield_pipe=False, cycle_range=None,
                     yield_wavelets=False, pe_filter=None):
    """
    Parse CTF stream file and yield event objects.

    Always yields DispatchEvent (id=2). When yield_pipe is True, also yields
    PipeEvent (id=3). When yield_wavelets is True, also yields WaveletEvent
    (id=5). All event types are emitted in trace order.

    Args:
        stream_path: path to stream0 file
        tile_filter: set of tile indices to keep (applies to DispatchEvent and
            PipeEvent, which carry tile_index), or None for all
        progress: optional tqdm instance updated with bytes consumed
        yield_pipe: also yield PipeEvent records
        cycle_range: optional (start, end) — yields events with start <= cycle < end.
                     end may be None (open-ended); stops streaming once we pass end.
                     Applies to all event types that carry a `cycle` field
                     (dispatch, pipe, wavelet — wavelet's `timestamp` is actually
                     a cycle, see WaveletEvent docstring).
        yield_wavelets: also yield WaveletEvent records
        pe_filter: set of (pe_x, pe_y) tuples to keep for WaveletEvent, or None
            for all. Has no effect on DispatchEvent / PipeEvent.
    """
    cyc_start = cycle_range[0] if cycle_range else None
    cyc_end = cycle_range[1] if cycle_range else None

    file_size = os.path.getsize(stream_path)
    with open(stream_path, "rb") as f:
        CHUNK = 256 * 1024 * 1024  # 256MB
        file_offset = 0
        leftover = b""
        abs_pos = 0
        stopped = False

        while file_offset < file_size and not stopped:
            raw = f.read(CHUNK)
            if not raw:
                break
            data = leftover + raw
            file_offset += len(raw)
            offset = 0

            while offset + PKT_HDR.size + PKT_CTX.size < len(data):
                magic, _stream_id = PKT_HDR.unpack_from(data, offset)
                if magic != CTF_MAGIC:
                    offset += 1
                    continue

                pkt_start = offset
                pkt_size_bits = struct.unpack_from("<Q", data, offset + PKT_HDR.size)[0]
                content_size_bits = struct.unpack_from("<Q", data, offset + PKT_HDR.size + 8)[0]
                pkt_size = pkt_size_bits // 8
                content_size = content_size_bits // 8

                if pkt_start + pkt_size > len(data):
                    break  # incomplete packet — keep as leftover

                content_end = pkt_start + content_size
                evt_offset = pkt_start + PKT_OVERHEAD

                # The packet header carries a timestamp_begin we could use to
                # skip whole packets outside cycle_range, but cycles and CTF
                # timestamps are not the same scale; rely on per-event filter.
                while evt_offset + EVT_HDR.size <= content_end:
                    evt_id, _evt_ts = EVT_HDR.unpack_from(data, evt_offset)
                    evt_offset += EVT_HDR.size

                    try:
                        evt_offset = _skip_or_parse_event(
                            data, pkt_start, evt_offset, evt_id, tile_filter,
                            yield_pipe, yield_wavelets, pe_filter,
                        )
                    except (struct.error, IndexError, ValueError):
                        evt_offset = content_end
                        break

                    if isinstance(evt_offset, tuple):
                        event, evt_offset = evt_offset
                        if cyc_start is not None and event.cycle < cyc_start:
                            continue
                        if cyc_end is not None and event.cycle >= cyc_end:
                            stopped = True
                            break
                        yield event

                offset = pkt_start + pkt_size

                if progress is not None:
                    new_abs = file_offset - len(data) + offset
                    progress.update(new_abs - abs_pos)
                    abs_pos = new_abs

                if stopped:
                    break

            leftover = data[offset:]

        if progress is not None:
            progress.update(file_size - abs_pos)


def _skip_or_parse_event(data, pkt_start, offset, evt_id, tile_filter,
                         yield_pipe, yield_wavelets=False, pe_filter=None):
    """
    Parse or skip one event. Returns the new offset, or (Event, new_offset)
    for events that pass the tile filter.
    """
    def _align(off, bits):
        return align_up(off - pkt_start, bits) + pkt_start

    if evt_id == 0:  # backpressure_trace_entry
        off = _align(offset, 64)
        off += 8 + 4 + 4 + 1
        return off

    elif evt_id == 1:  # debug_counters_wavelet
        off = _align(offset, 32)
        off += 4 + 4 + 4
        off = _align(off, 64)
        off += 8 + 8 + 8
        return off

    elif evt_id == 2:  # hwm_dispatch_trace_entry
        off = _align(offset, 64)
        cycle = struct.unpack_from("<Q", data, off)[0]; off += 8
        tile_index = struct.unpack_from("<I", data, off)[0]; off += 4

        if tile_filter is not None and tile_index not in tile_filter:
            off += 4 + 4 + 4 + 4 + 2 + 1 + 1 + 1
            end = data.index(b'\x00', off)
            return end + 1

        uid = struct.unpack_from("<I", data, off)[0]; off += 4
        inst_bin = struct.unpack_from("<I", data, off)[0]; off += 4
        off += 4 + 4  # num_data + context
        inst_ptr = struct.unpack_from("<H", data, off)[0]; off += 2
        task_color = data[off]; off += 1
        off += 1  # ut_id
        term_op = struct.unpack_from("<b", data, off)[0]; off += 1
        end = data.index(b'\x00', off)
        name = data[off:end].decode('utf-8', errors='replace')
        off = end + 1

        event = DispatchEvent(
            cycle=cycle, tile_index=tile_index, inst_ptr=inst_ptr,
            inst_bin=inst_bin, term_op=term_op, task_color=task_color,
            name=name, uid=uid,
        )
        return (event, off)

    elif evt_id == 3:  # hwm_pipe_trace_entry
        off = _align(offset, 64)
        if not yield_pipe:
            off += 8 + 4 + 4 + 4 + 4 + 4 + 4 + 4 + 1 + 1 + 1 + 1 + 1
            return off
        cycle = struct.unpack_from("<Q", data, off)[0]; off += 8
        tile_index = struct.unpack_from("<I", data, off)[0]; off += 4

        if tile_filter is not None and tile_index not in tile_filter:
            off += 4 + 4 + 4 + 4 + 4 + 4 + 1 + 1 + 1 + 1 + 1
            return off

        uid = struct.unpack_from("<I", data, off)[0]; off += 4
        data_f = struct.unpack_from("<I", data, off)[0]; off += 4
        dest = struct.unpack_from("<I", data, off)[0]; off += 4
        src0 = struct.unpack_from("<I", data, off)[0]; off += 4
        src1 = struct.unpack_from("<I", data, off)[0]; off += 4
        src2 = struct.unpack_from("<I", data, off)[0]; off += 4
        stage = data[off]; off += 1
        imm = data[off]; off += 1
        cflag = data[off]; off += 1
        off += 1 + 1  # xcptn + simdi

        event = PipeEvent(
            cycle=cycle, tile_index=tile_index, uid=uid,
            data=data_f, dest=dest, src0=src0, src1=src1, src2=src2,
            stage=stage, imm=imm, cflag=cflag,
        )
        return (event, off)

    elif evt_id == 4:  # switch_pos_trace_entry
        off = _align(offset, 64)
        off += 8 + 4 + 1 + 1 + 1 + 1 + 1
        return off

    elif evt_id == 5:  # wavelet_entry
        off = _align(offset, 16)
        if not yield_wavelets:
            off += 2 + 2 + 2 + 1 + 1
            off = _align(off, 64)
            off += 8 + 2 + 2 + 2 + 2
            return off
        pe_x = struct.unpack_from("<H", data, off)[0]; off += 2
        pe_y = struct.unpack_from("<H", data, off)[0]; off += 2
        color = struct.unpack_from("<H", data, off)[0]; off += 2
        ctrlbit = struct.unpack_from("<b", data, off)[0]; off += 1
        half_wavelet = struct.unpack_from("<b", data, off)[0]; off += 1
        off = _align(off, 64)
        cycle = struct.unpack_from("<Q", data, off)[0]; off += 8
        wvlt_cnt = struct.unpack_from("<H", data, off)[0]; off += 2
        wvlt_idx = struct.unpack_from("<H", data, off)[0]; off += 2
        wvlt_data = struct.unpack_from("<H", data, off)[0]; off += 2
        event_type = struct.unpack_from("<H", data, off)[0]; off += 2

        if pe_filter is not None and (pe_x, pe_y) not in pe_filter:
            return off

        event = WaveletEvent(
            cycle=cycle, pe_x=pe_x, pe_y=pe_y, color=color,
            ctrlbit=ctrlbit, half_wavelet=half_wavelet,
            wvlt_cnt=wvlt_cnt, wvlt_idx=wvlt_idx, wvlt_data=wvlt_data,
            event_type=event_type,
        )
        return (event, off)

    elif evt_id == 6:  # wavelet_trace_entry
        off = _align(offset, 64)
        off += 8 + 8 + 4 + 2 + 2
        off = _align(off, 32)
        off += 4
        return off

    else:
        raise ValueError(f"Unknown event id {evt_id}")


# --------------------------------------------------------------------------- #
#  Simulator-output convenience
# --------------------------------------------------------------------------- #

def resolve_trace_dir(out_dir, override=None):
    """Return a `simfab_traces/` directory that contains `stream0`.

    Depending on how the simulator was invoked, `simfab_traces/` may live
    inside `out_dir`, next to it, or in the working directory. We try, in order:

      - `override` (the --trace-dir flag), if provided
      - `<out_dir>/simfab_traces`
      - `./simfab_traces`
      - `<parent of out_dir>/simfab_traces`

    Raises FileNotFoundError with a helpful message if none of those works.
    """
    def _has_stream(d):
        return os.path.isfile(os.path.join(d, "stream0"))

    if override:
        d = os.path.abspath(override)
        if not _has_stream(d):
            raise FileNotFoundError(
                f"Trace directory '{override}' does not contain stream0"
            )
        return d

    out_dir_abs = os.path.abspath(out_dir)
    candidates = [
        os.path.join(out_dir_abs, "simfab_traces"),
        os.path.join(out_dir_abs, "out", "simfab_traces"),
        os.path.join(os.getcwd(), "simfab_traces"),
        os.path.join(os.path.dirname(out_dir_abs), "simfab_traces"),
    ]
    seen = set()
    for c in candidates:
        c = os.path.abspath(c)
        if c in seen:
            continue
        seen.add(c)
        if _has_stream(c):
            return c

    raise FileNotFoundError(
        "Could not locate simfab_traces/stream0. Pass --trace-dir <path> to "
        "set it explicitly. Tried:\n  " + "\n  ".join(sorted(seen))
    )


def read_grid_dims(trace_dir):
    """Return (grid_width, grid_height) read from <trace_dir>/global_simdata.json."""
    import json
    with open(os.path.join(trace_dir, "global_simdata.json")) as f:
        simdata = json.load(f)
    return simdata["xsize"], simdata["ysize"]


def stream0_path(trace_dir):
    return os.path.join(trace_dir, "stream0")

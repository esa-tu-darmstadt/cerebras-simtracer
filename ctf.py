"""
ctf: Shared CTF trace + ELF parsing primitives for simtracer / pe_trace.

Parses Cerebras simulator CTF streams (barectf-generated) and provides ELF
symbol lookup utilities. The dispatch trace (event id=2) records every
instruction issue; the pipe trace (event id=3) records the resolved operand
values at later pipeline stages (only stage=6 has real values — earlier
stages contain 0xFFFFFFFF sentinels).
"""

import bisect
import mmap
import os
import re
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
    """Architecture-specific constants for a WSE generation.

    The jump encodings below are used to classify control transfers during
    call-stack reconstruction. `jmp <reg>` shares an opcode across all
    registers and differs only in the register field, so the register-indirect
    form is matched with a mask that clears that field; `jmp r15` is then the
    one member of that family that denotes a function return.
    """
    version: int
    name: str
    jmp_r15: int       # encoding of `jmp r15` (function return)
    jmp_r15_mask: int  # mask to apply to inst_bin before comparing
    jmp_reg: int       # encoding of `jmp <reg>` with the register field cleared
    jmp_reg_mask: int  # mask that clears the register field


# ELF e_flags -> WSE generation: 0x0=WSE1, 0x1=WSE2, 0x2=WSE3
#
# WSE2 encodes the jump register in bits [14:11] (`jmp r15` = 0x7c6f,
# `jmp r8` = 0x446f); WSE3 encodes it in bits [9:6] (`jmp r15` = 0x6d8003c0,
# `jmp r8` = 0x6d800200). Both were read off dispatch traces whose mnemonic
# field the simulator reports as JMP.
WSE_ARCHS = {
    0x1: WSEArch(version=2, name="neumann",     jmp_r15=0x7C6F,     jmp_r15_mask=0xFFFF,
                 jmp_reg=0x046F,     jmp_reg_mask=0x87FF),
    0x2: WSEArch(version=3, name="schrödinger", jmp_r15=0x6D8003C0, jmp_r15_mask=0xFFFFFFFF,
                 jmp_reg=0x6D800000, jmp_reg_mask=0xFFFFFC3F),
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
EVT_ID = struct.Struct("<Q")         # event id alone; timestamp read lazily
EVT_HDR_SIZE = EVT_HDR.size

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
    segments: tile_index = (segment.p_paddr >> 40) & 0xFFFFFF, where
    tile_index = fabric_y * grid_width + fabric_x. Shared ELFs have one PT_LOAD
    per target tile. (The mask is 24-bit: a full WSE-3 fabric tile index
    fabric_y*762+fabric_x reaches ~892k, so a 16-bit mask silently wraps every
    tile below row ~86 onto a wrong index.)
    """
    mapping = {}
    for elf_path in elf_lookups:
        elf_name = os.path.basename(elf_path)
        tile_indices = set()
        with open(elf_path, "rb") as f:
            elf = ELFFile(f)
            for seg in elf.iter_segments():
                if seg["p_type"] == "PT_LOAD":
                    tile_idx = (seg["p_paddr"] >> 40) & 0xFFFFFF
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


@dataclass
class BackpressureEvent:
    """backpressure_trace_entry (event id=0): per-link fabric backpressure level.

    By far the most frequent event in a typical trace. `back_pressure` is a
    level (not a rate); `link` selects which fabric link/queue on the tile.
    """
    cycle: int
    tile_index: int
    back_pressure: int
    link: int


@dataclass
class DebugCountersEvent:
    """debug_counters_wavelet (event id=1): cumulative per-(PE, color) counts.

    Has no `cycle` field in the trace; `cycle` is taken from the CTF event
    header timestamp.
    """
    cycle: int
    pe_x: int
    pe_y: int
    color: int
    count_w: int
    count_t: int
    count_s: int


@dataclass
class SwitchPosEvent:
    """switch_pos_trace_entry (event id=4): router switch configuration."""
    cycle: int
    tile_index: int
    color: int
    input_pos: int
    input_mask: int
    output_pos: int
    output_mask: int


@dataclass
class WaveletTraceEvent:
    """wavelet_trace_entry (event id=6): per-wavelet fabric event.

    The wavelet stream emitted by these simulator builds. `ident` is a packed
    wavelet/route identifier; `data` is the 16-bit payload; `fields` is a packed
    control word; `index` is the color/route slot; `tile_index` is the PE.
    """
    cycle: int
    ident: int
    tile_index: int
    index: int
    data: int
    fields: int


@dataclass
class Event:
    """Generic fallback for event ids without a dedicated dataclass."""
    id: int
    name: str
    cycle: int
    fields: dict


# --------------------------------------------------------------------------- #
#  CTF metadata schema (barectf 1.8 text format)
# --------------------------------------------------------------------------- #

# struct fmt char for an (size_bits, signed) integer.
_INT_FMT = {
    (8, False): "B", (8, True): "b",
    (16, False): "H", (16, True): "h",
    (32, False): "I", (32, True): "i",
    (64, False): "Q", (64, True): "q",
}


@dataclass
class FieldSpec:
    name: str
    is_str: bool
    fmt: str      # struct format char, "" for strings
    nbytes: int   # 0 for strings
    align: int    # alignment in bits


@dataclass
class _Layout:
    """Precomputed decode plan for an event at one start-parity.

    CTF field alignment is relative to the enclosing packet start, and every
    field here aligns to at most 8 bytes, so an event's exact byte layout is
    fully determined by ``(offset - pkt_start) % 8``. For each of the 8 parities
    we precompute a single ``struct.Struct`` covering the contiguous fixed
    prefix (with inter-field padding baked in as ``x`` bytes), turning per-field
    Python iteration into one ``unpack_from`` call. Only the mnemonic string in
    the dispatch event (always the last field) needs the slow path.
    """
    prefix_struct: "struct.Struct"  # all fixed fields up to the first string
    prefix_names: tuple             # names matching prefix_struct's outputs
    prefix_size: int                # bytes from offset to end of prefix / string start
    string_name: str                # name of the string field, or None
    tail_fields: tuple              # fields after the string (general path; rare)
    fixed_size: int                 # total event size when there is no string, else None


class EventType:
    """A trace event's name + ordered field layout, with decode/skip.

    Layouts are precomputed once per start-parity in ``__init__``; ``decode`` and
    ``skip`` then index by ``(offset - pkt_start) & 7`` and avoid the per-field
    loop entirely (a single ``struct.unpack_from`` for decode, a constant add for
    skipping a fixed-size event).
    """

    def __init__(self, eid, name, fields):
        self.id = eid
        self.name = name
        self.fields = fields
        self._layouts = tuple(self._build_layout(p) for p in range(8))

    def _build_layout(self, start_mod):
        pos = start_mod          # byte position relative to pkt_start (only %8 matters)
        fmt = "<"
        names = []
        i, n = 0, len(self.fields)
        while i < n and not self.fields[i].is_str:
            f = self.fields[i]
            aligned = align_up(pos, f.align)
            if aligned != pos:
                fmt += "%dx" % (aligned - pos)
            fmt += f.fmt
            names.append(f.name)
            pos = aligned + f.nbytes
            i += 1
        if i == n:
            st = struct.Struct(fmt)
            return _Layout(st, tuple(names), st.size, None, (), st.size)
        # fields[i] is a string (the dispatch mnemonic): fold its leading pad
        # into the prefix so prefix_size lands exactly on the string start.
        f = self.fields[i]
        aligned = align_up(pos, f.align)
        if aligned != pos:
            fmt += "%dx" % (aligned - pos)
        st = struct.Struct(fmt)
        return _Layout(st, tuple(names), st.size, f.name,
                       tuple(self.fields[i + 1:]), None)

    def decode(self, data, pkt_start, offset):
        """Return (values dict, new offset)."""
        lay = self._layouts[(offset - pkt_start) & 7]
        vals = dict(zip(lay.prefix_names,
                        lay.prefix_struct.unpack_from(data, offset)))
        if lay.string_name is None:
            return vals, offset + lay.fixed_size
        off = offset + lay.prefix_size
        end = data.find(b"\x00", off)
        if end < 0:
            raise ValueError("unterminated string field")
        vals[lay.string_name] = data[off:end].decode("utf-8", errors="replace")
        off = end + 1
        for f in lay.tail_fields:  # fields after a string — empty for known events
            off = align_up(off - pkt_start, f.align) + pkt_start
            vals[f.name] = struct.unpack_from("<" + f.fmt, data, off)[0]
            off += f.nbytes
        return vals, off

    def skip(self, data, pkt_start, offset):
        """Advance past this event without materializing field values."""
        lay = self._layouts[(offset - pkt_start) & 7]
        if lay.fixed_size is not None:
            return offset + lay.fixed_size
        off = data.find(b"\x00", offset + lay.prefix_size)
        if off < 0:
            raise ValueError("unterminated string field")
        off += 1
        for f in lay.tail_fields:
            off = align_up(off - pkt_start, f.align) + pkt_start
            off += f.nbytes
        return off


_BLOCK_KEYWORD = "event {"
_FIELD_RE = re.compile(
    r"(?:integer\s*\{(?P<props>[^}]*)\}|string\s*\{[^}]*\})\s*(?P<name>\w+)\s*;")
_ID_RE = re.compile(r"(?m)^\s*id\s*=\s*(\d+)\s*;")
_NAME_RE = re.compile(r'name\s*=\s*"([^"]*)"')


def _iter_event_blocks(text):
    """Yield the brace-delimited body of each top-level `event { ... }` block."""
    i = 0
    while True:
        j = text.find(_BLOCK_KEYWORD, i)
        if j < 0:
            return
        k = text.find("{", j)
        depth = 0
        m = k
        while m < len(text):
            if text[m] == "{":
                depth += 1
            elif text[m] == "}":
                depth -= 1
                if depth == 0:
                    break
            m += 1
        yield text[k + 1:m]
        i = m + 1


def parse_metadata(metadata_path):
    """Parse a barectf CTF metadata file into {event_id: EventType}."""
    with open(metadata_path) as f:
        text = f.read()
    schema = {}
    for block in _iter_event_blocks(text):
        eid = int(_ID_RE.search(block).group(1))
        name = _NAME_RE.search(block).group(1)
        fields = []
        for m in _FIELD_RE.finditer(block):
            props = m.group("props")
            if props is None:  # string field
                fields.append(FieldSpec(m.group("name"), True, "", 0, 8))
            else:
                signed = "signed = true" in props
                size = int(re.search(r"size\s*=\s*(\d+)", props).group(1))
                align = int(re.search(r"align\s*=\s*(\d+)", props).group(1))
                fields.append(FieldSpec(m.group("name"), False,
                                        _INT_FMT[(size, signed)], size // 8, align))
        schema[eid] = EventType(eid, name, fields)
    return schema


def _build_event(eid, name, vals, cycle):
    """Map a decoded field dict onto a typed event (generic Event otherwise)."""
    if eid == 2:
        return DispatchEvent(
            cycle=cycle, tile_index=vals["tile_index"], inst_ptr=vals["inst_ptr"],
            inst_bin=vals["inst_bin"], term_op=vals["term_op"],
            task_color=vals["task_color"], name=vals["name"], uid=vals["uid"])
    if eid == 3:
        return PipeEvent(
            cycle=cycle, tile_index=vals["tile_index"], uid=vals["uid"],
            data=vals["data"], dest=vals["dest"], src0=vals["src0"],
            src1=vals["src1"], src2=vals["src2"], stage=vals["stage"],
            imm=vals["imm"], cflag=vals["cflag"])
    if eid == 0:
        return BackpressureEvent(
            cycle=cycle, tile_index=vals["tile_index"],
            back_pressure=vals["back_pressure"], link=vals["link"])
    if eid == 1:
        return DebugCountersEvent(
            cycle=cycle, pe_x=vals["PE_x"], pe_y=vals["PE_y"], color=vals["color"],
            count_w=vals["count_w"], count_t=vals["count_t"], count_s=vals["count_s"])
    if eid == 4:
        return SwitchPosEvent(
            cycle=cycle, tile_index=vals["tile_index"], color=vals["color"],
            input_pos=vals["input_pos"], input_mask=vals["input_mask"],
            output_pos=vals["output_pos"], output_mask=vals["output_mask"])
    if eid == 6:
        return WaveletTraceEvent(
            cycle=cycle, ident=vals["ident"], tile_index=vals["tile_index"],
            index=vals["index"], data=vals["data"], fields=vals["fields"])
    return Event(id=eid, name=name, cycle=cycle, fields=vals)


# --------------------------------------------------------------------------- #
#  CTF stream parser
# --------------------------------------------------------------------------- #

def parse_ctf_stream(stream_path, want_ids=(2,), tile_filter=None,
                     pe_filter=None, cycle_range=None, progress=None,
                     metadata_path=None):
    """
    Parse a CTF stream file and yield typed event objects in trace order.

    The per-event field layout is read from the trace's CTF metadata file, so
    any event the schema describes can be decoded. Each yielded event is a
    typed dataclass for the known ids (see `_build_event`) or a generic `Event`
    otherwise.

    Args:
        stream_path: path to stream0.
        want_ids: iterable of event ids to decode and yield (default: dispatch
            only, id=2). Events whose id is not requested are skipped cheaply.
        tile_filter: set of tile indices to keep (applies to events carrying a
            `tile_index` field), or None for all.
        pe_filter: set of (PE_x, PE_y) tuples to keep (applies to events
            carrying PE_x/PE_y, e.g. id=1 debug counters), or None for all.
        cycle_range: optional (start, end) — yields events with
            start <= cycle < end. `end` may be None (open-ended); streaming
            stops once we pass `end`. The cycle comes from the event's `cycle`
            field, else its `timestamp` field, else the CTF header timestamp.
        progress: optional tqdm instance updated with bytes consumed.
        metadata_path: path to the CTF metadata; defaults to a file named
            `metadata` next to `stream_path`.
    """
    if metadata_path is None:
        metadata_path = os.path.join(os.path.dirname(stream_path), "metadata")
    schema = parse_metadata(metadata_path)
    want = set(want_ids)

    cyc_start = cycle_range[0] if cycle_range else None
    cyc_end = cycle_range[1] if cycle_range else None

    file_size = os.path.getsize(stream_path)
    if file_size == 0:
        return

    with open(stream_path, "rb") as f:
        # mmap the whole stream: packets are walked in place with no chunk
        # boundary handling and no per-chunk copy. struct.unpack_from / .find
        # operate on the mapping directly.
        data = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            offset = 0
            last_progress = 0
            stopped = False

            while offset + PKT_OVERHEAD < file_size and not stopped:
                magic, _stream_id = PKT_HDR.unpack_from(data, offset)
                if magic != CTF_MAGIC:
                    offset += 1
                    continue

                pkt_start = offset
                pkt_size = struct.unpack_from("<Q", data, offset + PKT_HDR.size)[0] // 8
                content_size = struct.unpack_from("<Q", data, offset + PKT_HDR.size + 8)[0] // 8

                if pkt_start + pkt_size > file_size:
                    break  # truncated trailing packet

                content_end = pkt_start + content_size
                evt_offset = pkt_start + PKT_OVERHEAD

                # The packet header carries a timestamp_begin we could use to
                # skip whole packets outside cycle_range, but cycles and CTF
                # timestamps are not the same scale; rely on per-event filter.
                while evt_offset + EVT_HDR_SIZE <= content_end:
                    evt_id = EVT_ID.unpack_from(data, evt_offset)[0]
                    # event header is id(u64) + timestamp(u64); the timestamp is
                    # only a cycle fallback (read lazily below) so skip past both.
                    hdr_offset = evt_offset
                    evt_offset += EVT_HDR_SIZE

                    et = schema.get(evt_id)
                    if et is None:
                        evt_offset = content_end  # unknown layout — bail packet
                        break
                    try:
                        if evt_id not in want:
                            evt_offset = et.skip(data, pkt_start, evt_offset)
                            continue
                        vals, evt_offset = et.decode(data, pkt_start, evt_offset)
                    except (struct.error, IndexError, ValueError):
                        evt_offset = content_end
                        break

                    tile = vals.get("tile_index")
                    if tile_filter is not None and tile is not None and tile not in tile_filter:
                        continue
                    if pe_filter is not None and "PE_x" in vals \
                            and (vals["PE_x"], vals["PE_y"]) not in pe_filter:
                        continue

                    cycle = vals.get("cycle")
                    if cycle is None:
                        cycle = vals.get("timestamp")
                        if cycle is None:  # neither field present — CTF header ts
                            cycle = EVT_ID.unpack_from(data, hdr_offset + 8)[0]
                    if cyc_start is not None and cycle < cyc_start:
                        continue
                    if cyc_end is not None and cycle >= cyc_end:
                        stopped = True
                        break

                    yield _build_event(evt_id, et.name, vals, cycle)

                offset = pkt_start + pkt_size

                if progress is not None:
                    progress.update(offset - last_progress)
                    last_progress = offset

            if progress is not None and not stopped:
                progress.update(file_size - last_progress)
        finally:
            data.close()


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


# --------------------------------------------------------------------------- #
#  Multi-stream support
# --------------------------------------------------------------------------- #
#
# The simulator splits its CTF trace across N stream files (stream0..stream{N-1})
# inside simfab_traces/. global_simdata.json describes the split:
#   "traceFiles": N            — number of stream files
#   "streamMap": [ {"tileId": int, "streamId": int}, ... ]
#                              — which stream file each tile's events land in;
#                                streamId == -1 means the tile was not traced.
# A single tile's events live entirely in one stream, so per-tile queries read
# only that one file. Older single-stream traces have no traceFiles/streamMap;
# they fall back to one file (stream0) holding every tile.


def read_stream_map(trace_dir):
    """Return (num_files, tile_to_stream) parsed from global_simdata.json.

    `num_files` is the number of stream files (>= 1). `tile_to_stream` maps a
    tile index to its stream id; tiles with streamId == -1 (untraced) are
    omitted. For an old/single-stream trace (no traceFiles or no streamMap),
    returns (1, {}) — meaning "one file, stream0, holds everything".
    """
    import json
    path = os.path.join(trace_dir, "global_simdata.json")
    try:
        with open(path) as f:
            simdata = json.load(f)
    except FileNotFoundError:
        return 1, {}
    num_files = int(simdata.get("traceFiles", 1) or 1)
    tile_to_stream = {}
    for entry in simdata.get("streamMap", []) or []:
        sid = entry["streamId"]
        if sid < 0:
            continue
        tile_to_stream[entry["tileId"]] = sid
    return num_files, tile_to_stream


def stream_paths(trace_dir):
    """Return the ordered list of existing stream{i} file paths.

    Indexed 0..num_files-1, skipping any that are absent on disk. Always
    includes stream0 if present (single-stream back-compat).
    """
    num_files, _ = read_stream_map(trace_dir)
    paths = []
    for i in range(num_files):
        p = os.path.join(trace_dir, f"stream{i}")
        if os.path.isfile(p):
            paths.append(p)
    if not paths:  # defensive: at least try stream0
        p = stream0_path(trace_dir)
        if os.path.isfile(p):
            paths.append(p)
    return paths


def stream_of_tile(trace_dir, tile):
    """Return the stream id (int) that holds tile `tile`'s events.

    Falls back to 0 when the trace has no streamMap (single-stream) or the tile
    is absent from the map (treated as stream0 for back-compat).
    """
    _num, tile_to_stream = read_stream_map(trace_dir)
    return tile_to_stream.get(tile, 0)


def streams_for_tiles(trace_dir, tiles):
    """Return the sorted list of stream{i} file paths that hold any of `tiles`.

    Consults the streamMap so a per-tile/per-PE query reads ONLY the relevant
    stream file(s), never scanning every stream for one tile.
    """
    _num, tile_to_stream = read_stream_map(trace_dir)
    want_sids = {tile_to_stream.get(t, 0) for t in tiles}
    paths = []
    for sid in sorted(want_sids):
        p = os.path.join(trace_dir, f"stream{sid}")
        if os.path.isfile(p):
            paths.append(p)
    return paths


def streams_total_size(paths):
    """Sum of byte sizes of the given stream file paths (for progress bars)."""
    return sum(os.path.getsize(p) for p in paths)


# --------------------------------------------------------------------------- #
#  Cross-stream parallelism
# --------------------------------------------------------------------------- #
#
# The streams are independent files and a tile lives entirely in one stream, so
# any whole-trace consumer whose per-tile work is independent (event counts,
# per-tile call-stack reconstruction, per-tile Perfetto packets) can process
# each stream in its own process and combine the compact per-stream results.
# With 20 streams on a many-core node this is the dominant whole-trace speedup,
# multiplying on top of the faster per-event decode.


def default_jobs(num_paths):
    """Worker count for a parallel scan: one per stream, capped at the CPU count."""
    return max(1, min(num_paths, os.cpu_count() or 1))


def parallel_streams(paths, worker, args=(), jobs=None,
                     initializer=None, initargs=()):
    """Run ``worker(path, *args)`` over ``paths``, yielding ``(path, result)``.

    Results are yielded as each stream finishes (not in ``paths`` order). With
    ``jobs <= 1`` or a single path the work runs inline in this process (no pool,
    easy to profile/debug); otherwise it fans out across a process pool sized by
    ``default_jobs``. ``initializer``/``initargs`` run once per worker process —
    use them to stash large read-only state (ELF symbol tables, the tile→ELF
    map) in worker globals instead of pickling it per task.

    ``worker`` and ``initializer`` must be importable top-level callables, and
    every ``result`` must be picklable. Keep results compact (counts, per-tile
    summaries, a temp-file path) — never the raw event stream.
    """
    if jobs is None:
        jobs = default_jobs(len(paths))
    if jobs <= 1 or len(paths) <= 1:
        if initializer is not None:
            initializer(*initargs)
        for p in paths:
            yield p, worker(p, *args)
        return

    import concurrent.futures as futures
    with futures.ProcessPoolExecutor(max_workers=jobs, initializer=initializer,
                                     initargs=initargs) as ex:
        fut_to_path = {ex.submit(worker, p, *args): p for p in paths}
        for fut in futures.as_completed(fut_to_path):
            yield fut_to_path[fut], fut.result()


def elf_of_tile(tile_elf_mapping, tile):
    """Return the ELF path for `tile`, or None.

    `tile_elf_mapping` is the dict returned by `build_elf_mapping`. This is the
    clean supported "given a tile, find its ELF" lookup; equivalent to
    `build_elf_mapping(...).get(tile)`.
    """
    return tile_elf_mapping.get(tile)


def _heap_merge_streams(generators):
    """Merge per-stream event generators into one cycle-ordered stream.

    Each input generator is already in trace (cycle) order, so a k-way heap
    merge on `.cycle` yields a globally cycle-ordered stream.
    """
    import heapq

    def keyed(idx, gen):
        for evt in gen:
            yield evt.cycle, idx, evt

    yield from (evt for _cyc, _idx, evt in
                heapq.merge(*(keyed(i, g) for i, g in enumerate(generators)),
                            key=lambda t: (t[0], t[1])))


def parse_ctf_trace(trace_dir, want_ids=(2,), tile_filter=None, pe_filter=None,
                    cycle_range=None, progress=None, merge=True,
                    grid_width=None):
    """Parse a (possibly multi-stream) CTF trace and yield typed events.

    Picks the stream file(s) to read from the streamMap:
      * `tile_filter` set  -> read only the stream(s) holding those tiles.
      * `pe_filter` set    -> map each (PE_x, PE_y) to tile = PE_y*grid_width +
                              PE_x (needs `grid_width`) and read those stream(s).
      * neither            -> read every stream file.

    A single tile lives entirely in one stream, so a per-tile query needs no
    cross-stream merge. For whole-trace consumers that need cycle order, pass
    `merge=True` (default) to heap-merge the per-stream generators; pass
    `merge=False` to simply concatenate the streams (cheaper, fine for pure
    count aggregation like the `tiles` command).

    The `tile_filter` / `pe_filter` are still applied per-event inside
    `parse_ctf_stream`, so passing both a filter and an over-broad stream set is
    always correct (just less efficient).
    """
    tiles = set()
    if tile_filter is not None:
        tiles |= set(tile_filter)
    if pe_filter is not None:
        if grid_width is None:
            raise ValueError("pe_filter requires grid_width to pick streams")
        tiles |= {py * grid_width + px for (px, py) in pe_filter}

    if tiles:
        paths = streams_for_tiles(trace_dir, tiles)
    else:
        paths = stream_paths(trace_dir)

    metadata_path = os.path.join(trace_dir, "metadata")

    def gen_for(path):
        return parse_ctf_stream(
            path, want_ids=want_ids, tile_filter=tile_filter,
            pe_filter=pe_filter, cycle_range=cycle_range, progress=progress,
            metadata_path=metadata_path)

    if len(paths) <= 1:
        for path in paths:
            yield from gen_for(path)
        return

    if merge:
        yield from _heap_merge_streams([gen_for(p) for p in paths])
    else:
        for path in paths:
            yield from gen_for(path)

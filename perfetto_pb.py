"""
perfetto_pb: A tiny, dependency-free writer for Perfetto protobuf traces.

Perfetto's native trace format is a length-delimited stream of `TracePacket`
messages (the root `Trace` message is just `repeated TracePacket packet = 1`).
We hand-encode the small subset of the schema we need rather than pulling in a
generated `perfetto_trace_pb2` module — it keeps simtracer's dependency list at
`pyelftools` + `tqdm`, avoids protobuf-runtime version skew, and the field
numbers below are stable Perfetto API.

Field numbers are taken from Perfetto's
`protos/perfetto/trace/{trace_packet,track_event/*}.proto`. They are pinned as
named constants next to each builder so the wire layout is auditable.

Model we emit:
  * one *process* track per tile (groups the tile's rows in the UI)
  * child *slice* tracks (call-stack flamegraph, wavelet instant events)
  * child *counter* tracks (per-bin rates)
Each tile is its own packet sequence (`trusted_packet_sequence_id`), and its
events are written in cycle order so slice begin/end nesting and same-timestamp
ties resolve in trace order. Names are inlined on each event (no interned-data
incremental state) — simpler and correct-by-construction; gzip handles the
resulting string repetition well, and the writer can gzip transparently.

Timestamps are simulator cycles written directly as the packet timestamp (the
UI labels the axis "ns"; read it as cycles — 1 tick = 1 cycle).
"""

import gzip
import struct

# --------------------------------------------------------------------------- #
#  Low-level protobuf wire encoding
# --------------------------------------------------------------------------- #

_WIRE_VARINT = 0
_WIRE_64BIT = 1
_WIRE_LEN = 2


def _varint(n):
    """Encode an unsigned (or two's-complement int64) varint."""
    if n < 0:
        n += 1 << 64
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _tag(field, wire):
    return _varint((field << 3) | wire)


def _f_varint(field, value):
    return _tag(field, _WIRE_VARINT) + _varint(value)


def _f_fixed64(field, value):
    return _tag(field, _WIRE_64BIT) + struct.pack("<Q", value)


def _f_double(field, value):
    return _tag(field, _WIRE_64BIT) + struct.pack("<d", value)


def _f_bytes(field, data):
    return _tag(field, _WIRE_LEN) + _varint(len(data)) + data


def _f_string(field, s):
    return _f_bytes(field, s.encode("utf-8"))


# --------------------------------------------------------------------------- #
#  TrackEvent.Type
# --------------------------------------------------------------------------- #

TYPE_SLICE_BEGIN = 1
TYPE_SLICE_END = 2
TYPE_INSTANT = 3
TYPE_COUNTER = 4


# --------------------------------------------------------------------------- #
#  Message builders (return raw message bytes)
# --------------------------------------------------------------------------- #

# --- ProcessDescriptor (process track) ---
#   int32  pid          = 1
#   string process_name = 6
def _process_descriptor(pid, name):
    return _f_varint(1, pid) + _f_string(6, name)


# --- CounterDescriptor (counter track) ---
#   string unit_name      = 6
#   bool   is_incremental = 5
def _counter_descriptor(unit_name=None, is_incremental=False):
    b = b""
    if unit_name:
        b += _f_string(6, unit_name)
    if is_incremental:
        b += _f_varint(5, 1)
    return b


# --- TrackDescriptor ---
#   uint64            uuid        = 1
#   string            name        = 2
#   ProcessDescriptor process     = 3
#   uint64            parent_uuid = 5
#   CounterDescriptor counter     = 8   (NB: field 6 is chrome_process)
def track_descriptor(uuid, name=None, parent_uuid=None,
                     process=None, counter=None):
    b = _f_varint(1, uuid)
    if name is not None:
        b += _f_string(2, name)
    if process is not None:
        b += _f_bytes(3, process)
    if parent_uuid is not None:
        b += _f_varint(5, parent_uuid)
    if counter is not None:
        b += _f_bytes(8, counter)
    return b


# --- DebugAnnotation ---
#   string name         = 10
#   bool   bool_value   = 2
#   uint64 uint_value   = 4
#   int64  int_value    = 5
#   string string_value = 7
def _debug_annotation(name, value):
    b = _f_string(10, name)
    if isinstance(value, bool):
        b += _f_varint(2, 1 if value else 0)
    elif isinstance(value, int):
        if value < 0:
            b += _tag(5, _WIRE_VARINT) + _varint(value)   # int_value (signed)
        else:
            b += _f_varint(4, value)                       # uint_value
    else:
        b += _f_string(7, str(value))
    return b


# --- TrackEvent ---
#   repeated DebugAnnotation debug_annotations    = 4
#   Type                     type                 = 9
#   uint64                   track_uuid           = 11
#   string                   name                 = 23
#   int64                    counter_value        = 30
#   double                   double_counter_value = 44
#   repeated fixed64         flow_ids             = 47
def track_event(track_uuid, type_, name=None, counter_value=None,
                double_counter_value=None, flow_ids=(), annotations=None):
    b = _f_varint(9, type_) + _f_varint(11, track_uuid)
    if name is not None:
        b += _f_string(23, name)
    if counter_value is not None:
        b += _tag(30, _WIRE_VARINT) + _varint(counter_value)
    if double_counter_value is not None:
        b += _f_double(44, double_counter_value)
    for fid in flow_ids:
        b += _f_fixed64(47, fid)
    if annotations:
        for k, v in annotations.items():
            b += _f_bytes(4, _debug_annotation(k, v))
    return b


# --------------------------------------------------------------------------- #
#  TracePacket assembly + streaming writer
# --------------------------------------------------------------------------- #

# TracePacket field numbers:
#   uint64          timestamp                   = 8
#   uint32          trusted_packet_sequence_id  = 10
#   TrackEvent      track_event                 = 11
#   TrackDescriptor track_descriptor            = 60
_PKT_TIMESTAMP = 8
_PKT_SEQ_ID = 10
_PKT_TRACK_EVENT = 11
_PKT_TRACK_DESCRIPTOR = 60

# Trace.packet = 1
_TRACE_PACKET = 1


class TraceWriter:
    """Streams `TracePacket`s into a Perfetto trace file.

    If `path` ends with ``.gz`` the output is gzip-compressed (the Perfetto UI
    and trace_processor both auto-detect gzip).
    """

    def __init__(self, path):
        self._gz = path.endswith(".gz")
        self._f = gzip.open(path, "wb") if self._gz else open(path, "wb")

    def _emit(self, packet_bytes):
        self._f.write(_f_bytes(_TRACE_PACKET, packet_bytes))

    def descriptor(self, desc_bytes, seq_id):
        self._emit(_f_varint(_PKT_SEQ_ID, seq_id)
                   + _f_bytes(_PKT_TRACK_DESCRIPTOR, desc_bytes))

    def event(self, event_bytes, seq_id, timestamp):
        self._emit(_f_varint(_PKT_TIMESTAMP, timestamp)
                   + _f_varint(_PKT_SEQ_ID, seq_id)
                   + _f_bytes(_PKT_TRACK_EVENT, event_bytes))

    def close(self):
        self._f.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

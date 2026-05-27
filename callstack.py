"""
callstack: Output-agnostic call-stack reconstruction from a CTF dispatch stream.

Both simflame (speedscope) and simperfetto (Perfetto protobuf) need the same
per-tile call-stack timeline; this module owns that state machine so the two
exporters can never drift apart. It consumes DispatchEvents and yields a flat
stream of frame open/close events that each exporter renders in its own format.

The state machine, per tile:
  * the active task color is the outermost frame ("task N");
  * function frames nest within it, opened on entry-point hits and closed on
    `jmp r15` returns (architecture-specific encoding) or when the function
    reappears lower on the stack;
  * a task switch or task terminator (.term) unwinds the whole stack.

Yields tuples ``(kind, tile_index, label, cycle)`` where ``kind`` is ``"O"``
(open) or ``"C"`` (close) and ``label`` is a function name or ``"task N"``.
"""

from collections import Counter
from dataclasses import dataclass, field


@dataclass
class _TileState:
    call_stack: list = field(default_factory=list)
    prev_func: str = None
    current_task: int = -1
    first_cycle: int = 0
    last_cycle: int = 0


def reconstruct(events, tile_elf_mapping, elf_lookups, stats=None):
    """Yield ``(kind, tile_index, label, cycle)`` frame open/close events.

    Args:
        events: iterable of DispatchEvent (in trace order).
        tile_elf_mapping: tile_index -> elf_path.
        elf_lookups: elf_path -> SymbolLookup.
        stats: optional Counter, populated in place with counts for keys
            ``events``, ``calls``, ``returns``, ``task_switches``,
            ``task_terms`` (useful for a one-line summary).
    """
    if stats is None:
        stats = Counter()
    states = {}

    def get_state(tile_idx):
        st = states.get(tile_idx)
        if st is None:
            st = states[tile_idx] = _TileState()
        return st

    for evt in events:
        tile_idx = evt.tile_index
        stats["events"] += 1

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
            stats["task_switches"] += 1
            for fn in reversed(state.call_stack):
                yield ("C", tile_idx, fn, evt.cycle)
            state.call_stack.clear()
            if state.current_task >= 0:
                yield ("C", tile_idx, f"task {state.current_task}", evt.cycle)
            state.current_task = evt.task_color
            yield ("O", tile_idx, f"task {evt.task_color}", evt.cycle)
            state.prev_func = None

        if evt.term_op == 1:
            stats["task_terms"] += 1
            for fn in reversed(state.call_stack):
                yield ("C", tile_idx, fn, evt.cycle)
            state.call_stack.clear()
            if state.current_task >= 0:
                yield ("C", tile_idx, f"task {state.current_task}", evt.cycle)
                state.current_task = -1
            state.prev_func = None
            continue

        arch = lookup.arch
        if evt.inst_bin & arch.jmp_r15_mask == arch.jmp_r15:
            stats["returns"] += 1
            if state.call_stack:
                top = state.call_stack[-1]
                yield ("C", tile_idx, top, evt.cycle)
                state.call_stack.pop()
            state.prev_func = state.call_stack[-1] if state.call_stack else None
            continue

        if func_name != state.prev_func:
            if is_entry and state.prev_func is not None:
                stats["calls"] += 1
                state.call_stack.append(func_name)
                yield ("O", tile_idx, func_name, evt.cycle)
            elif not state.call_stack:
                state.call_stack.append(func_name)
                yield ("O", tile_idx, func_name, evt.cycle)
            elif func_name in state.call_stack:
                while state.call_stack and state.call_stack[-1] != func_name:
                    top = state.call_stack.pop()
                    yield ("C", tile_idx, top, evt.cycle)
            else:
                if state.call_stack:
                    top = state.call_stack.pop()
                    yield ("C", tile_idx, top, evt.cycle)
                state.call_stack.append(func_name)
                yield ("O", tile_idx, func_name, evt.cycle)

        state.prev_func = func_name

    # Flush any frames still open at end of trace.
    for tile_idx, state in states.items():
        for fn in reversed(state.call_stack):
            yield ("C", tile_idx, fn, state.last_cycle)
        state.call_stack.clear()
        if state.current_task >= 0:
            yield ("C", tile_idx, f"task {state.current_task}", state.last_cycle)
            state.current_task = -1

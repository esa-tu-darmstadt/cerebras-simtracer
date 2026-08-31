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
  * a task switch or task terminator (.term) unwinds the whole stack, except
    that a stack-switching coroutine resume re-establishes the stack the
    resumed coroutine had when it suspended (see below).

Frames are opened on entry-point hits, so a function reached by a tail jump is
nested inside the function that jumped to it rather than replacing it. The
dispatch stream cannot tell a tail jump from an indirect call — both are
`jmp <reg>`, and whether control returns depends on whether r15 was set
beforehand, which is only visible in the pipe trace — so the conservative
nesting is kept.

Yields tuples ``(kind, tile_index, label, cycle)`` where ``kind`` is ``"O"``
(open) or ``"C"`` (close) and ``label`` is a function name or ``"task N"``.
"""

from collections import Counter
from dataclasses import dataclass, field


# --------------------------------------------------------------------------- #
#  Stack-switching coroutine support
#
#  Stock CSL has no coroutines: a task runs to its terminator and the next
#  activation of that task re-enters it at its entry point. Programs built with
#  the coroutine transpiler developed at TU Darmstadt do have them. Its stackful
#  ("fiber") backend gives each async task its own stack in memory and allows it to
#  suspend itself by saving the hardware stack pointer and a resume address and then
#  terminating the task; a later activation of the same task restores that stack
#  pointer and jumps back to the resume address. Simtracer can detect that resume
#  and re-establish the call stack the coroutine suspended with.
#
#  A resume is recognised from the address stream alone — no symbol names and no
#  knowledge of the transpiler's runtime are needed. The resume address emitted
#  by that runtime is the instruction immediately following the terminator that
#  suspended the coroutine, so a resume is a control transfer that lands one
#  instruction past a terminator, inside the function that terminator was in, on
#  the task that executed it. See `_resumed_frames()` for the full set of conditions.
# --------------------------------------------------------------------------- #

# Maximum distance, in 16-bit words, from a terminator to the instruction that
# follows it. WSE instructions are either one or two words wide.
_RESUME_SKEW_WORDS = 2


def _is_indirect_jump(inst_bin, arch):
    """True if `inst_bin` is `jmp <reg>` for a register other than r15.

    This says nothing about whether control returns: an indirect call is
    `movri r15 = <return address>` followed by the same `jmp <reg>`, and the
    two are indistinguishable in the dispatch stream. The register field is
    masked out, so the register the compiler happened to allocate does not
    matter; only r15, which denotes the function return and is handled
    separately, is excluded.
    """
    return (inst_bin & arch.jmp_reg_mask == arch.jmp_reg
            and inst_bin & arch.jmp_r15_mask != arch.jmp_r15)


def _resumed_frames(state, prev_inst_bin, func_name, is_entry, evt, arch):
    """Return the call stack a suspending coroutine is resuming, or None.

    `state.suspended` holds, per task color, the frames that were open when
    that task last ran to a terminator, together with the address of the
    terminator itself. An entry is consumed when all of the following hold:

    1. an entry exists for the task color currently executing — the transpiler's
       runtime resumes a coroutine by activating the very task that suspended
       it, so a resume is always on the task that recorded the entry;
    2. the previous instruction was a register-indirect jump, which is how the
       runtime transfers control to the resume address. This is the condition
       that excludes an ordinary task whose terminator sits in the middle of a
       function and whose following block is later reached by a local branch:
       such a branch satisfies 3, 4 and 5 but is not a jump. It does not
       exclude indirect calls, which are the same instruction; condition 5
       excludes those;
    3. that jump came from a different function. An indirect jump within one
       function is a switch dispatch, which can land on the block after a
       terminator in that same function; a resume always arrives from the
       runtime, never from the function being resumed;
    4. the landing address is one instruction past the recorded terminator;
    5. the landing is inside the function named by the innermost retained frame
       and is not that function's entry point. A resume address is mid-function
       by construction, which is what distinguishes it both from the case where
       a terminator ends a function and an unrelated function begins at the
       very next address, and from an indirect call, which targets an entry
       point.
    """
    entry = state.suspended.get(state.current_task)
    if entry is None:
        return None
    frames, term_ip = entry
    if not _is_indirect_jump(prev_inst_bin, arch):
        return None
    if func_name == state.prev_func:
        return None
    if not 0 < evt.inst_ptr - term_ip <= _RESUME_SKEW_WORDS:
        return None
    if is_entry or func_name != frames[-1]:
        return None
    del state.suspended[state.current_task]
    return frames


@dataclass
class _TileState:
    call_stack: list = field(default_factory=list)
    # Logical frames nested inside call_stack[-1]. They come from DWARF and
    # never participate in physical call/return or coroutine-resume state.
    inline_stack: list = field(default_factory=list)
    prev_func: str = None
    prev_inst_bin: int = 0
    current_task: int = -1
    first_cycle: int = 0
    last_cycle: int = 0
    # task color -> (frames open at its last terminator, address of that
    # terminator). Populated for every task, read only on a coroutine resume.
    suspended: dict = field(default_factory=dict)


def reconstruct(events, tile_elf_mapping, elf_lookups, stats=None,
                coroutine_stacks=True, inline_frames=False):
    """Yield ``(kind, tile_index, label, cycle)`` frame open/close events.

    Args:
        events: iterable of DispatchEvent (in trace order).
        tile_elf_mapping: tile_index -> elf_path.
        elf_lookups: elf_path -> SymbolLookup.
        stats: optional Counter, populated in place with counts for keys
            ``events``, ``calls``, ``returns``, ``task_switches``,
            ``task_terms``, ``coroutine_resumes``, and ``inline_opens``
            (useful for a one-line summary).
        coroutine_stacks: when False, do not re-establish the stacks of
            coroutines resumed by a stack-switching runtime. Traces from
            programs without such a runtime are unaffected either way.
        inline_frames: when True, expand the top physical function with the
            DWARF inline chain at each instruction pointer. Inline scopes are
            reporting frames only: physical calls, returns, task switches and
            coroutine resumes continue to use the ELF symbol table alone.
    """
    if stats is None:
        stats = Counter()
    states = {}

    def get_state(tile_idx):
        st = states.get(tile_idx)
        if st is None:
            st = states[tile_idx] = _TileState()
        return st

    def close_inline(state, tile_idx, cycle):
        while state.inline_stack:
            yield ("C", tile_idx, state.inline_stack.pop(), cycle)

    def sync_inline(state, lookup, func_name, byte_addr, tile_idx, cycle):
        if not inline_frames or not state.call_stack:
            desired = []
        else:
            chain = lookup.inline_chain(byte_addr)
            # inline_chain normally begins with the physical function. If a
            # linker thunk/padding mismatch made it explicit twice, only the
            # portion below the current physical frame is logical nesting.
            desired = list(chain[1:] if chain and chain[0] == func_name
                           else chain)

        common = 0
        limit = min(len(state.inline_stack), len(desired))
        while (common < limit
               and state.inline_stack[common] == desired[common]):
            common += 1
        while len(state.inline_stack) > common:
            yield ("C", tile_idx, state.inline_stack.pop(), cycle)
        for name in desired[common:]:
            state.inline_stack.append(name)
            stats["inline_opens"] += 1
            yield ("O", tile_idx, name, cycle)

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

        # Classifying a control transfer needs the instruction that performed
        # it, so take the previous one before overwriting it for the next round.
        prev_inst_bin = state.prev_inst_bin
        state.prev_inst_bin = evt.inst_bin

        # Task frame management
        if evt.task_color != state.current_task:
            stats["task_switches"] += 1
            yield from close_inline(state, tile_idx, evt.cycle)
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
            # Retain the open frames in case this is a coroutine suspending;
            # the frames still close here either way, so a suspended coroutine
            # accrues no time while it is not running.
            if state.call_stack and state.current_task >= 0:
                state.suspended[state.current_task] = (
                    list(state.call_stack), evt.inst_ptr)
            yield from close_inline(state, tile_idx, evt.cycle)
            for fn in reversed(state.call_stack):
                yield ("C", tile_idx, fn, evt.cycle)
            state.call_stack.clear()
            if state.current_task >= 0:
                yield ("C", tile_idx, f"task {state.current_task}", evt.cycle)
                state.current_task = -1
            state.prev_func = None
            continue

        arch = lookup.arch

        if coroutine_stacks:
            resumed = _resumed_frames(state, prev_inst_bin, func_name,
                                      is_entry, evt, arch)
            if resumed is not None:
                stats["coroutine_resumes"] += 1
                # The runtime frames that performed the switch run on the
                # scheduler's stack and are abandoned by the jump, so they end
                # here rather than enclosing the resumed call chain.
                yield from close_inline(state, tile_idx, evt.cycle)
                for fn in reversed(state.call_stack):
                    yield ("C", tile_idx, fn, evt.cycle)
                state.call_stack = resumed
                for fn in state.call_stack:
                    yield ("O", tile_idx, fn, evt.cycle)
                state.prev_func = func_name
                yield from sync_inline(state, lookup, func_name,
                                       evt.inst_ptr * 2, tile_idx, evt.cycle)
                continue

        if evt.inst_bin & arch.jmp_r15_mask == arch.jmp_r15:
            stats["returns"] += 1
            yield from close_inline(state, tile_idx, evt.cycle)
            if state.call_stack:
                top = state.call_stack[-1]
                yield ("C", tile_idx, top, evt.cycle)
                state.call_stack.pop()
            state.prev_func = state.call_stack[-1] if state.call_stack else None
            continue

        if func_name != state.prev_func:
            yield from close_inline(state, tile_idx, evt.cycle)
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

        yield from sync_inline(state, lookup, func_name, evt.inst_ptr * 2,
                               tile_idx, evt.cycle)
        state.prev_func = func_name

    # Flush any frames still open at end of trace.
    for tile_idx, state in states.items():
        yield from close_inline(state, tile_idx, state.last_cycle)
        for fn in reversed(state.call_stack):
            yield ("C", tile_idx, fn, state.last_cycle)
        state.call_stack.clear()
        if state.current_task >= 0:
            yield ("C", tile_idx, f"task {state.current_task}", state.last_cycle)
            state.current_task = -1

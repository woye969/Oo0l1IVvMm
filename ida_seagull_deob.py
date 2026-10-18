"""Seagull Deobfuscator - IDA Pro 7.4+ / 8.x / 9.x

Conservative static triage for native obfuscation.  The plugin is intentionally
non-destructive: it annotates likely control-flow-flattening dispatchers,
state updates, indirect jump tables, opaque predicates, and anti-disassembly
idioms, then exports a machine-readable report.  It does not pretend that a
single script can solve every VM protector or cryptographic check.

Install by copying this file to IDA's plugins directory.  Menu:
    Edit -> Plugins -> Seagull Deobfuscator

Hotkey: Ctrl+Shift+Alt+D (deflatten current function and refresh pseudocode)
"""

from __future__ import print_function

import json
import os
import re
import traceback
from collections import Counter, defaultdict

import idaapi
import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_segment
import ida_ua
import ida_xref
import idautils
import idc


PLUGIN_NAME = "Seagull Deobfuscator"
PLUGIN_VERSION = "0.9.0"
COMMENT_TAG = "[SEAGULL-DEOB]"
_MICROCODE_UNFLAT = None
_UNFLAT_ACTIVE = False
_D810_STATE = None
_HEX_HOOK = None
_HEX_ANALYSIS = {}
_UI_HOOK = None
_UI_TIMER = None
_REWIRED_ENTRIES = set()
_ARMED = False


def _is_unflat_active():
    """Detect our hook even if IDA loaded a second module instance."""
    if _UNFLAT_ACTIVE:
        return True
    try:
        import unflat.new_unflattener as unflat
        return getattr(unflat, "hook_instance", None) is not None
    except Exception:
        return False


def _analysis_for_entry(entry_ea):
    """Build the bounded abstract state graph used by the F5 microcode hook."""
    entry_ea = int(entry_ea)
    cached = _HEX_ANALYSIS.get(entry_ea)
    if cached is not None:
        return cached
    try:
        import seagull_core
        Analyzer = seagull_core.Analyzer
        if not seagull_core.CAPSTONE_AVAILABLE:
            raise RuntimeError("Capstone decoder unavailable: %s" % seagull_core._CAPSTONE_ERROR)
        func = ida_funcs.get_func(entry_ea)
        if not func:
            return None
        seg = ida_segment.getseg(entry_ea)
        # Flattened functions are usually truncated by IDA at their first
        # encoded jump. Bound the exploration to the executable segment, while
        # the analyzer itself follows calls only as invalidating operations.
        end = int(seg.end_ea) if seg and (seg.perm & idaapi.SEGPERM_EXEC) else int(func.end_ea)
        if end <= entry_ea or end - entry_ea > 0x200000:
            end = int(func.end_ea)
        result = Analyzer(ida_bytes.get_bytes, entry_ea, end).run()
        # Resolve the real next block for every state-update site that feeds
        # a compare-and-table dispatch chain. This is what plain
        # valrange-based unflatteners cannot recover when the state base is
        # kept in a stack slot: the resolver re-executes the chain once per
        # site with that site's concrete state values.
        try:
            if any(v for v in result.edges.values()):
                resolution = seagull_core.resolve_chain(ida_bytes.get_bytes, entry_ea, end)
                if resolution is not None:
                    result.chain_rewires = resolution.rewires
                    result.chain_head = resolution.chain_head
                    result.chain_state_reg = resolution.state_reg
                    result.chain_key_reg = resolution.key_reg
                    result.chain_site_kinds = resolution.site_kinds
                    singles = sum(1 for p in resolution.rewires.values() if len(p) == 1)
                    print("[%s] chain resolver: %d sites (%d direct, %d conditional splits; state=%s key=%s head=0x%X)" %
                          (PLUGIN_NAME, len(resolution.rewires), singles,
                           len(resolution.rewires) - singles,
                           resolution.state_reg, resolution.key_reg,
                           resolution.chain_head))
        except Exception:
            print("[%s] chain resolver failed\n%s" % (PLUGIN_NAME, traceback.format_exc()))
        # Materialize only the recursively decoded instruction heads. This
        # gives Hex-Rays a block boundary for every recovered destination and
        # avoids linear-sweeping junk bytes. If IDA truncated the function at
        # the first ijmp, rebuild that one bounded function around the decoded
        # region; callers and neighboring functions remain untouched outside
        # the recovered range.
        try:
            for address in sorted(result.insns):
                ida_ua.create_insn(int(address))
            max_state = max(result.states) if result.states else entry_ea
            if max_state >= int(func.end_ea) and max_state + 1 <= end:
                for other in list(idautils.Functions(entry_ea, max_state + 1)):
                    if other == entry_ea or int(ida_funcs.get_func(other).end_ea) <= max_state + 1:
                        old_func = ida_funcs.get_func(other)
                        old_start = int(old_func.start_ea)
                        old_end = int(old_func.end_ea)
                        ida_funcs.del_func(other)
                        # Junk calls can make IDA create an overlapping fake
                        # function (e.g. in the middle of a conditional jump).
                        # Remove only that function's simple item heads so the
                        # recursively decoded instruction can be recreated.
                        if old_start != entry_ea:
                            cursor = old_start
                            while cursor < old_end:
                                head = ida_bytes.get_item_head(cursor)
                                if head == idaapi.BADADDR:
                                    cursor += 1
                                else:
                                    size = max(1, int(ida_bytes.get_item_size(head)))
                                    ida_bytes.del_items(head, ida_bytes.DELIT_SIMPLE)
                                    cursor = max(cursor + 1, head + size)
                ida_funcs.add_func(entry_ea, max_state + 1)
                for address in sorted(result.insns):
                    ida_ua.create_insn(int(address))
        except Exception:
            print("[%s] function boundary materialization failed\n%s" %
                  (PLUGIN_NAME, traceback.format_exc()))
        _HEX_ANALYSIS[entry_ea] = result
        # Arm the full recovery chain from any context that discovers finite
        # dispatches, not only from the UI timer. Without this, a scripted
        # ida_hexrays.decompile() silently decompiles the truncated database
        # function: everything past the first unresolved `jmp reg` is
        # unreachable and gets dropped, which looks like a clean result while
        # actually being a truncation artifact.
        try:
            _install_hexrays_hook()
        except Exception:
            pass
        print("[%s] microcode analysis 0x%X..0x%X: %d instructions, %d dispatches" %
              (PLUGIN_NAME, entry_ea, end, len(result.insns),
               sum(1 for v in result.edges.values() if v)))
        return result
    except Exception:
        print("[%s] microcode analysis failed at 0x%X\n%s" %
              (PLUGIN_NAME, entry_ea, traceback.format_exc()))
        return None


def _replace_indirect_jumps(mba, analysis):
    """Turn finite abstractly-resolved ijmps into valid Hex-Rays jtbl nodes."""
    import ida_hexrays
    import ida_pro
    changed = 0
    for i in range(mba.qty):
        block = mba.get_mblock(i)
        tail = block.tail
        if not tail or tail.opcode != ida_hexrays.m_ijmp:
            continue
        jump_ea = int(tail.ea)
        addresses = sorted(analysis.edges.get(jump_ea, ()))
        if not addresses:
            continue
        serials = []
        for target in addresses:
            found = None
            for n in range(mba.qty):
                if int(mba.get_mblock(n).start) == int(target):
                    found = n
                    break
            if found is None:
                serials = []
                break
            serials.append(found)
        if not serials or len(serials) != len(addresses):
            continue

        # A duplicate synthetic 'def' target makes IDA reject the microcode
        # with INTERR 50860. A finite explicit list is legal and preserves all
        # statically recovered destinations.
        cases = ida_hexrays.mcases_t()
        for value, serial in zip(addresses, serials):
            values = ida_pro.svalvec_t()
            values.push_back(int(value))
            cases.values.push_back(values)
            cases.targets.push_back(int(serial))

        selector = ida_hexrays.mop_t()
        selector.assign(tail.d)
        tail.opcode = ida_hexrays.m_jtbl
        tail.l = selector
        tail.r.erase()
        tail.r._make_cases(cases)
        tail.d.erase()

        block.type = ida_hexrays.BLT_NWAY
        block.flags = 512  # MBL_GOTO in IDA 9.1; native jtbl blocks carry it.
        block.succset.clear()
        for serial in serials:
            block.succset.push_back(int(serial))
        for serial in serials:
            destination = mba.get_mblock(serial)
            if block.serial not in list(destination.predset):
                destination.predset.push_back(block.serial)
            destination.mark_lists_dirty()
        block.mark_lists_dirty()
        changed += 1
    if changed:
        mba.mark_chains_dirty()
        _REWIRED_ENTRIES.add(int(mba.entry_ea))
    return changed


def _chain_state_mreg(mba, analysis):
    """Microcode register holding the dispatch state, from the chain's cmp."""
    import ida_hexrays
    head = getattr(analysis, "chain_head", None)
    state_reg = getattr(analysis, "chain_state_reg", None)
    if head is None or state_reg is None:
        return None, 4
    want = state_reg.lower()
    for n in range(mba.qty):
        block = mba.get_mblock(n)
        if int(block.start) != int(head):
            continue
        # x86 `cmp` lowers to setcmp/jcnd in microcode (no m_cmp exists), so
        # locate the state register by matching operand names
        ins = block.head
        while ins:
            for mop in (ins.l, ins.r):
                try:
                    if mop.t == ida_hexrays.mop_r:
                        name = ida_hexrays.get_mreg_name(int(mop.r), int(mop.size))
                        if name and name.split(".")[0].lower() == want:
                            return int(mop.r), int(mop.size) or 4
                except Exception:
                    pass
            ins = ins.next
        break
    return None, 4


def _apply_chain_rewires(mba, analysis):
    """Turn resolved state transitions into direct or conditional edges.

    Single-value sites get a direct edge to the recovered state block. Join
    sites (the obfuscator folded the original if/else into the state value,
    usually via cmov) get a chain of m_jz blocks on the state register - one
    comparison per candidate value - which restores the original branch.
    With every site bypassing the dispatcher chain, the chain becomes
    unreachable and is dropped at glbopt.

    Two phases are mandatory: inserting blocks renumbers every later serial,
    so all insertions happen first and every goto/jz instruction and edge is
    written afterwards with the final serial numbers. Writing a target early
    lets later insertions silently redirect it onto an unrelated block.
    """
    import ida_hexrays
    rewires = getattr(analysis, "chain_rewires", None) or {}
    site_kinds = getattr(analysis, "chain_site_kinds", None) or {}
    if not rewires:
        return 0
    state_mreg, state_size = _chain_state_mreg(mba, analysis)
    _CONDS = (ida_hexrays.m_ja, ida_hexrays.m_jae, ida_hexrays.m_jb,
              ida_hexrays.m_jbe, ida_hexrays.m_jcnd, ida_hexrays.m_jg,
              ida_hexrays.m_jge, ida_hexrays.m_jl, ida_hexrays.m_jle,
              ida_hexrays.m_jz, ida_hexrays.m_jnz)

    import unflat.cfgUtil as cfg

    def block_containing(ea):
        for n in range(mba.qty):
            b = mba.get_mblock(n)
            bs, be = int(b.start), int(b.end)
            if bs <= ea < be and be - ea <= 16:
                return b
        return None

    def serial_by_start():
        m = {}
        for n in range(mba.qty):
            m.setdefault(int(mba.get_mblock(n).start), n)
        return m

    # Phase 1: decide per site and insert every new block first.
    plans = []
    for ea, pairs in sorted(rewires.items()):
        blk = block_containing(ea)
        ins = analysis.insns.get(ea)
        if blk is None or ins is None:
            continue
        kind = site_kinds.get(ea)
        if kind in ("jmp", "jcc"):
            old_target = int(ins.operands[0].imm)
        else:
            old_target = ea + int(ins.size)
        tail = blk.tail
        is_jcc = kind == "jcc" and tail is not None and tail.opcode in _CONDS
        is_goto = tail is not None and tail.opcode == ida_hexrays.m_goto
        if len(pairs) == 1 and (is_jcc or is_goto):
            plans.append((ea, kind, pairs, 0, old_target))
            continue
        # fallthrough-type site, or a conditional split: dedicated blocks
        # packed directly after the site block
        count = 1 if len(pairs) == 1 else len(pairs)
        base = blk.serial
        for k in range(count):
            cfg.create_mblock(blk, base + 1 + k)
        plans.append((ea, kind, pairs, count, old_target))

    # Phase 2: write instructions and edges with the final serial numbers.
    changed = 0
    for ea, kind, pairs, count, old_target in plans:
        try:
            smap = serial_by_start()
            blk = block_containing(ea)
            if blk is None:
                continue
            old_serial = smap.get(old_target)
            if old_serial is not None:
                succs = [int(x) for x in blk.succset]
                if succs and old_serial not in succs:
                    continue
            tgts = [smap.get(int(t)) for _, t in pairs]
            if any(t is None for t in tgts):
                continue

            if count == 0:
                serial = tgts[0]
                if serial in (None, blk.serial, old_serial):
                    continue
                tail = blk.tail
                try:
                    if tail.opcode == ida_hexrays.m_goto:
                        tail.l.erase()
                        tail.l.make_blkref(serial)
                    else:
                        tail.d.erase()
                        tail.d.make_blkref(serial)
                except Exception:
                    pass
                if old_serial is not None:
                    cfg.modify_edge(mba, blk.serial, serial, old_serial)
                else:
                    cfg.modify_edge(mba, blk.serial, serial)
                blk.mark_lists_dirty()
                changed += 1
                continue

            news = [mba.get_mblock(blk.serial + 1 + k) for k in range(count)]
            if len(pairs) == 1:
                g = news[0]
                cfg.insert_goto(g, tgts[0])
                g.type = ida_hexrays.BLT_1WAY
                g.flags |= 512  # MBL_GOTO in IDA 9.1
                cfg.modify_edge(mba, g.serial, tgts[0])
                cfg.modify_edge(mba, blk.serial, g.serial,
                                old_serial if old_serial is not None else 0)
                g.mark_lists_dirty()
            else:
                for k, (value, target) in enumerate(pairs[:-1]):
                    jz = news[k]
                    if value is None:
                        break
                    cfg.insert_jz(jz, tgts[k],
                                  int(value) & ((1 << (state_size * 8)) - 1),
                                  state_mreg, state_size, state_size)
                    jz.type = ida_hexrays.BLT_2WAY
                    jz.flags |= 512  # MBL_GOTO in IDA 9.1
                    cfg.modify_edge(mba, jz.serial, jz.serial + 1)
                    cfg.modify_edge(mba, jz.serial, tgts[k])
                    jz.mark_lists_dirty()
                else:
                    g = news[-1]
                    cfg.insert_goto(g, tgts[-1])
                    g.type = ida_hexrays.BLT_1WAY
                    g.flags |= 512  # MBL_GOTO in IDA 9.1
                    cfg.modify_edge(mba, g.serial, tgts[-1])
                    g.mark_lists_dirty()
                    first = news[0]
                    tail = blk.tail
                    if tail is not None and tail.opcode == ida_hexrays.m_goto:
                        try:
                            tail.l.erase()
                            tail.l.make_blkref(first.serial)
                        except Exception:
                            pass
                    elif kind == "jcc" and tail is not None and tail.opcode in _CONDS:
                        try:
                            tail.d.erase()
                            tail.d.make_blkref(first.serial)
                        except Exception:
                            pass
                    cfg.modify_edge(mba, blk.serial, first.serial,
                                    old_serial if old_serial is not None else 0)
                    blk.mark_lists_dirty()
            changed += 1
        except Exception:
            print("[%s] chain rewire failed at 0x%X: %s" %
                  (PLUGIN_NAME, ea, traceback.format_exc()))
    if changed:
        mba.mark_chains_dirty()
        _REWIRED_ENTRIES.add(int(mba.entry_ea))
    return changed


class _SeagullHexraysHook(ida_hexrays.Hexrays_Hooks):
    """Reachability and finite-jump lifting hook used by normal F5 decompilation."""
    def __init__(self):
        ida_hexrays.Hexrays_Hooks.__init__(self)

    def hook(self):
        return ida_hexrays.Hexrays_Hooks.hook(self)

    def unhook(self):
        return ida_hexrays.Hexrays_Hooks.unhook(self)

    def flowchart(self, fc, mba, reachable_blocks, decomp_flags):
        analysis = _analysis_for_entry(mba.entry_ea)
        if analysis is None:
            return 0
        # IDA often truncates a flattened function at its first ijmp. Extend
        # that database function before Hex-Rays finalizes the reachability
        # graph. The hook remains bounded by the executable segment.
        try:
            func = ida_funcs.get_func(mba.entry_ea)
            max_state = max(analysis.states) if analysis.states else 0
            if func and max_state >= int(func.end_ea):
                ida_funcs.set_func_end(func, max_state + 1)
        except Exception:
            pass
        for n in range(fc.size()):
            if int(fc[n].start_ea) in analysis.states:
                reachable_blocks.add(n)
        return 0

    def prolog(self, mba, fc, reachable_blocks, decomp_flags):
        # This callback runs before Hex-Rays freezes the initial flowchart.
        # Materializing the decoded heads here lets a plain F5 see the full
        # flattened region on its first decompilation.
        _analysis_for_entry(mba.entry_ea)
        return 0

    def glbopt(self, mba):
        # After the stage-0 chain rewires every site bypasses the dispatcher
        # chain, but the chain blocks were pinned reachable at flowchart time
        # and Hex-Rays keeps rendering them. At this maturity the block lists
        # are consistent, so dead blocks can be dropped safely.
        if int(mba.entry_ea) in _REWIRED_ENTRIES:
            try:
                mba.remove_empty_and_unreachable_blocks()
            except Exception:
                print("[%s] unreachable-block removal failed: %s" %
                      (PLUGIN_NAME, traceback.format_exc()))
        return 0

    def microcode(self, mba):
        analysis = _analysis_for_entry(mba.entry_ea)
        if analysis is not None:
            try:
                changed = _replace_indirect_jumps(mba, analysis)
                if changed:
                    print("[%s] lifted %d finite indirect jumps for F5 at 0x%X" %
                          (PLUGIN_NAME, changed, mba.entry_ea))
                rewired = _apply_chain_rewires(mba, analysis)
                if rewired:
                    print("[%s] rewired %d state transitions to direct edges at 0x%X" %
                          (PLUGIN_NAME, rewired, mba.entry_ea))
            except Exception:
                print("[%s] microcode lift failed at 0x%X\n%s" %
                      (PLUGIN_NAME, mba.entry_ea, traceback.format_exc()))
        return 0


def _install_hexrays_hook():
    global _HEX_HOOK
    if _HEX_HOOK is not None:
        return True
    try:
        import ida_hexrays
        # init_hexrays_plugin() can transiently report false while IDA is
        # loading the decompiler. The hook itself is safe to attempt again on
        # the first F5 action, so do not make that status a hard gate.
        ida_hexrays.init_hexrays_plugin()
        _HEX_HOOK = _SeagullHexraysHook()
        if not _HEX_HOOK.hook():
            _HEX_HOOK = None
            return False
        print("[%s] F5 finite-CFG Hex-Rays hook enabled" % PLUGIN_NAME)
        return True
    except Exception:
        _HEX_HOOK = None
        print("[%s] F5 hook unavailable\n%s" % (PLUGIN_NAME, traceback.format_exc()))
        return False


def _open_deobfuscated_pseudocode(ea):
    """Open a fresh Hex-Rays view after the optimizer is armed.

    The ordinary F5 action can be disabled or consumed by another IDA view
    (for example the graph overview). Calling open_pseudocode directly keeps
    the user from falling back to the database's truncated `jmp rdx` flow.
    """
    try:
        import ida_hexrays
        if not ida_hexrays.init_hexrays_plugin():
            return False
        vu = ida_hexrays.open_pseudocode(int(ea), ida_hexrays.OPF_REUSE)
        return vu is not None
    except Exception:
        print("[%s] direct pseudocode open failed\n%s" %
              (PLUGIN_NAME, traceback.format_exc()))
        return False


class _SeagullUIHook(ida_kernwin.UI_Hooks):
    """Prepare a truncated CFF function once the database UI is ready."""
    def ready_to_run(self):
        if not _ARMED:
            return 0
        try:
            ida_auto.auto_wait()
            ea = ida_kernwin.get_screen_ea()
            if ea == idaapi.BADADDR:
                # IDA 9.x removed get_inf_structure(); the module-level
                # getters are the supported replacement.
                try:
                    import ida_ida
                    ea = ida_ida.inf_get_start_ea()
                except Exception:
                    ea = idaapi.BADADDR
            func = ida_funcs.get_func(ea)
            if func:
                # Materialization is cached and only expands when finite
                # dispatches are actually discovered.
                _analysis_for_entry(func.start_ea)
        except Exception:
            print("[%s] UI preparation failed\n%s" % (PLUGIN_NAME, traceback.format_exc()))
        return 0

    def screen_ea_changed(self, ea, prev_ea):
        if not _ARMED:
            return 0
        try:
            func = ida_funcs.get_func(ea)
            if func:
                # Delay the expensive pass until the analyst navigates into a
                # function; this keeps plugin startup fast on large binaries.
                _analysis_for_entry(func.start_ea)
        except Exception:
            pass
        return 0

    def preprocess_action(self, name):
        # F5 is dispatched as an action by the Hex-Rays UI. Prepare the
        # truncated function before the decompiler builds its flowchart.
        if not _ARMED:
            return 0
        try:
            lname = str(name).lower()
            # A real F5 keypress in the IDA 9.1 GUI dispatches
            # ``hx:GenPseudo`` (the message log shows "Executing action:
            # hx:GenPseudo"); ``hx:HexDec``/``hx:decompile`` are other
            # builds' spellings and hx:HexDec even fails process_ui_action()
            # on 9.1.  Match only the single-function decompile actions so
            # "decompile all" keeps its default behavior.
            is_hexrays_action = (
                lname in ("hx:genpseudo", "hx:hexdec", "hx:decompile", "hx:hx_decompile") or
                (lname.startswith("hx:") and "decomp" in lname and "all" not in lname)
            )
            if is_hexrays_action:
                # If the analyst opened D-810's own GUI after our instruction
                # state was armed, release ours so exactly one D-810 manager
                # owns the optimizers (done here, outside any decompilation).
                try:
                    if _D810_INSTR_STATE is not None and                             _d810_already_running() is not _D810_INSTR_STATE:
                        print("[%s] user-started D-810 detected - releasing ours" % PLUGIN_NAME)
                        _stop_d810_instructions()
                except Exception:
                    pass
                func = ida_funcs.get_func(ida_kernwin.get_screen_ea())
                if func:
                    _analysis_for_entry(func.start_ea)
                _start_preferred_unflattener()
                _start_d810_instructions()
                _install_hexrays_hook()
                print("[%s] intercepted Hex-Rays action %s" % (PLUGIN_NAME, name))
                if func:
                    try:
                        ida_hexrays.mark_cfunc_dirty(func.start_ea, True)
                    except Exception:
                        pass
                target_ea = func.start_ea if func else ida_kernwin.get_screen_ea()
                if target_ea != idaapi.BADADDR and _open_deobfuscated_pseudocode(target_ea):
                    print("[%s] F5 opened deobfuscated pseudocode at 0x%X" %
                          (PLUGIN_NAME, target_ea))
                    return 1
        except Exception:
            pass
        return 0


def _install_ui_hook():
    global _UI_HOOK
    if _UI_HOOK is not None:
        return True
    try:
        _UI_HOOK = _SeagullUIHook()
        if not _UI_HOOK.hook():
            _UI_HOOK = None
            print("[%s] UI F5 hook rejected by IDA" % PLUGIN_NAME)
            return False
        print("[%s] UI F5 hook enabled" % PLUGIN_NAME)
        return True
    except Exception:
        _UI_HOOK = None
        print("[%s] UI F5 hook unavailable\n%s" % (PLUGIN_NAME, traceback.format_exc()))
        return False


def _late_hook_tick():
    """Install the (inert when disarmed) UI hook once the UI is up.

    Nothing heavy is armed here on purpose: while the plugin is disarmed
    every decompilation goes through vanilla Hex-Rays at native speed and
    navigation triggers no analysis. The whole recovery stack is started
    only by an explicit Seagull action.
    """
    global _UI_TIMER
    _install_ui_hook()
    _UI_TIMER = None
    return -1


def _schedule_late_hooks():
    global _UI_TIMER
    if _UI_TIMER is None:
        try:
            _UI_TIMER = ida_kernwin.register_timer(500, _late_hook_tick)
        except Exception:
            _UI_TIMER = None


def _start_preferred_unflattener():
    """Start the direct-edge OLLVM hook before the first F5 decompile."""
    global _MICROCODE_UNFLAT, _UNFLAT_ACTIVE
    if _UNFLAT_ACTIVE:
        return True
    try:
        import importlib
        unflat = importlib.import_module("unflat.new_unflattener")
        unflat.main()
        _MICROCODE_UNFLAT = unflat
        _UNFLAT_ACTIVE = True
        print("[%s] preferred direct-edge unflattener enabled" % PLUGIN_NAME)
        return True
    except Exception as exc:
        _UNFLAT_ACTIVE = False
        print("[%s] preferred unflattener unavailable: %s" % (PLUGIN_NAME, exc))
        return False


_D810_INSTR_STATE = None
_D810_SAVED_INDEX = None

D810_INSTRUCTION_PROFILE = 0    # default_instruction_only.json
D810_OLLVM_PROFILE = 1          # default_unflattening_ollvm.json
D810_SWITCH_CASE_PROFILE = 2    # default_unflattening_switch_case.json


def _d810_already_running():
    try:
        import d810.manager as d810_manager
        state = getattr(d810_manager, "d810_state", None)
        if state is not None and getattr(state, "manager", None) is not None:
            return state
    except Exception:
        pass
    return None


def _start_d810_instructions(project_index=D810_INSTRUCTION_PROFILE):
    """Arm D-810's instruction-level simplification stack.

    The instruction-only profile carries 177 rules: the MBA families
    (AddXor / HackersDelight / Ollvm / SpecialConstant / Factor / Mba),
    22 constant-folding rules, the Pred* opaque-predicate rules and the
    Z3 SMT rules, while its only block rule is the harmless JumpFixer.
    That is exactly the complement to this plugin: Seagull and unflat own
    the control-flow recovery, D-810 owns the arithmetic obfuscation.
    Its flow unflattener is deliberately NOT enabled here - three CFG
    rewriters racing on one mba corrupt each other.

    start_d810() persists last_project_index into the user's options.json,
    so the original selection is restored immediately afterwards.
    """
    global _D810_INSTR_STATE, _D810_SAVED_INDEX
    if _D810_INSTR_STATE is not None:
        return True
    running = _d810_already_running()
    if running is not None and running is not _D810_INSTR_STATE:
        print("[%s] D-810 already active (user profile) - not overriding" % PLUGIN_NAME)
        return False
    try:
        from d810.conf import D810Configuration
        from d810.manager import D810State
        cfg = D810Configuration()
        _D810_SAVED_INDEX = cfg.get("last_project_index")
        state = D810State(cfg)
        state.load_project(project_index)
        state.start_d810()
        # keep the user's own D-810 profile selection intact
        cfg.set("last_project_index", _D810_SAVED_INDEX)
        cfg.save()
        _D810_INSTR_STATE = state
        print("[%s] D-810 instruction-level simplifier enabled (MBA/constants/opaque predicates/Z3)" % PLUGIN_NAME)
        return True
    except Exception as exc:
        print("[%s] D-810 instruction simplifier unavailable: %s" % (PLUGIN_NAME, exc))
        return False


def _stop_d810_instructions():
    global _D810_INSTR_STATE
    if _D810_INSTR_STATE is None:
        return
    try:
        _D810_INSTR_STATE.stop_d810()
    except Exception:
        pass
    _D810_INSTR_STATE = None
    print("[%s] D-810 instruction-level simplifier disabled" % PLUGIN_NAME)


def _toggle_unflat_classic():
    """Mirror the flatPlugin toggles so one menu controls the whole stack."""
    try:
        import unflat.config as unflat_config
        unflat_config.enable_ollvm_unflatten = not unflat_config.enable_ollvm_unflatten
        state = "on" if unflat_config.enable_ollvm_unflatten else "off"
        print("[%s] classic OLLVM unflattener (unflat) %s" % (PLUGIN_NAME, state))
        _refresh_decompiler()
        return True
    except Exception as exc:
        print("[%s] unflat toggle failed: %s" % (PLUGIN_NAME, exc))
        return False


def _recover_static_cfg(ea=None):
    """Recover finite encoded jump targets with a bounded abstract interpreter.

    This pass only adds user xrefs/comments; it never patches bytes or merges
    unrelated IDA functions.  The report is therefore safe to run repeatedly.
    """
    try:
        from seagull_core import Analyzer
        f = ida_funcs.get_func(ea or ida_kernwin.get_screen_ea())
        if not f:
            return None
        seg = ida_segment.getseg(f.start_ea)
        # IDA stops at the first unresolved jmp.  Analyze the executable
        # segment as a bounded region, while following only direct branches;
        # calls are recorded but never traversed, so neighboring functions are
        # not silently merged into the recovered graph.
        end = int(seg.end_ea) if seg and (seg.perm & idaapi.SEGPERM_EXEC) and (int(f.end_ea) - int(f.start_ea) < 0x1000) else int(f.end_ea)
        a = Analyzer(ida_bytes.get_bytes, int(f.start_ea), end).run()
        count = 0
        for jump, targets in a.edges.items():
            if not targets:
                continue
            for target in targets:
                if ida_bytes.is_code(ida_bytes.get_flags(target)):
                    ida_xref.add_cref(jump, target, ida_xref.fl_JN | ida_xref.XREF_USER)
            _add_comment(jump, "%s static targets: %s" % (COMMENT_TAG, ", ".join("0x%X" % x for x in sorted(targets))))
            count += 1
        report = {"function": int(f.start_ea), "end": end, "instructions": len(a.insns),
                  "steps": a.steps, "indirect_jumps": {"0x%X" % k: ["0x%X" % x for x in sorted(v)] for k,v in a.edges.items() if v}}
        out = os.path.splitext(idc.get_input_file_path())[0] + ".seagull.cfg.json"
        with open(out, "w", encoding="utf-8") as fp:
            json.dump(report, fp, indent=2, sort_keys=True)
        print("[%s] recovered %d indirect dispatches; %d edges; report %s" % (PLUGIN_NAME, count, sum(len(x) for x in a.edges.values() if x), out))
        return report
    except Exception:
        print("[%s] static CFG recovery failed\n%s" % (PLUGIN_NAME, traceback.format_exc()))
        return None


class _AnalysisRange(object):
    """Small function-like object used when IDA split an obfuscated region."""

    def __init__(self, start_ea, end_ea):
        self.start_ea = int(start_ea)
        self.end_ea = int(end_ea)


def _is_code(ea):
    return ea != idaapi.BADADDR and ida_bytes.is_code(ida_bytes.get_flags(ea))


def _func_bounds(func):
    return int(func.start_ea), int(func.end_ea)


def _instruction_rows(func):
    """Return (ea, size, mnemonic, op0, op1, text) without relying on IDA text parsing."""
    start, end = _func_bounds(func)
    ea = start
    rows = []
    while ea < end:
        insn = ida_ua.insn_t()
        size = ida_ua.decode_insn(insn, ea)
        if not size:
            ea = ida_bytes.next_head(ea, end)
            if ea == idaapi.BADADDR or ea <= 0:
                break
            continue
        mnem = idc.print_insn_mnem(ea).lower()
        max_ops = getattr(idaapi, "UA_MAXOP", 8)
        ops = [idc.print_operand(ea, i).lower() for i in range(max_ops)]
        rows.append({
            "ea": int(ea),
            "size": int(size),
            "mnem": mnem,
            "op0": ops[0],
            "op1": ops[1],
            "text": idc.generate_disasm_line(ea, 0) or "",
            "insn": insn,
        })
        ea += size
    return rows


def _is_indirect_jump(row):
    if row["mnem"] not in ("jmp", "ijmp"):
        return False
    op = row["op0"]
    # Immediate/direct jumps are resolved by IDA and do not need this pass.
    return bool(op) and not op.startswith("0x") and not re.match(r"^[0-9a-f]+h$", op)


def _is_register(op):
    op = op.strip().lower()
    if op in {
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
        "ax", "bx", "cx", "dx", "al", "bl", "cl", "dl",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
        "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
    }:
        return True
    return bool(re.match(r"^r\d+(?:d|w|b)?$", op))


def _direct_target(ea):
    try:
        op_type = idc.get_operand_type(ea, 0)
        if op_type in (idaapi.o_near, idaapi.o_far):
            value = idc.get_operand_value(ea, 0)
            if value != idaapi.BADADDR:
                return int(value)
    except Exception:
        pass
    return None


def _add_comment(ea, text):
    old = idc.get_cmt(ea, 0) or ""
    if text in old:
        return
    merged = (old + " " + text).strip() if old else text
    idc.set_cmt(ea, merged[:2047], 0)


def _set_name(ea, name):
    if ea == idaapi.BADADDR:
        return False
    try:
        current = idc.get_name(ea) or ""
        if current.startswith("sub_") or not current:
            return bool(idc.set_name(ea, name, idc.SN_CHECK))
    except Exception:
        return False
    return False


def _parse_imm(text):
    text = text.strip().lower().replace("0x", "")
    text = text.rstrip("h")
    try:
        return int(text, 16)
    except ValueError:
        try:
            return int(text, 10)
        except ValueError:
            return None


def _looks_like_state_update(row):
    """Recognize common CFF state transitions without assuming one compiler."""
    m, a, b = row["mnem"], row["op0"], row["op1"]
    if m in ("add", "sub", "xor", "rol", "ror", "inc", "dec", "lea") and a in (
        "eax", "ebx", "ecx", "edx", "esi", "edi", "r8d", "r9d", "r10d", "r11d",
    ):
        return True
    if m == "mov" and a in (
        "eax", "ebx", "ecx", "edx", "esi", "edi", "r8d", "r9d", "r10d", "r11d",
    ) and _parse_imm(b) is not None:
        return True
    if m.startswith("cmov") or m.startswith("set"):
        return True
    return False


def _memory_base(text):
    # This is only a hint extractor.  It deliberately avoids claiming that a
    # displacement is a valid table address when relocations/segment bases are
    # unknown.
    m = re.search(r"\[([^\]]+)\]", text.lower())
    if not m:
        return None
    expr = m.group(1).replace(" ", "")
    regs = re.findall(r"(?:r\d+|e?[abcd]x|e?[sd]i|e?[sb]p|rip)", expr)
    return regs[0] if regs else None


def _stack_slot(text):
    """Return a normalized stack/frame slot such as rsp+0xc or rbp-0x20."""
    expr = text.lower().replace(" ", "")
    m = re.search(r"\[(rsp|rbp)([+-](?:0x)?[0-9a-f]+)?\]", expr)
    if not m:
        return None
    return m.group(1) + (m.group(2) or "+0")


def _rip_target(ea, text):
    """Best-effort RIP-relative address recovery for table annotations."""
    if "rip" not in text.lower():
        return None
    try:
        value = int(idc.get_operand_value(ea, 1))
        # IDA versions differ: some return the displacement, others the
        # already-resolved address.  Prefer an address in a mapped segment.
        if ida_segment.getseg(value):
            return value
        end = ida_bytes.next_head(ea, idaapi.BADADDR)
        candidate = end + value
        if ida_segment.getseg(candidate):
            return candidate
    except Exception:
        pass
    return None


def _norm_reg(reg):
    reg = reg.lower().strip()
    if reg.startswith("r") and reg.endswith("d"):
        return reg[:-1]
    return reg


def _resolve_indirect_targets(rows, index):
    """Resolve encoded jump-table entries used by the sample's dispatcher.

    Recognized shape (with arbitrary registers/constants):
        mov  index, IMM
        mov  base, [rip+global]
        mov  target, [base + index*SCALE + DISP]
        add  target, ADJUST_REG
        jmp  target

    The global qword and table entries are read from the IDB, so no input or
    network execution is required.  Unknown shapes simply return no edges.
    """
    row = rows[index]
    if not _is_indirect_jump(row):
        return []
    target_reg = row["op0"].strip().lower()
    prev = rows[max(0, index - 40):index]
    constants = {}
    indices = []
    load = None
    adjust_reg = None
    for p in prev:
        if p["mnem"] == "mov":
            dst, src = p["op0"].strip().lower(), p["op1"].strip().lower()
            imm = _parse_imm(src)
            if imm is not None and _is_register(dst):
                constants[_norm_reg(dst)] = imm & 0xFFFFFFFFFFFFFFFF
            if dst == target_reg and "[" in src and "rdx" in src:
                load = p
            if dst in ("edx", "rdx") and imm is not None:
                indices.append(imm)
        if p["mnem"] == "add" and p["op0"].strip().lower() == target_reg:
            rhs = p["op1"].strip().lower()
            if _is_register(rhs):
                adjust_reg = _norm_reg(rhs)
            else:
                imm = _parse_imm(rhs)
                if imm is not None:
                    constants["__adjust__"] = imm & 0xFFFFFFFFFFFFFFFF
    if load is None or not indices:
        return []

    expr = load["op1"].lower().replace(" ", "")
    scale_match = re.search(r"rdx(?:\*(\d+))?", expr)
    if not scale_match:
        return []
    scale = int(scale_match.group(1) or "1", 10)
    disp_match = re.search(r"rdx(?:\*\d+)?([+-])(0x[0-9a-f]+)", expr)
    if not disp_match:
        return []
    disp = int(disp_match.group(2), 16)
    if disp_match.group(1) == "-":
        disp = -disp

    # Find the RIP-relative global pointer feeding the table base.
    global_ea = None
    for p in reversed(prev):
        if p["mnem"] == "mov" and p["op0"].strip().lower() in ("rax", "rdx") and "rip" in p["op1"]:
            global_ea = _rip_target(p["ea"], p["op1"])
            if global_ea:
                break
    if global_ea is None:
        return []
    try:
        encoded_base = ida_bytes.get_qword(global_ea)
    except Exception:
        return []
    table = (encoded_base + disp) & 0xFFFFFFFFFFFFFFFF
    adjust = constants.get(adjust_reg) if adjust_reg else constants.get("__adjust__")
    if adjust is None:
        return []

    result = []
    for value in sorted(set(indices)):
        entry_ea = (table + value * scale) & 0xFFFFFFFFFFFFFFFF
        if not ida_segment.getseg(entry_ea):
            continue
        try:
            encoded_target = ida_bytes.get_qword(entry_ea)
        except Exception:
            continue
        target = (encoded_target + adjust) & 0xFFFFFFFFFFFFFFFF
        target_seg = ida_segment.getseg(target)
        if not target_seg or not (target_seg.perm & idaapi.SEGPERM_EXEC):
            continue
        result.append({"target": int(target), "index": int(value), "entry": int(entry_ea), "table": int(table)})
    return result


def _resolve_region_edges(func):
    rows = _instruction_rows(func)
    edges = []
    for i, row in enumerate(rows):
        for item in _resolve_indirect_targets(rows, i):
            edge = {"from": int(row["ea"]), **item}
            edges.append(edge)
            try:
                ida_xref.add_cref(row["ea"], item["target"], ida_xref.fl_JN)
            except Exception:
                pass
            _add_comment(row["ea"], "%s resolved edge -> 0x%X (state/index=0x%X)" % (
                COMMENT_TAG, item["target"], item["index"]))
    return edges


def _classify_function(func):
    rows = _instruction_rows(func)
    indirect = [r for r in rows if _is_indirect_jump(r)]
    direct_back = []
    start, end = _func_bounds(func)
    for r in rows:
        target = _direct_target(r["ea"])
        if target is not None and start <= target < end and target <= r["ea"]:
            direct_back.append((r["ea"], target))

    # Dispatcher candidates are indirect branches with a table-like load or a
    # state update immediately before them.  This catches OLLVM-style code and
    # the sample's mov [base+index]; add const; jmp reg sequence.
    dispatcher_sites = []
    state_updates = []
    opaque = []
    anti_disasm = []
    table_hints = []
    stack_accesses = Counter()
    stack_writes = Counter()

    for i, row in enumerate(rows):
        for operand in (row["op0"], row["op1"]):
            slot = _stack_slot(operand)
            if slot:
                stack_accesses[slot] += 1
                if row["mnem"] in ("mov", "stos", "push", "pop", "add", "sub", "xor") and operand == row["op0"]:
                    stack_writes[slot] += 1
        if _looks_like_state_update(row):
            state_updates.append(row["ea"])
        if _is_indirect_jump(row):
            prev = rows[max(0, i - 8):i]
            mem_load = next((p for p in reversed(prev) if p["mnem"] in ("mov", "lea") and "[" in p["op1"]), None)
            add_const = next((p for p in reversed(prev) if p["mnem"] in ("add", "sub") and _parse_imm(p["op1"]) is not None), None)
            if mem_load or add_const:
                dispatcher_sites.append(row["ea"])
                hint = {
                    "jump": int(row["ea"]),
                    "register": row["op0"],
                    "load": int(mem_load["ea"]) if mem_load else None,
                    "load_text": mem_load["text"] if mem_load else None,
                    "adjust": int(add_const["ea"]) if add_const else None,
                    "adjust_text": add_const["text"] if add_const else None,
                    "base_register": _memory_base(mem_load["text"]) if mem_load else None,
                    "rip_target": _rip_target(mem_load["ea"], mem_load["op1"]) if mem_load else None,
                }
                table_hints.append(hint)

        # Obvious local opaque predicates: cmp/test of a register against
        # itself, or an immediate written and compared immediately afterwards.
        if row["mnem"] in ("cmp", "test") and row["op0"] and row["op0"] == row["op1"]:
            opaque.append({"ea": int(row["ea"]), "kind": "self_compare", "text": row["text"]})
        if row["mnem"] == "cmp" and i and rows[i - 1]["mnem"] == "mov":
            prev = rows[i - 1]
            if prev["op0"] == row["op0"] and _parse_imm(prev["op1"]) is not None and _parse_imm(row["op1"]) is not None:
                if _parse_imm(prev["op1"]) == _parse_imm(row["op1"]):
                    opaque.append({"ea": int(row["ea"]), "kind": "constant_compare", "text": row["text"]})
        if row["mnem"] in ("push", "call") and i + 1 < len(rows):
            nxt = rows[i + 1]
            if row["mnem"] == "push" and nxt["mnem"] == "ret":
                anti_disasm.append({"ea": int(row["ea"]), "kind": "push_ret_jump", "text": row["text"]})
            if row["mnem"] == "call" and "[rsp" in nxt["op0"] and nxt["mnem"] in ("add", "sub"):
                anti_disasm.append({"ea": int(row["ea"]), "kind": "call_stack_delta", "text": row["text"]})

    # A high ratio of indirect jumps plus repeated back edges is a strong CFF
    # signal.  The score is surfaced so analysts can tune it for their sample.
    score = 0
    score += min(len(indirect), 20) * 2
    score += min(len(dispatcher_sites), 20) * 3
    score += min(len(direct_back), 20)
    if len(rows) and len(indirect) / float(len(rows)) > 0.01:
        score += 5
    is_cff = score >= 18 and len(dispatcher_sites) >= 2

    dispatcher = None
    # Flatteners commonly return to one small dispatcher block via dozens of
    # direct jumps.  Prefer the most frequently targeted backward edge over an
    # arbitrary indirect-jump site.
    if direct_back:
        target, count = Counter(t for _, t in direct_back).most_common(1)[0]
        if count >= 3:
            dispatcher = target
    if dispatcher is None and dispatcher_sites:
        dispatcher = dispatcher_sites[0]
    return {
        "function": int(start),
        "end": int(end),
        "instruction_count": len(rows),
        "indirect_jumps": [int(r["ea"]) for r in indirect],
        "dispatcher_sites": [int(x) for x in dispatcher_sites],
        "dispatcher": int(dispatcher) if dispatcher else None,
        "back_edges": [{"from": int(a), "to": int(b)} for a, b in direct_back],
        "state_updates": [int(x) for x in state_updates],
        "table_hints": table_hints,
        "state_slots": [
            {"slot": slot, "accesses": count, "writes": stack_writes.get(slot, 0)}
            for slot, count in stack_accesses.most_common()
            if stack_writes.get(slot, 0) and count >= 2
        ],
        "opaque_predicates": opaque,
        "anti_disassembly": anti_disasm,
        "resolved_edges": _resolve_region_edges(func),
        "score": score,
        "cff": bool(is_cff),
    }


def _annotate(report):
    func = ida_funcs.get_func(report["function"])
    if not func:
        return
    fn = "sub_%X" % report["function"]
    if report["cff"]:
        _set_name(report["function"], "seagull_cff_%X" % report["function"])
        _add_comment(report["function"], "%s CFF candidate score=%d; dispatcher=%s" % (
            COMMENT_TAG, report["score"],
            ("0x%X" % report["dispatcher"]) if report["dispatcher"] else "unknown"))
    if report["dispatcher"]:
        _set_name(report["dispatcher"], "seagull_dispatch_%X" % report["dispatcher"])
        _add_comment(report["dispatcher"], "%s likely dispatcher/state dispatch" % COMMENT_TAG)

    for slot in report.get("state_slots", [])[:4]:
        _add_comment(report["function"], "%s state-slot candidate %s (accesses=%d writes=%d)" % (
            COMMENT_TAG, slot["slot"], slot["accesses"], slot["writes"]))

    for ea in report["indirect_jumps"]:
        _add_comment(ea, "%s indirect branch; inspect table/state producer" % COMMENT_TAG)
    for item in report["table_hints"]:
        text = "%s jump-table hint: %s" % (COMMENT_TAG, item.get("load_text") or "computed target")
        if item.get("rip_target"):
            text += "; RIP target=0x%X" % item["rip_target"]
        _add_comment(item["jump"], text)
    for item in report.get("resolved_edges", []):
        _add_comment(item["from"], "%s static target 0x%X via table 0x%X" % (
            COMMENT_TAG, item["target"], item["table"]))
    for item in report["opaque_predicates"]:
        _add_comment(item["ea"], "%s possible opaque predicate (%s); verify before patching" % (COMMENT_TAG, item["kind"]))
    for item in report["anti_disassembly"]:
        _add_comment(item["ea"], "%s anti-disassembly idiom: %s" % (COMMENT_TAG, item["kind"]))


def analyze_current():
    ea = ida_kernwin.get_screen_ea()
    func = ida_funcs.get_func(ea)
    if not func:
        ida_kernwin.warning("No function at the current address")
        return None
    report = _classify_function(func)
    # Aggressive indirect branches often make IDA terminate a function at the
    # first unresolved jmp.  Retry over the containing executable segment so a
    # flattened region is analyzed as a whole.
    seg = ida_segment.getseg(func.start_ea)
    if (seg and seg.end_ea - func.start_ea >= 0x1000 and
            len(report["indirect_jumps"]) < 8):
        region = _classify_function(_AnalysisRange(func.start_ea, seg.end_ea))
        if region["score"] > report["score"]:
            region["region_scan"] = True
            region["ida_function_end"] = int(func.end_ea)
            report = region
    _annotate(report)
    print("[%s] %s" % (PLUGIN_NAME, json.dumps(report, indent=2, sort_keys=True)))
    ida_kernwin.info("Seagull: score=%d, CFF=%s, indirect jumps=%d" % (
        report["score"], report["cff"], len(report["indirect_jumps"])))
    return report


def analyze_all():
    reports = []
    for func_ea in idautils.Functions():
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue
        try:
            report = _classify_function(func)
            if report["cff"] or report["anti_disassembly"] or report["opaque_predicates"]:
                _annotate(report)
                reports.append(report)
        except Exception:
            print("[%s] failed at 0x%X\n%s" % (PLUGIN_NAME, func_ea, traceback.format_exc()))
    # Add one segment-level pass for binaries whose control-flow flattening
    # prevents IDA from forming a useful function boundary in the first place.
    seen_regions = set()
    for idx in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(idx)
        if not seg or not (seg.perm & idaapi.SEGPERM_EXEC):
            continue
        if seg.end_ea - seg.start_ea < 0x1000:
            continue
        try:
            region = _classify_function(_AnalysisRange(seg.start_ea, seg.end_ea))
            if region["cff"]:
                key = (region["function"], region["end"])
                if key not in seen_regions:
                    region["region_scan"] = True
                    _annotate(region)
                    reports.append(region)
                    seen_regions.add(key)
        except Exception:
            print("[%s] segment scan failed at 0x%X\n%s" % (PLUGIN_NAME, seg.start_ea, traceback.format_exc()))
    out = os.path.splitext(idc.get_input_file_path())[0] + ".seagull.json"
    try:
        with open(out, "w", encoding="utf-8") as fp:
            json.dump({"plugin": PLUGIN_VERSION, "functions": reports}, fp, indent=2, sort_keys=True)
        ida_kernwin.info("Seagull: annotated %d functions; report written to %s" % (len(reports), out))
    except Exception as exc:
        ida_kernwin.warning("Could not write report: %s" % exc)
    return reports


def _refresh_decompiler(ea=None):
    """Invalidate and refresh the current Hex-Rays view after CFG rewriting."""
    try:
        import ida_hexrays
        if ea is None:
            ea = ida_kernwin.get_screen_ea()
        func = ida_funcs.get_func(ea)
        if func:
            ida_hexrays.mark_cfunc_dirty(func.start_ea, True)
        vdui = ida_hexrays.get_widget_vdui(ida_kernwin.get_current_widget())
        if vdui:
            vdui.refresh_view(True)
            return True
    except Exception:
        print("[%s] decompiler refresh failed\n%s" % (PLUGIN_NAME, traceback.format_exc()))
    return False


def _expand_flattened_function(ea=None):
    # Removed: merging an executable segment destroys real function boundaries.
    return False


def enable_microcode_deflatten(refresh=True):
    """Install the IDA 9.1 Hex-Rays microcode unflattener shipped with the setup.

    The existing unflat implementation rewrites mblock successors during
    glbopt(), which is the right layer for making F5 show real control flow.
    Keeping the import optional lets the scanner still work on machines that
    do not have that helper installed.
    """
    global _MICROCODE_UNFLAT, _D810_STATE
    try:
        import ida_hexrays
        if not ida_hexrays.init_hexrays_plugin():
            raise RuntimeError("Hex-Rays decompiler is unavailable")

        if _start_preferred_unflattener():
            _start_d810_instructions()
            changed = _refresh_decompiler() if refresh else False
            msg = "direct-edge unflattener enabled"
            if changed:
                msg += "; current pseudocode refreshed"
            ida_kernwin.info("Seagull: %s" % msg)
            return True

        # D-810 is present in the target IDA 9.1 installation and has a more
        # complete generic dispatcher emulator than the small bundled helper.
        # Start its OLLVM project without opening its GUI.  It rewrites
        # mblock_t successors during Hex-Rays optimization.
        try:
            if _D810_STATE is None:
                from d810.conf import D810Configuration
                from d810.manager import D810State
                cfg = D810Configuration()
                _D810_STATE = D810State(cfg)
                _D810_STATE.start_d810()
                print("[%s] D-810 OLLVM microcode optimizer enabled" % PLUGIN_NAME)
                changed = _refresh_decompiler() if refresh else False
                msg = "D-810 OLLVM deflatten enabled"
                if changed:
                    msg += "; current pseudocode refreshed"
                ida_kernwin.info("Seagull: %s" % msg)
                return True
            changed = _refresh_decompiler() if refresh else False
            return True
        except Exception as d810_exc:
            if _D810_STATE is not None:
                try:
                    _D810_STATE.stop_d810()
                except Exception:
                    pass
                _D810_STATE = None
            print("[%s] D-810 unavailable, falling back to unflat: %s" % (PLUGIN_NAME, d810_exc))

        import importlib
        # Do not reload a live hook: the helper stores its hook instance in a
        # module global, and reloading would lose the reference needed to
        # unhook the previous instance.
        if _MICROCODE_UNFLAT is not None:
            unflat = _MICROCODE_UNFLAT
        else:
            unflat = importlib.import_module("unflat.new_unflattener")
        unflat.main()
        _MICROCODE_UNFLAT = unflat
        changed = _refresh_decompiler() if refresh else False
        msg = "microcode deflatten enabled"
        if changed:
            msg += "; current pseudocode refreshed"
        print("[%s] %s" % (PLUGIN_NAME, msg))
        ida_kernwin.info("Seagull: %s" % msg)
        return True
    except Exception as exc:
        print("[%s] microcode deflatten unavailable: %s\n%s" % (PLUGIN_NAME, exc, traceback.format_exc()))
        ida_kernwin.warning("Seagull microcode deflatten failed: %s" % exc)
        return False


def seagull_armed():
    return _ARMED


def arm_seagull():
    """Explicitly start the full deobfuscation stack for this session.

    Called from the plugin entry, the all-around menu action or the hotkey.
    While armed, every F5 goes through the recovery chain (Seagull structure
    + unflat classic dispatcher + D-810 instruction simplification); while
    disarmed, decompilation is vanilla Hex-Rays with zero overhead.
    """
    global _ARMED
    if _ARMED:
        return True
    _ARMED = True
    ok_hook = _install_hexrays_hook()
    ok_unflat = _start_preferred_unflattener()
    ok_mba = _start_d810_instructions()
    # release our D-810 instance if the analyst opened D-810's own GUI first
    try:
        if _D810_INSTR_STATE is not None and _d810_already_running() is not _D810_INSTR_STATE:
            _stop_d810_instructions()
            ok_mba = _start_d810_instructions()
    except Exception:
        pass
    ea = ida_kernwin.get_screen_ea()
    func = ida_funcs.get_func(ea)
    if func:
        _analysis_for_entry(func.start_ea)
        try:
            ida_hexrays.mark_cfunc_dirty(func.start_ea, True)
        except Exception:
            pass
        _open_deobfuscated_pseudocode(func.start_ea)
    print("[%s] ARMED - structure=%s classic-unflat=%s d810-instructions=%s (toggle off via the same menu)" %
          (PLUGIN_NAME, ok_hook, ok_unflat, ok_mba))
    return True


def disarm_seagull():
    """Stop every optimizer this plugin started; F5 returns to vanilla."""
    global _ARMED, _HEX_HOOK, _UNFLAT_ACTIVE, _MICROCODE_UNFLAT
    if not _ARMED:
        return True
    _ARMED = False
    if _HEX_HOOK is not None:
        try:
            _HEX_HOOK.unhook()
        except Exception:
            pass
        _HEX_HOOK = None
    try:
        if _MICROCODE_UNFLAT is not None:
            hook = getattr(_MICROCODE_UNFLAT, "hook_instance", None)
            if hook:
                hook.unhook()
    except Exception:
        pass
    _UNFLAT_ACTIVE = False
    _MICROCODE_UNFLAT = None
    _stop_d810_instructions()
    _REWIRED_ENTRIES.clear()
    print("[%s] DISARMED - decompilation is vanilla again" % PLUGIN_NAME)
    _refresh_decompiler()
    return True


def toggle_allround():
    if _ARMED:
        disarm_seagull()
        ida_kernwin.info("Seagull: disarmed - F5 is vanilla again")
    else:
        arm_seagull()
        ida_kernwin.info("Seagull: armed - F5 now runs the full recovery chain")


def allround_mode():
    """One-click full deobfuscation stack.

    Division of labour between the cooperating plugins:
      - Seagull (this plugin): structural recovery - instruction
        materialization, finite jtbl lifting, dispatch-chain resolution and
        direct-edge rewriting, dead dispatcher removal.
      - unflat/new_unflattener: classic OLLVM central-dispatcher valrange
        unflattening plus BCF dead-code removal.
      - D-810 (instruction-only profile): 177 instruction rules - MBA
        simplification, constant folding, opaque predicates, Z3 SMT.
      - hrtng.dll keeps running autonomously (toggle: "[hrt] Enable
        Unflattener" in its own menu).
    """
    import ida_hexrays
    ok_flow = _install_hexrays_hook()
    ok_unflat = _start_preferred_unflattener()
    ok_mba = _start_d810_instructions()
    ea = ida_kernwin.get_screen_ea()
    func = ida_funcs.get_func(ea)
    if func:
        _analysis_for_entry(func.start_ea)
        try:
            ida_hexrays.mark_cfunc_dirty(func.start_ea, True)
        except Exception:
            pass
    _open_deobfuscated_pseudocode(func.start_ea if func else ea)
    ida_kernwin.info("Seagull all-around mode: structure=%s, classic-unflat=%s, D-810 instructions=%s" %
                     (ok_flow, ok_unflat, ok_mba))


def toggle_d810_instructions():
    if _D810_INSTR_STATE is not None:
        _stop_d810_instructions()
    else:
        _start_d810_instructions()
    _refresh_decompiler()


def toggle_d810_switch_case():
    """D-810's switch-case unflattener for flattening styles our engines
    do not cover; restores the user's profile selection afterwards."""
    if _D810_INSTR_STATE is not None:
        try:
            _D810_INSTR_STATE.load_project(D810_SWITCH_CASE_PROFILE)
            _D810_INSTR_STATE.start_d810()
            _D810_INSTR_STATE.d810_config.set("last_project_index", _D810_SAVED_INDEX)
            _D810_INSTR_STATE.d810_config.save()
            print("[%s] D-810 switch-case unflattening profile active" % PLUGIN_NAME)
            _refresh_decompiler()
            return
        except Exception as exc:
            print("[%s] D-810 switch-case profile failed: %s" % (PLUGIN_NAME, exc))
    _start_d810_instructions(D810_SWITCH_CASE_PROFILE)
    _refresh_decompiler()


def deflatten_current():
    """Scan first, then install microcode rewriting and refresh F5 output."""
    analyze_current()
    _recover_static_cfg()
    return enable_microcode_deflatten(refresh=True)


class SeagullHandler(ida_kernwin.action_handler_t):
    def __init__(self, callback):
        ida_kernwin.action_handler_t.__init__(self)
        self.callback = callback

    def activate(self, ctx):
        self.callback()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class SeagullPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_FIX
    comment = "Conservative native obfuscation triage"
    help = "Find CFF dispatchers, indirect jump tables, opaque predicates, and anti-disassembly idioms"
    wanted_name = PLUGIN_NAME
    # D-810 already uses Ctrl+Shift+D in the user's IDA installation.
    wanted_hotkey = "Ctrl+Shift+Alt+D"

    ACTION_SCAN = "seagull:scan-current"
    ACTION_ALL = "seagull:scan-all"
    ACTION_DEFLAT = "seagull:deflatten-current"
    ACTION_RECOVER = "seagull:recover-static-cfg"
    ACTION_ALLROUND = "seagull:allround-mode"
    ACTION_MBA = "seagull:toggle-d810-instructions"
    ACTION_SWITCHCASE = "seagull:d810-switch-case"

    def init(self):
        try:
            _install_ui_hook()
            _schedule_late_hooks()
            ida_kernwin.register_action(ida_kernwin.action_desc_t(
                self.ACTION_SCAN, "Seagull: scan current function", SeagullHandler(analyze_current),
                self.wanted_hotkey, self.help, 0))
            ida_kernwin.register_action(ida_kernwin.action_desc_t(
                self.ACTION_ALL, "Seagull: scan all functions", SeagullHandler(analyze_all),
                None, self.help, 0))
            ida_kernwin.register_action(ida_kernwin.action_desc_t(
                self.ACTION_DEFLAT, "Seagull: enable Hex-Rays optimizers",
                SeagullHandler(deflatten_current), None,
                "Enable installed Hex-Rays optimizers", 0))
            ida_kernwin.register_action(ida_kernwin.action_desc_t(
                self.ACTION_RECOVER, "Seagull: recover encoded CFG targets",
                SeagullHandler(lambda: _recover_static_cfg()), None,
                "Recover finite encoded indirect jump targets", 0))
            ida_kernwin.register_action(ida_kernwin.action_desc_t(
                self.ACTION_ALLROUND, "Seagull: arm/disarm all-around deobfuscation",
                SeagullHandler(toggle_allround), None,
                "Arm the full deobfuscation stack: Seagull structure recovery, unflat classic dispatcher, D-810 instruction simplification", 0))
            ida_kernwin.register_action(ida_kernwin.action_desc_t(
                self.ACTION_MBA, "Seagull: toggle D-810 instruction simplifier (MBA)",
                SeagullHandler(toggle_d810_instructions), None,
                "Toggle D-810's 177 instruction rules (MBA, constants, opaque predicates, Z3)", 0))
            ida_kernwin.register_action(ida_kernwin.action_desc_t(
                self.ACTION_SWITCHCASE, "Seagull: D-810 switch-case unflattener",
                SeagullHandler(toggle_d810_switch_case), None,
                "Switch D-810 to its switch-case unflattening profile", 0))
            ida_kernwin.attach_action_to_menu("Edit/Plugins/", self.ACTION_SCAN, ida_kernwin.SETMENU_APP)
            ida_kernwin.attach_action_to_menu("Edit/Plugins/", self.ACTION_ALL, ida_kernwin.SETMENU_APP)
            ida_kernwin.attach_action_to_menu("Edit/Plugins/", self.ACTION_DEFLAT, ida_kernwin.SETMENU_APP)
            ida_kernwin.attach_action_to_menu("Edit/Plugins/", self.ACTION_RECOVER, ida_kernwin.SETMENU_APP)
            ida_kernwin.attach_action_to_menu("Edit/Plugins/", self.ACTION_ALLROUND, ida_kernwin.SETMENU_APP)
            ida_kernwin.attach_action_to_menu("Edit/Plugins/", self.ACTION_MBA, ida_kernwin.SETMENU_APP)
            ida_kernwin.attach_action_to_menu("Edit/Plugins/", self.ACTION_SWITCHCASE, ida_kernwin.SETMENU_APP)
            try:
                import seagull_core
                print("[%s] decoder=%s" % (PLUGIN_NAME, seagull_core.CAPSTONE_PATH or "unavailable"))
            except Exception as exc:
                print("[%s] decoder status unavailable: %s" % (PLUGIN_NAME, exc))
            print("[%s] %s loaded" % (PLUGIN_NAME, PLUGIN_VERSION))
            return idaapi.PLUGIN_KEEP
        except Exception:
            print("[%s] initialization failed\n%s" % (PLUGIN_NAME, traceback.format_exc()))
            return idaapi.PLUGIN_SKIP

    def run(self, arg):
        # Clicking the plugin entry (Edit -> Plugins -> Seagull Deobfuscator)
        # toggles the whole stack: nothing runs until this is clicked.
        toggle_allround()

    def term(self):
        global _D810_STATE, _HEX_HOOK, _HEX_ANALYSIS, _UI_HOOK, _UI_TIMER, _UNFLAT_ACTIVE
        if _D810_INSTR_STATE is not None:
            _stop_d810_instructions()
        if _UI_TIMER is not None:
            try:
                ida_kernwin.unregister_timer(_UI_TIMER)
            except Exception:
                pass
            _UI_TIMER = None
        if _UI_HOOK is not None:
            try:
                _UI_HOOK.unhook()
            except Exception:
                pass
            _UI_HOOK = None
        if _HEX_HOOK is not None:
            try:
                _HEX_HOOK.unhook()
            except Exception:
                pass
            _HEX_HOOK = None
        _HEX_ANALYSIS.clear()
        if _D810_STATE is not None:
            try:
                _D810_STATE.stop_d810()
            except Exception:
                pass
            _D810_STATE = None
        if _MICROCODE_UNFLAT is not None:
            try:
                hook = getattr(_MICROCODE_UNFLAT, "hook_instance", None)
                if hook:
                    hook.unhook()
            except Exception:
                pass
        _UNFLAT_ACTIVE = False
        for action in (self.ACTION_SCAN, self.ACTION_ALL, self.ACTION_DEFLAT, self.ACTION_RECOVER,
                       self.ACTION_ALLROUND, self.ACTION_MBA, self.ACTION_SWITCHCASE):
            try:
                ida_kernwin.unregister_action(action)
            except Exception:
                pass


def PLUGIN_ENTRY():
    return SeagullPlugin()


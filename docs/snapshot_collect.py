"""Oo0l1IVvMm runtime-snapshot collector.

Run this INSIDE IDA while DEBUGGING the target (native Windows debugger):
  1. Set your breakpoint where the obfuscation tables are known to be built
     (e.g. the md5-compare site hinted by the challenge's own
     print_target_md5.py - break on the function that reads the input buffer,
     or on any dispatch site inside the flattened function).
  2. When the debugger stops there, run:  Oo0l1IVvMm.snapshot_collect()
     from the IDA Python console (or via the plugin's
     "load runtime snapshot" action after importing this module).

It dumps every segment of the debugged process plus the concrete registers,
and writes a manifest that Oo0l1IVvMm's "load runtime snapshot" action
consumes: resolve_chain then overlays the runtime tables, pins the captured
seeds, and recovers the CFG of lazily-initialized flattening.
"""
import json
import os

import idaapi
import ida_dbg
import ida_segment
import ida_bytes

OUT_DIR = os.path.join(os.environ.get("TEMP", "."), "oo_snapshot_out")


def snapshot_collect(out_dir=OUT_DIR, max_bytes_per_seg=0x40000):
    if not ida_dbg.dbg_can_query():
        print("[snapshot] debugger is not paused on a process - run to your "
              "breakpoint first")
        return None
    os.makedirs(out_dir, exist_ok=True)
    regions = []
    nseg = ida_segment.get_segm_qty()
    for i in range(nseg):
        seg = ida_segment.getnseg(i)
        if seg is None:
            continue
        size = min(seg.end_ea - seg.start_ea, max_bytes_per_seg)
        data = ida_dbg.read_dbg_memory(seg.start_ea, size)
        if not data:
            continue
        fname = "%s_%x.bin" % (ida_segment.get_segm_name(seg).strip(".@") or "seg", seg.start_ea)
        with open(os.path.join(out_dir, fname), "wb") as fp:
            fp.write(data)
        regions.append({"name": ida_segment.get_segm_name(seg),
                        "ea": "%x" % seg.start_ea,
                        "size": len(data),
                        "bytes": fname})

    regs = {}
    for name in ("rcx", "rdx", "r8", "r9", "rbx", "rsi", "rdi",
                 "r10", "r11", "r12", "r13", "r14", "r15", "rax", "rbp"):
        try:
            regs[name] = ida_dbg.get_reg_val(name)
        except Exception:
            pass
    rsp = regs.get("rsp")
    rip = regs.get("rip") or ida_dbg.get_ip_val()
    stack = b""
    if rsp:
        stack = ida_dbg.read_dbg_memory(rsp, 0x2000) or b""
    with open(os.path.join(out_dir, "stack.bin"), "wb") as fp:
        fp.write(stack)

    manifest = {
        "rip": "%x" % (rip or 0),
        "rsp": "%x" % (rsp or 0),
        "registers": {k: v for k, v in regs.items()},
        "regions": regions,
    }
    mpath = os.path.join(out_dir, "manifest.json")
    with open(mpath, "w", encoding="utf-8") as fp:
        json.dump(manifest, fp, indent=1)
    print("[snapshot] %d regions, rip=%#x rsp=%#x -> %s" %
          (len(regions), rip or 0, rsp or 0, mpath))
    print("[snapshot] now: Edit -> Plugins -> Oo0l1IVvMm: load runtime snapshot, "
          "pick %s, then MAX-mode F5 the flattened function" % mpath)
    return mpath

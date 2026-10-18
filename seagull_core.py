"""Bounded x86-64 abstract interpretation, independent of IDA operand text.

Unknown values are TOP, never zero. Both outcomes of unknown conditions are
visited. Results describe an overapproximation, not a sampled execution trace.
"""
from collections import deque
from itertools import product
import os
import sys


def _load_capstone():
    """Load Capstone without requiring a separate IDA Python install.

    IDA 9.1 ships its own Python runtime, so a package installed in the
    user's normal Python environment is invisible to plugins.  Lookup order:
    the SEAGULL_CAPSTONE_PATH environment variable, the plugin-local vendor
    directory, then anything already importable from sys.path (e.g. a
    capstone installed into IDA's Python).  The analyzer stays importable
    when none is present; the caller reports the missing optional decoder
    instead of failing during plugin discovery.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.environ.get("SEAGULL_CAPSTONE_PATH", ""),
        os.path.join(here, "vendor"),
        os.path.join(here, "..", "vendor"),
    ]
    for root in candidates:
        root = os.path.abspath(root)
        if os.path.isdir(os.path.join(root, "capstone")) and root not in sys.path:
            sys.path.insert(0, root)
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_JUMP, CS_GRP_RET
        from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM
        return (Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_JUMP, CS_GRP_RET,
                X86_OP_REG, X86_OP_IMM, X86_OP_MEM, None)
    except Exception as exc:
        return (None, None, None, None, None, None, None, None, exc)


(Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_JUMP, CS_GRP_RET,
 X86_OP_REG, X86_OP_IMM, X86_OP_MEM, _CAPSTONE_ERROR) = _load_capstone()
CAPSTONE_AVAILABLE = Cs is not None
CAPSTONE_PATH = getattr(sys.modules.get("capstone"), "__file__", None)

MASK = (1 << 64) - 1
LIMIT = 8


def values(*xs):
    return frozenset(x & MASK for x in xs)


def join(a, b):
    if a is None or b is None:
        return None
    c = a | b
    return c if len(c) <= LIMIT else None


def calc(a, b, fn, bits=64):
    if a is None or b is None:
        return None
    mask = (1 << bits) - 1
    try:
        c = frozenset(fn(x, y) & mask for x, y in product(a, b))
        return c if len(c) <= LIMIT else None
    except (ValueError, ZeroDivisionError):
        return None


def alias(name):
    roots = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp']
    for root in roots:
        stem = root[1:]
        names = {root: (64, 0), 'e' + stem: (32, 0), stem: (16, 0)}
        low = stem[0] + 'l' if root in roots[:4] else stem + 'l'
        names[low] = (8, 0)
        if root in roots[:4]:
            names[stem[0] + 'h'] = (8, 8)
        if name in names:
            return (root,) + names[name]
    if name.startswith('r') and name[1:].rstrip('dwb').isdigit():
        suffix = name[-1]
        return (name[:-1], {'d': 32, 'w': 16, 'b': 8}[suffix], 0) if suffix in 'dwb' else (name, 64, 0)
    return name, 64, 0


class State:
    def __init__(self, regs=None, mem=None):
        self.regs = dict(regs or {})
        self.mem = dict(mem or {})

    def copy(self):
        return State(self.regs, self.mem)

    def read(self, name):
        root, bits, shift = alias(name)
        v = self.regs.get(root)
        return None if v is None else frozenset((x >> shift) & ((1 << bits) - 1) for x in v)

    def write(self, name, v):
        root, bits, shift = alias(name)
        if bits >= 32:
            self.regs[root] = None if v is None else frozenset(x & ((1 << bits) - 1) for x in v)
        else:
            mask = ((1 << bits) - 1) << shift
            self.regs[root] = calc(self.regs.get(root), v, lambda a, b: (a & ~mask) | ((b << shift) & mask))

    def merge(self, other):
        changed = False
        for mine, theirs in [(self.regs, other.regs), (self.mem, other.mem)]:
            for k in set(mine) | set(theirs):
                v = join(mine.get(k), theirs.get(k))
                if k not in mine or mine[k] != v:
                    mine[k] = v
                    changed = True
        return changed


class Analyzer:
    def __init__(self, read, start, end):
        self.read = read
        self.start, self.end = start, end
        self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self.cs.detail = True
        self.insns = {}
        self.states = {}
        self.edges = {}
        self.calls = {}
        self.unresolved = set()
        self.steps = 0

    def decode(self, ea):
        if ea not in self.insns:
            data = self.read(ea, min(15, self.end - ea))
            self.insns[ea] = next(self.cs.disasm(data or b'', ea, 1), None)
        return self.insns[ea]

    def address(self, ins, op, state):
        m = op.mem
        if m.segment:
            return None
        base = values(ins.address + ins.size) if ins.reg_name(m.base) == 'rip' else state.read(ins.reg_name(m.base)) if m.base else values(0)
        index = calc(state.read(ins.reg_name(m.index)), values(m.scale), lambda a, b: a * b) if m.index else values(0)
        return calc(calc(base, index, lambda a, b: a + b), values(m.disp), lambda a, b: a + b)

    def operand(self, ins, op, state):
        if op.type == X86_OP_IMM:
            return values(op.imm & ((1 << (op.size * 8)) - 1))
        if op.type == X86_OP_REG:
            return state.read(ins.reg_name(op.reg))
        if op.type == X86_OP_MEM:
            addresses = self.address(ins, op, state)
            if addresses is None:
                return None
            out = frozenset()
            for a in addresses:
                key = a, op.size
                if key in state.mem:
                    v = state.mem[key]
                elif 0x700000000000 <= a < 0x700000100000:
                    return None
                else:
                    raw = self.read(a, op.size)
                    v = values(int.from_bytes(raw, 'little')) if raw and len(raw) == op.size else None
                out = join(out, v)
                if out is None:
                    return None
            return out
        return None

    def put(self, ins, op, state, v):
        if op.type == X86_OP_REG:
            state.write(ins.reg_name(op.reg), v)
        elif op.type == X86_OP_MEM:
            addrs = self.address(ins, op, state)
            if addrs is None:
                # An unmodelled alias may overwrite known local memory.
                state.mem.clear()
                return
            for a in addrs:
                for key in list(state.mem):
                    if key[0] < a + op.size and a < key[0] + key[1]:
                        state.mem[key] = None
                state.mem[(a, op.size)] = v if len(addrs) == 1 else None

    def execute(self, ins, s):
        m, ops = ins.mnemonic, ins.operands
        get = lambda n: self.operand(ins, ops[n], s)
        put = lambda v: self.put(ins, ops[0], s, v)
        bits = ops[0].size * 8 if ops else 64
        if m in ('mov', 'movabs', 'movzx'):
            put(get(1))
        elif m in ('movsx', 'movsxd'):
            b = ops[1].size * 8
            v = get(1)
            put(None if v is None else frozenset((x - (1 << b) if x & (1 << (b - 1)) else x) & ((1 << bits) - 1) for x in v))
        elif m == 'lea':
            put(self.address(ins, ops[1], s))
        elif m in ('xor', 'sub') and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG and ops[0].reg == ops[1].reg:
            put(values(0))
        elif m in ('add', 'sub', 'xor', 'and', 'or', 'shl', 'sal', 'shr', 'sar', 'imul'):
            funcs = {'add': lambda a,b:a+b, 'sub': lambda a,b:a-b, 'xor':lambda a,b:a^b,
                     'and':lambda a,b:a&b, 'or':lambda a,b:a|b, 'shl':lambda a,b:a << (b & (63 if bits == 64 else 31)),
                     'sal':lambda a,b:a << (b & (63 if bits == 64 else 31)), 'shr':lambda a,b:a >> (b & (63 if bits == 64 else 31)),
                     'sar':lambda a,b: (a-(1<<bits) if a & (1<<(bits-1)) else a) >> (b & (63 if bits == 64 else 31)),
                     'imul':lambda a,b:a*b}
            put(calc(get(1) if len(ops) == 3 else get(0), get(2) if len(ops) == 3 else get(1), funcs[m], bits))
        elif m in ('inc', 'dec', 'neg', 'not'):
            put(calc(get(0), values(0), {'inc':lambda a,b:a+1, 'dec':lambda a,b:a-1, 'neg':lambda a,b:-a, 'not':lambda a,b:~a}[m], bits))
        elif m.startswith('set'):
            put(values(0, 1))
        elif m.startswith('cmov'):
            put(join(get(0), get(1)))
        elif m == 'push':
            v = get(0)
            s.write('rsp', calc(s.read('rsp'), values(8), lambda a,b:a-b))
            a = s.read('rsp')
            if a and len(a) == 1:
                s.mem[(next(iter(a)), 8)] = v
        elif m == 'pop':
            a = s.read('rsp')
            put(s.mem.get((next(iter(a)), 8)) if a and len(a) == 1 else None)
            s.write('rsp', calc(s.read('rsp'), values(8), lambda a,b:a+b))
        elif m == 'call':
            v = get(0)
            self.calls[ins.address] = join(self.calls.get(ins.address, frozenset()), v)
            for r in ('rax','rcx','rdx','rsi','rdi','r8','r9','r10','r11'):
                s.write(r, None)
        elif m not in ('cmp','test','nop','endbr64') and not ins.group(CS_GRP_JUMP) and not ins.group(CS_GRP_RET):
            _, written = ins.regs_access()
            for reg in written:
                s.write(ins.reg_name(reg), None)
            if ops and ops[0].type == X86_OP_MEM and ops[0].access & 2:
                self.put(ins, ops[0], s, None)

    def run(self, max_steps=250000):
        initial = State({'rsp': values(0x700000080000)})
        self.states[self.start] = initial
        todo = deque([self.start])
        queued = {self.start}
        def enqueue(ea, s):
            if not self.start <= ea < self.end:
                return
            if ea not in self.states:
                self.states[ea] = s.copy()
                changed = True
            else:
                changed = self.states[ea].merge(s)
            if changed and ea not in queued:
                todo.append(ea)
                queued.add(ea)
        while todo:
            ea = todo.popleft()
            queued.discard(ea)
            self.steps += 1
            if self.steps > max_steps:
                raise RuntimeError('abstract interpretation exceeded step budget')
            ins = self.decode(ea)
            if not ins:
                continue
            s = self.states[ea].copy()
            if ins.mnemonic == 'jmp':
                targets = self.operand(ins, ins.operands[0], s)
                if ins.operands[0].type != X86_OP_IMM:
                    old = self.edges.get(ea, frozenset())
                    self.edges[ea] = join(old, targets)
                    if self.edges[ea] is None:
                        self.unresolved.add(ea)
                if targets:
                    for dst in targets:
                        enqueue(dst, s)
            elif ins.group(CS_GRP_JUMP):
                if ins.operands[0].type == X86_OP_IMM:
                    enqueue(ins.operands[0].imm, s)
                enqueue(ea + ins.size, s)
            elif not ins.group(CS_GRP_RET) and ins.mnemonic not in ('ud2','hlt','int3'):
                self.execute(ins, s)
                enqueue(ea + ins.size, s)
        return self


class ElfImage:
    def __init__(self, path):
        from elftools.elf.elffile import ELFFile
        with open(path, 'rb') as f:
            elf = ELFFile(f)
            self.segments = [(int(s['p_vaddr']), s.data()) for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']
            self.functions = sorted((int(e['initial_location']), int(e['initial_location'] + e['address_range']))
                                    for e in elf.get_dwarf_info().EH_CFI_entries() if e.__class__.__name__ == 'FDE')

    def read(self, address, size):
        for base, data in self.segments:
            if base <= address and address + size <= base + len(data):
                return data[address-base:address-base+size]
        return None


# ---------------------------------------------------------------------------
# Dispatch-chain resolution.
#
# Some flatteners do not use a compare-chain dispatcher on a register. Each
# state block updates a state value (kept in a stack slot or a register),
# then dispatches through a chain of tiny compare-and-table stubs:
#
#     mov  edx, OFF_A
#     cmp  ecx, K
#     jl   next_insn          ; pick OFF_A or OFF_B
#     mov  edx, OFF_B
#     mov  rax, [rip+global]  ; table base, adjusted along the chain
#     mov  rdx, [rax + rdx + DISP]
#     add  rdx, r14           ; per-path decode key
#     jmp  rdx                ; miss -> next stub, hit -> state block
#
# Merged abstract states cannot resolve these sites (the state base lives in
# a stack slot that stores through unknown addresses keep invalidating). The
# resolver below re-executes the chain once per state-update site with that
# site's own concrete values, which recovers the exact next block.
# ---------------------------------------------------------------------------

SIGNED_JCC = {'jl': lambda a, b: a < b, 'jge': lambda a, b: a >= b,
              'jg': lambda a, b: a > b, 'jle': lambda a, b: a <= b}
UNSIGNED_JCC = {'jb': lambda a, b: a < b, 'jbe': lambda a, b: a <= b,
                'ja': lambda a, b: a > b, 'jae': lambda a, b: a >= b}
EQUAL_JCC = {'je': lambda a, b: a == b, 'jne': lambda a, b: a != b}


def _signed(v, bits):
    return v - (1 << bits) if v & (1 << (bits - 1)) else v


def slot_inits(analyzer, start, end):
    """Constant single-writer stack slots keyed by true address.

    Writers' own concrete rsp computes the slot address; functions with big
    prologues keep their slots far below the entry rsp.
    """
    writes = {}
    for ea, ins in analyzer.insns.items():
        if not (start <= ea < end):
            continue
        ops = ins.operands
        if ins.mnemonic in ('mov', 'movl') and len(ops) >= 2 and \
                ops[0].type == X86_OP_MEM and ops[1].type == X86_OP_IMM:
            m = ops[0].mem
            if ins.reg_name(m.base) == 'rsp' and not m.index:
                s = analyzer.states.get(ea)
                rsp = s.read('rsp') if s is not None else None
                if rsp is None or len(rsp) != 1:
                    continue
                addr = (next(iter(rsp)) + m.disp) & MASK
                writes.setdefault((addr, ops[0].size), []).append(
                    ops[1].imm & ((1 << (ops[0].size * 8)) - 1))
    return {key: vals[0] for key, vals in writes.items() if len(vals) == 1}


class StickyAnalyzer(Analyzer):
    """Analyzer whose memory model preserves constant single-writer slots.

    A store through an unknown address clears the whole memory model, which
    loses the state base kept in a single-writer slot. Those slots survive
    clears and are never invalidated by overlap writes.
    """
    sticky_slots = {}

    def put(self, ins, op, state, v):
        import capstone
        if op.type == capstone.x86.X86_OP_MEM:
            addrs = self.address(ins, op, state)
            if addrs is None:
                state.mem.clear()
                state.mem.update(self.sticky_slots)
                return
        Analyzer.put(self, ins, op, state, v)


class ChainWalker:
    """Concrete re-execution of the dispatch chain from a state-update site."""

    def __init__(self, analyzer):
        self.an = analyzer
        self._stub_cache = {}

    def is_stub(self, ea):
        """A dispatch stub: a short side-effect-free run ending in `jmp reg`."""
        if ea in self._stub_cache:
            return self._stub_cache[ea]
        result = False
        cur, n = ea, 0
        while cur is not None and n < 15:
            ins = self.an.decode(cur)
            if ins is None:
                break
            if ins.mnemonic == 'jmp':
                result = ins.operands[0].type != X86_OP_IMM
                break
            if ins.mnemonic == 'call' or ins.mnemonic.startswith('ret'):
                break
            if ins.operands and ins.operands[0].type == X86_OP_MEM and ins.operands[0].access & 2:
                break
            cur = cur + ins.size
            n += 1
        self._stub_cache[ea] = result
        return result

    def _decide(self, mnem, a, b, bits):
        fn = SIGNED_JCC.get(mnem) or UNSIGNED_JCC.get(mnem) or EQUAL_JCC.get(mnem)
        if fn is None:
            return None
        if mnem in SIGNED_JCC:
            return fn(_signed(a, bits), _signed(b, bits))
        return fn(a, b)

    def walk(self, start_ea, state, max_steps=4000):
        """Execute the chain; return the set of final non-stub targets."""
        import capstone
        CS_GRP_JUMP = capstone.CS_GRP_JUMP
        CS_GRP_RET = capstone.CS_GRP_RET
        finals = set()
        stack = [(start_ea, state.copy())]
        steps = 0
        while stack:
            ea, s = stack.pop()
            cur = ea
            pending = None
            while True:
                steps += 1
                if steps > max_steps:
                    return None
                ins = self.an.decode(cur)
                if ins is None:
                    return None
                m = ins.mnemonic
                if m in ('cmp', 'test'):
                    ops = ins.operands
                    pending = (m, self.an.operand(ins, ops[0], s), self.an.operand(ins, ops[1], s),
                               ops[0].size * 8 if ops[0].size else 32)
                    cur += ins.size
                    continue
                if m.startswith('set') and pending is not None and pending[0] == 'cmp':
                    ops = ins.operands
                    cond = None
                    if pending[1] is not None and len(pending[1]) == 1 and pending[2] is not None and len(pending[2]) == 1:
                        cond = self._decide('j' + m[3:], next(iter(pending[1])), next(iter(pending[2])), pending[3])
                    if cond is not None:
                        self.an.put(ins, ops[0], s, values(1 if cond else 0))
                    else:
                        self.an.put(ins, ops[0], s, values(0, 1))
                    cur += ins.size
                    continue
                if m == 'jmp':
                    ops = ins.operands
                    if ops[0].type == X86_OP_IMM:
                        cur = ops[0].imm
                        continue
                    tset = self.an.operand(ins, ops[0], s)
                    if not tset:
                        return None
                    for t in tset:
                        if self.is_stub(t):
                            stack.append((t, s.copy()))
                        else:
                            finals.add(t)
                    break
                if ins.group(CS_GRP_JUMP):
                    ops = ins.operands
                    taken = None
                    if pending is not None and pending[0] in ('cmp', 'test') and \
                            pending[1] is not None and len(pending[1]) == 1 and \
                            pending[2] is not None and len(pending[2]) == 1:
                        a, b = next(iter(pending[1])), next(iter(pending[2]))
                        if pending[0] == 'test':
                            if m in ('je', 'jne'):
                                taken = EQUAL_JCC[m](a & b, 0)
                        else:
                            taken = self._decide(m, a, b, pending[3])
                    if taken is None:
                        if ops[0].type == X86_OP_IMM:
                            stack.append((ops[0].imm, s.copy()))
                        cur += ins.size
                    elif taken:
                        if ops[0].type != X86_OP_IMM:
                            return None
                        cur = ops[0].imm
                    else:
                        cur += ins.size
                    pending = None
                    continue
                if ins.group(CS_GRP_RET) or m in ('ud2', 'hlt', 'int3'):
                    return None
                self.an.execute(ins, s)
                cur += ins.size
        return finals or None


def _discover_chain_regs(an, chain_head):
    """State and decode-key register names used by the dispatch chain.

    The state register is what the chain head's first `cmp` tests; the decode
    key is the register added to the table entry right before `jmp reg`.
    Falls back to the common ecx/r14 pair when the shapes are not found.
    """
    state_reg, key_reg = "ecx", "r14"
    insns = []
    cur = chain_head
    for _ in range(16):
        ins = an.decode(cur)
        if ins is None:
            break
        insns.append(ins)
        if ins.mnemonic == "jmp":
            break
        cur += ins.size
    for ins in insns:
        if ins.mnemonic in ("cmp", "test"):
            for op in ins.operands[:2]:
                if op.type == X86_OP_REG:
                    state_reg = ins.reg_name(op.reg)
                    break
            break
    for ins in reversed(insns):
        if ins.mnemonic in ("add", "sub", "xor", "or", "and") and ins.operands[0].type == X86_OP_REG \
                and ins.operands[1].type == X86_OP_REG:
            key_reg = ins.reg_name(ins.operands[1].reg)
            break
    return state_reg, key_reg


def _pin_seeds(an, seeds):
    """Overwrite seeded registers in every abstract state and re-propagate."""
    for ea, st in an.states.items():
        for reg, val in seeds.items():
            st.write(reg, values(val & MASK))


class ChainResolution(object):
    """Outcome of dispatch-chain resolution.

    ``rewires`` maps each state-update site to ((state_value, target), ...)
    pairs: at runtime the site's state register holds one of the values and
    control continues at the matching target. Single-pair sites become direct
    edges; multi-pair sites are genuine data-dependent joins (the obfuscator
    folded the original if/else into the state computation, often via cmov)
    and need a conditional split.
    """

    def __init__(self, rewires, chain_head, state_reg, key_reg, site_kinds=None):
        self.rewires = rewires
        self.chain_head = chain_head
        self.state_reg = state_reg
        self.key_reg = key_reg
        self.site_kinds = site_kinds or {}


def resolve_chain(read, start, end, max_steps_per_site=4000, seeds=None,
                  mem_overlay=None):
    """Resolve every state-update site's real next block.

    seeds: optional {regname: int} concrete values injected at the function
    entry state (e.g. a runtime-captured dispatch key that lives in a
    caller-provided buffer). Every seeded register is pinned for the whole
    run, which lets the walker resolve sites whose key normally comes from
    an input buffer.

    mem_overlay: optional {ea: bytes} patches applied on top of `read`
    (e.g. runtime-captured table contents for lazily-built dispatch
    tables). Applied through a wrapping reader so lookups see the live
    memory instead of the file image.

    Returns a ChainResolution (or None when no dispatcher chain exists).
    """
    import capstone
    CS_GRP_JUMP = capstone.CS_GRP_JUMP
    CS_GRP_RET = capstone.CS_GRP_RET

    if mem_overlay:
        class _Overlay:
            def __init__(self, inner):
                self.inner = inner
            def __call__(self, ea, size):
                for oea, obytes in mem_overlay.items():
                    if oea <= ea and ea + size <= oea + len(obytes):
                        return obytes[ea - oea: ea - oea + size]
                return self.inner(ea, size)
        read = _Overlay(read)

    base = Analyzer(read, start, end).run()
    if not base.edges:
        return None
    sticky = {key: values(v) for key, v in slot_inits(base, start, end).items()}
    if seeds:
        import capstone
        for reg, val in seeds.items():
            lo = reg.lower()
            if lo in ("ecx", "rcx"):
                # seed both the 64-bit root and pin via sticky reg mechanism
                sticky[("reg:" + lo, 4)] = values(val & 0xFFFFFFFF)
            else:
                sticky[("reg:" + lo, 8)] = values(val & MASK)
        # teach StickyAnalyzer to apply register seeds on every state copy
    StickyAnalyzer.sticky_slots = sticky
    an = StickyAnalyzer(read, start, end).run()
    if seeds:
        _pin_seeds(an, seeds)

    walker = ChainWalker(an)

    # chain head: most-targeted direct-jump destination inside the region
    tgt_count = {}
    for ea, ins in an.insns.items():
        if ins.mnemonic == 'jmp' and ins.operands[0].type == X86_OP_IMM:
            t = ins.operands[0].imm
            if start < t < end:
                tgt_count[t] = tgt_count.get(t, 0) + 1
    if not tgt_count:
        return None
    chain_head = max(tgt_count.items(), key=lambda kv: kv[1])[0]
    state_reg, key_reg = _discover_chain_regs(an, chain_head)
    stub_starts = {chain_head}
    for targets in an.edges.values():
        for t in (targets or ()):
            if t != chain_head and walker.is_stub(t):
                stub_starts.add(t)

    entries = {}
    for ea, ins in an.insns.items():
        if not (start <= ea < end):
            continue
        dst = None
        kind = None
        if ins.mnemonic == 'jmp':
            if ins.operands[0].type == X86_OP_IMM and ins.operands[0].imm in stub_starts:
                dst = ins.operands[0].imm
                kind = 'jmp'
        elif ins.group(CS_GRP_JUMP):
            # a conditional whose taken edge enters the chain keeps its
            # condition; only the taken target gets rewritten
            if ins.operands[0].type == X86_OP_IMM and ins.operands[0].imm in stub_starts:
                dst = ins.operands[0].imm
                kind = 'jcc'
        elif not ins.group(CS_GRP_RET):
            if ea + ins.size in stub_starts:
                dst = ea + ins.size
                kind = 'fall'
        if dst is not None:
            entries[ea] = (dst, kind)

    rewires = {}
    site_kinds = {}
    for ea in sorted(entries):
        entry_dst, kind = entries[ea]
        site_kinds[ea] = kind
        s = an.states.get(ea)
        if s is None:
            continue
        s = s.copy()
        ins = an.decode(ea)
        if ins is not None and ins.mnemonic != 'jmp' and not ins.group(CS_GRP_JUMP):
            try:
                an.execute(ins, s)
            except Exception:
                continue
        # Split join points into singleton-state walks: a site reached with
        # several state values is a real data-dependent join (each value has
        # its own next block), and walking them together explodes the paths.
        sv = s.read(state_reg)
        kv = s.read(key_reg)
        splits = []
        if sv is not None and kv is not None:
            for v in sorted(sv):
                for k in sorted(kv):
                    s2 = s.copy()
                    s2.write(state_reg, values(v))
                    s2.write(key_reg, values(k))
                    splits.append((v, s2))
        else:
            splits.append((None, s))
        pairs = {}
        ok = True
        for v, s2 in splits:
            got = walker.walk(entry_dst, s2, max_steps_per_site)
            if got is None:
                ok = False
                break
            pairs.setdefault(v, set()).update(got)
        if not ok or not pairs:
            continue
        # every state value must lead to exactly one block for a clean split
        if all(len(t) == 1 for t in pairs.values()):
            rewires[ea] = tuple((v, next(iter(t))) for v, t in pairs.items())
    return ChainResolution(rewires, chain_head, state_reg, key_reg, site_kinds)


if __name__ == '__main__':
    import sys, json
    image = ElfImage(sys.argv[1])
    reports = []
    for start, end in image.functions:
        if start < 0x401150:
            continue
        a = Analyzer(image.read, start, end).run()
        report = {'start':start,'end':end,'instructions':len(a.insns),'steps':a.steps,
                  'edges':{str(k):sorted(v) for k,v in a.edges.items() if v},
                  'unresolved':sorted(k for k,v in a.edges.items() if v is None),
                  'calls':{str(k):sorted(v) for k,v in a.calls.items() if v}}
        reports.append(report)
        print(hex(start),len(a.insns),'edges',len(report['edges']),'unknown',len(report['unresolved']),'steps',a.steps, flush=True)
    with open(sys.argv[2], 'w') as f:
        json.dump(reports, f, indent=2)


# IDA scans every .py file in plugins/ and expects a plugin entry point. Keep
# the analyzer importable while making this support module a harmless skipped
# plugin when it is discovered by the loader.
try:
    import idaapi as _idaapi
    class _SeagullCoreLibraryPlugin(_idaapi.plugin_t):
        flags = _idaapi.PLUGIN_HIDE
        wanted_name = "Seagull Core Library"
        comment = "Seagull analyzer support module"
        help = ""
        wanted_hotkey = ""
        def init(self):
            return _idaapi.PLUGIN_SKIP
        def run(self, arg):
            return 0
        def term(self):
            pass
    def PLUGIN_ENTRY():
        return _SeagullCoreLibraryPlugin()
except Exception:
    pass


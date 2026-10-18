# Changelog

## 1.1.0 - 2026-10-19

- Runtime snapshot support: `resolve_chain(seeds=..., mem_overlay=...)` pins
  concrete dispatch-key registers and overlays runtime-captured table memory.
- New action `Oo0l1IVvMm: load runtime snapshot` (manifest + region bins).
- `docs/snapshot_collect.py`: in-debugger collector for snapshot manifests.

## 1.0.0 - 2026-10-19

- Renamed plugin to **Oo0l1IVvMm**; file renamed to `Oo0l1IVvMm.py`.
- Two modes with an opt-in chooser (plugin entry / menu / Ctrl+Shift+Alt+D):
  - **MIN** - classic OLLVM flattening: materialization + jtbl lifting +
    unflat valrange + D-810 instruction simplification (chain resolver off).
  - **MAX** - encoded inline dispatch (`jmp reg` family): everything in MIN
    plus the concrete chain resolver, microcode direct-edge/jz rewriting and
    dead-dispatcher removal.
- Disarmed by default: vanilla F5 speed, zero background work.

## 0.9.0 - 2026-10-19

- Manual arming model; capstone lookup generalized
  (`SEAGULL_CAPSTONE_PATH` > `vendor/` > `sys.path`).

## 0.8.0 - 2026-10-19

- All-around orchestration: D-810 instruction-only profile (177 rules)
  conflict-guarded against the flow engines; user profile selection restored.

## 0.7.0 - 2026-10-18

- Full dispatch-chain resolution (74/74 sites on the reference sample) with
  two-phase microcode serial rewriting (fixes renumbering corruption),
  fallthrough goto-blocks, jcc taken-edge retargeting, glbopt dead-chain
  removal. GUI F5: 98390 -> 2965 chars, switch 175 -> 0, goto 131 -> 0.

## 0.6.0 - 2026-10-18

- Concrete chain walker (sticky single-writer stack slots + per-value split).

## 0.5.x - 2026-10-18

- Materialization + unflat integration + finite `ijmp -> jtbl` lifting.

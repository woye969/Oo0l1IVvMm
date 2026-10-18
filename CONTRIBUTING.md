# Contributing

Thanks for your interest in improving Oo0l1IVvMm!

## Development setup

1. Copy `Oo0l1IVvMm.py` and `seagull_core.py` into your IDA plugins directory
   (or run `install.ps1`).
2. Make sure `capstone` is importable from IDA's Python
   (set `SEAGULL_CAPSTONE_PATH` or place it under `plugins/vendor/capstone`).
3. Restart IDA, then `Edit -> Plugins -> Oo0l1IVvMm` to pick a mode.

## Testing

There is no public sample shipped with the repo. Before submitting a change,
please re-verify on your own flattened binary that:

- disarmed mode: F5 output identical to vanilla Hex-Rays, plugin silent;
- MIN mode: no crashes on non-flattened functions (regression safety);
- MAX mode: previously-working samples keep resolving, no INTERR popups.

## Code style

- Pure `idaapi`/`ida_hexrays` public API only; guard anything version-specific.
- Never patch process memory outside the debugger or fake control-flow edges:
  every rewritten edge must come from a proven (concretely executed) state.
- Keep `seagull_core.py` importable outside IDA (it must not import idaapi at
  module level) so the analyzer stays testable standalone.

## Reporting issues

Include: IDA/Hex-Rays version, OS, the plugin's message-log lines
(`[Oo0l1IVvMm] ...`), and - if possible - a **sanitized** description of the
obfuscation shape (stub protocol, where the state/key live). Do not upload
samples you are not allowed to share.

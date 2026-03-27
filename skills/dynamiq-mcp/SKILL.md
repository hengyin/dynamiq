---
name: dynamiq-mcp
description: Use when operating the Interactive Dynamic Analysis MCP server (`dynamiq`) for live binary sessions, including start/run loops, breakpoint placement from session symbols, stdin payload delivery, and output/state polling.
---

# Dynamiq MCP Skill

Use this skill when a task requires driving the `dynamiq` MCP tools for interactive dynamic analysis.

## Required Operating Rules

0. Keep analysis program-agnostic.
- Do not assume target-specific commands, prompts, symbol names, offsets, or exploit paths.
- Infer interaction flow from observed `stdout`/`stderr`, then adapt inputs accordingly.
- Use `syms`/`maps`/`regs` from the current session as the source of truth.

1. Never guess runtime addresses.
- Always call `syms` in the current session and use `symbols[].loaded_address` for `bp_add`.

2. Always close the run/input/output loop.
- After each `run`, call `stdout`, `stderr`, and usually `state`.
- After each `send_line`, `send_bytes`, or `send_file`, call `run` again, then poll `stdout`/`stderr`.

3. Treat elapsed run windows as non-fatal.
- A `run` result with `reason=window_elapsed` is not a failure.
- Mandatory sequence after `window_elapsed`: `stdout` -> `stderr` -> `state`.
- Do not close/restart solely because the run window elapsed.

4. Use the correct stdin tool.
- `send_line` for menu/prompt interactions.
- `send_bytes` for exact text/byte payloads.
- `send_file` for large payloads.

5. Prefer targeted breakpoint workflows for complex interactive binaries.
- Avoid long free-form interaction when trying to confirm a specific bug.
- Set breakpoints on likely handlers/parsers first, then drive minimal input to hit them.
- Use `regs`/`disasm`/`mem` at breakpoints to verify conditions and memory effects.
- Use static analysis to identify candidate functions/conditions, then validate dynamically.

## Canonical Session Sequence

1. `start` with absolute `target` (and optional `args`, `cwd`, `qemu_config`).
2. `state` to confirm launch.
3. `syms` (optional `name_filter`) and collect `loaded_address` values.
4. `bp_clear` then `bp_add` if breakpoints are needed.
5. `run`.
6. `stdout` + `stderr`.
7. `send_line` / `send_bytes` / `send_file` as needed.
8. Repeat `run` -> `stdout` -> `stderr` -> `state`.
9. Use `regs`, `disasm`, `mem`, `maps`, `step`, `bb` for inspection.
10. `close` at end.

## Tool Choice Guide

- `start`: begin a session; requires non-empty string `target`.
- `run`: resume execution; breakpoint-aware.
- `pause`: force pause while running.
- `syms`: resolve runtime addresses for this session only.
- `bp_add` / `bp_del` / `bp_clear` / `bp_list`: breakpoint management.
- `stdout` / `stderr`: incremental stream reads (cursor maintained by server).
- `send_line`: appends newline automatically.
- `send_bytes`: use `data` (text) or `data_hex` (raw bytes), not both.
- `send_file`: stream bytes from local file to stdin.
- `regs` / `disasm` / `mem` / `maps`: low-level state inspection.
- `state`: verify lifecycle (`idle`, `paused`, `running`, `exited`).
- `close`: terminate active session and reset stream cursors.

## Recovery Procedure

If the session behaves unexpectedly or appears stale:

1. Call `state`.
2. Drain `stdout` and `stderr`.
3. Call `close`.
4. Call `start` again.
5. Re-run `syms` and rebuild breakpoints using fresh `loaded_address` values.

## Deep + Wide Exploration Playbook

Use a two-loop strategy: breadth first, then depth on hotspots.

1. Build a breadth map first.
- Use static outputs to identify hubs: dispatchers, parsers, validators, alloc/copy/string handlers, and error exits.
- Resolve those symbols with `syms` and set initial breakpoints from `loaded_address`.

2. Run a structured input matrix.
- Prefer grouped cases over ad-hoc typing: valid, boundary, malformed, oversized, empty, and command-like inputs.
- For each case, keep the same loop: `run` -> `stdout` -> `stderr` -> `state`.

3. Track state-space explicitly.
- Treat each unique prompt/page/handler combination as a node.
- Record the shortest input sequence that reaches each node.
- Prioritize unexplored nodes, not repeated paths.

4. Use checkpoints for branch fanout.
- Save reusable checkpoints (or deterministic input prefixes) at major branch points.
- Fan out mutations from each checkpoint instead of restarting from process start.

5. Switch to depth mode only on risky paths.
- When breakpoints hit vulnerable surfaces, add fine-grained breakpoints nearby.
- Collect `regs`, `disasm`, and targeted `mem` reads to confirm exact conditions and effects.

6. Rank exploration by novelty.
- Prefer cases that increase unique breakpoint hits, unique states, or new error outputs.
- Deprioritize cases that reproduce known behavior without new evidence.

7. Keep reproducible evidence per path.
- Save: exact input sequence, breakpoint hit order, key `stdout`/`stderr`/`state`, and critical register/memory observations.
- Require reproducible replay before elevating a path to a vulnerability claim.

## Notes

- Prefer absolute target paths in `start`.
- For stack memory reads, call `regs` first and use live `rsp` from that result.
- Do not reuse addresses from previous sessions.
- If tool output indicates malformed arguments, fix input shape before retrying.

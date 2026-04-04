---
name: dynamiq-mcp
description: Use when operating the Interactive Dynamic Analysis MCP server (`dynamiq`) for live binary sessions, including start/advance loops, breakpoint placement from session symbols, stdin payload delivery, and output/state polling.
---

# Dynamiq MCP Skill

Use this skill when a task requires driving the `dynamiq` MCP tools for interactive dynamic analysis.

## When to Use MCP vs Scripting API

Dynamiq provides **two complementary interfaces** for analyzing target programs:

| Aspect | MCP Interface | Scripting API |
|--------|---|---|
| **Best For** | One-shot analysis from LLM; interactive debugging | Autonomous systems; testing; CI/CD pipelines |
| **Interaction** | JSON-RPC stateless requests; human-friendly | Python library; persistent session |
| **Session Management** | LLM manages session state across calls | Python code maintains session automatically |
| **Data Flow** | Request → Response cycle; clean separation | Direct method calls; full state access |
| **Integration** | Immediate availability; no setup | Local Python environment required |
| **Real-time Feedback** | Good for interactive exploration | Better for programmatic workflows |

**Choose MCP if:** You're analyzing a program interactively, need to explore dynamically, or want clean separation between tool calls.

**Choose Scripting if:** You're building autonomous tests, security scanners, CI/CD workflows, or need persistent session state without round-trip overhead.

### Example Scenarios

- **MCP**: "Help me analyze this binary by setting breakpoints at malloc and checking memory allocation patterns"
- **Scripting**: Automated test suite validating that functions execute correctly; autonomous security scanner continuously checking syscalls

## Required Operating Rules

0. Keep analysis program-agnostic.
- Do not assume target-specific commands, prompts, symbol names, offsets, or exploit paths.
- Infer interaction flow from observed `stdout`/`stderr`, then adapt inputs accordingly.
- Use `syms`/`maps`/`regs`/`bt` from the current session as the source of truth.

1. Never guess runtime addresses.
- Always call `syms` in the current session and use `symbols[].loaded_address` for `bp_add`.

2. Do not choose the runtime binary.
- Runtime selection is environment-controlled by the MCP server launcher.
- Do not ask the model to choose or override the qemu-user binary.

3. Always close the run/input/output loop.
- After each `advance` with `mode="continue"`, call `stdout`, `stderr`, and usually `state`.
- After each `send_line`, `send_bytes`, or `send_file`, call `advance {"mode":"continue"}` again, then poll `stdout`/`stderr`.

4. Treat elapsed run windows as non-fatal.
- An `advance` result with `reason=window_elapsed` is not a failure.
- Mandatory sequence after `window_elapsed`: `stdout` -> `stderr` -> `state`.
- Do not close/restart solely because the advance window elapsed.

5. Use the correct stdin tool.
- `send_line` for menu/prompt interactions.
- `send_bytes` for exact text/byte payloads.
- `send_file` for large payloads.

6. Prefer targeted breakpoint workflows for complex interactive binaries.
- Avoid long free-form interaction when trying to confirm a specific bug.
- Set breakpoints on likely handlers/parsers first, then drive minimal input to hit them.
- Use `regs`/`disasm`/`mem` at breakpoints to verify conditions and memory effects.
- Use static analysis to identify candidate functions/conditions, then validate dynamically.

## Canonical Session Sequence

1. `start` with absolute `target` (and optional `args`, `cwd`, `qemu_config`).
2. `state` to confirm launch.
3. `syms` (optional `name_filter`) and collect `loaded_address` values.
4. `bp_clear` then `bp_add` if breakpoints are needed.
5. `advance {"mode":"continue"}`.
6. `stdout` + `stderr`.
7. `send_line` / `send_bytes` / `send_file` as needed.
8. Repeat `advance {"mode":"continue"}` -> `stdout` -> `stderr` -> `state`.
9. Use `regs`, `bt`, `disasm`, `mem`, `maps`, and `advance` for motion/inspection.
10. Do not assume argv, stack buffers, heap buffers, or derived parser buffers become symbolic automatically. Use `symbolize_mem` or `symbolize_reg` explicitly for those.
11. For stdin-driven input, prefer the built-in queued stdin flow. `send_line`, `send_bytes`, and `send_file` accept `symbolic: true`. When the runtime supports `queue_stdin_chunk`, each stdin write is recorded as an ordered concrete or symbolic chunk, and the guest buffer becomes symbolic automatically when stdin syscalls consume those bytes.
12. Mixed stdin is supported. You can send concrete menu choices first, then a symbolic payload, then more concrete input. Keep the send order exact because the runtime preserves that byte-stream order.
13. Immediately verify the result with `mem` or `regs` after execution reaches a point where the guest has consumed the stdin bytes. Expect symbolic metadata in `mem.result.symbolic_bytes` or `regs.result.symbolic_registers`.
14. After finding a non-zero symbolic label in `regs` or `mem`, use `expr` to inspect the symbolic expression for that label.
15. Use the older manual breakpoint-plus-`symbolize_mem` workflow only when the data source is not stdin, or when you need to symbolize a later derived buffer rather than the original stdin stream.
16. After symbolic input has actually influenced control flow, call `recent_path_constraints` to discover the newest path-condition labels. Good trigger points are: after a breakpoint at an interesting branch target, after `advance {"mode":"continue"}` stops somewhere beyond a comparison or branch, or during a terminal pause on exit/crash. Do not query path constraints before the symbolic bytes have been consumed and exercised.
17. Once you have a recent label, call `path_constraint_closure(label)` to recover the earlier constraints that the newest condition depends on.
18. For tracing, use `trace_start` -> exercise target -> `trace_get` -> `trace_status` -> `trace_stop`.
19. `close` at end.

Concrete stdin pattern:
1. `start` the target.
2. `send_line {"line":"1"}` for concrete menu input, or `send_line {"line":"AAAA", "symbolic": true}` / `send_bytes {"data":"AAAA", "symbolic": true}` for symbolic stdin.
3. `advance {"mode":"continue"}` until the program reaches the point where it has consumed that input.
4. `stdout`, `stderr`, `state`, `regs`, or `mem` to confirm how the input affected execution and whether symbolic labels appeared.
5. `expr {"label":"<first_nonzero_label>"}` if you need the expression for one symbolic byte or word.
6. `advance {"mode":"continue"}` to keep running.

Concrete path-constraint pattern:
1. Send symbolic stdin with `send_line {"line":"AAAA", "symbolic": true}` or `send_bytes {"data":"AAAA", "symbolic": true}`.
2. `advance {"mode":"continue"}` until the target has consumed that input and reached an interesting branch, breakpoint, or terminal pause.
3. Optionally confirm symbolic influence first with `mem`, `regs`, or `expr`.
4. Call `recent_path_constraints {"limit": 5}`. If it returns no constraints, keep running; the symbolic input has not influenced control flow yet.
5. Pick the newest label from `constraints[0].label`.
6. Call `path_constraint_closure {"label":"<newest_label>"}` to recover the earlier constraints that explain why that branch was taken.
7. Use this after each interesting stop, especially after branch-target breakpoints and exit/crash terminal pauses.

Trace file mode:
- If live event streaming is unstable, set `start.qemu_config.instrumentation_trace_file_path` and use file-backed tracing via the same `trace_*` tools.
- The runtime receives this path as `IA_TRACE_FILE`.

## Tool Choice Guide

- `start`: begin a session; requires non-empty string `target`.
- `advance`: motion control with `continue`, `insn`, `bb`, or `return` modes; all modes may stop early on input, breakpoints, or exit.
- `pause`: force pause while running.
- `syms`: resolve runtime addresses for this session only.
- `bp_add` / `bp_del` / `bp_clear` / `bp_list`: breakpoint management.
- `stdout` / `stderr`: incremental stream reads (cursor maintained by server).
- `send_line`: appends newline automatically; add `symbolic: true` when you want that stdin line queued as symbolic.
- `send_bytes`: use `data` (text) or `data_hex` (raw bytes), not both; add `symbolic: true` for symbolic stdin bytes.
- `send_file`: stream bytes from local file to stdin; add `symbolic: true` when the streamed bytes should become symbolic on stdin consumption.
- `regs` / `bt` / `disasm` / `mem` / `maps`: low-level state inspection.
- `regs` also carries symbolic register labels in `result.symbolic_registers` when supported.
- `mem` also carries symbolic byte labels in `result.symbolic_bytes` when supported.
- `expr`: render the symbolic expression for one concrete symbolic label, typically after discovering that label through `regs` or `mem`.
- `recent_path_constraints` / `path_constraint_closure`: scripting-side helpers for recent path-condition discovery and nested constraint closure lookup.
- `symbolize_mem` / `symbolize_reg`: inject symbolic state into paused memory/registers. These are explicit actions; dynamiq does not symbolize newly received input for you.
- `bt`: best-effort stack backtrace; use after breakpoints to quickly map call chains.
- `trace_start` / `trace_stop` / `trace_status` / `trace_get`: trace tracing workflow and retrieval.
- `qemu_config.instrumentation_trace_file_path`: optional trace spool file for deferred/offline trace retrieval.
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
- For each case, keep the same loop: `advance {"mode":"continue"}` -> `stdout` -> `stderr` -> `state`.

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
- For stdin-controlled input, prefer `send_line` / `send_bytes` / `send_file` with `symbolic: true` instead of manual post-`read` buffer symbolization. Fall back to `symbolize_mem` only for non-stdin sources or derived buffers.
- For symbolic reasoning, discover labels through `regs` or `mem` first, then call `expr` on the specific non-zero label you want to inspect.
- For path-constraint reasoning, do not query immediately after sending symbolic input. First let execution advance until the symbolic bytes have been consumed and a branch or terminal condition has been reached. Then call `recent_path_constraints()`/`recent_path_constraints {"limit": ...}` and use the newest returned label with `path_constraint_closure(label)`.
- A good default is: symbolic stdin -> `advance` -> `recent_path_constraints` -> `path_constraint_closure`.
- For call-chain context, call `bt` after a breakpoint hit before deeper `disasm`/`mem`.
- Do not reuse addresses from previous sessions.
- If tool output indicates malformed arguments, fix input shape before retrying.

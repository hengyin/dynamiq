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
10. Do not assume stdin, argv, stack buffers, or heap buffers become symbolic automatically. They are concrete unless you explicitly symbolize them.
11. To symbolize an input buffer, first stop at a point where the target has already copied or parsed the input into a concrete memory region, then locate that region with `regs`, `bt`, `mem`, `maps`, or breakpoints on parser/handler code.
12. For `read` / `fgets` / similar stdin-oriented input routines, first send input with `send_line`, `send_bytes`, or `send_file`, then use breakpoints and `advance` so you pause after the function returns, when the destination buffer has been filled.
13. Once the buffer address and size are known, call `symbolize_mem {"address":"...", "size":N, "name":"..."}` while paused. Use `symbolize_reg` only when the symbolic source should be a register value rather than memory.
14. Immediately verify the result with `mem` or `regs`. Expect symbolic metadata in `mem.result.symbolic_bytes` or `regs.result.symbolic_registers`. If those labels are still zero/concrete, you symbolized the wrong location or did it at the wrong time.
15. After finding a non-zero symbolic label in `regs` or `mem`, use `expr` to inspect the symbolic expression for that label.
16. For path-constraint reasoning in the scripting API, first call `recent_path_constraints(limit=...)`, then `path_constraint_closure(label)` for the label you want to explain.
17. For tracing, use `trace_start` -> exercise target -> `trace_get` -> `trace_status` -> `trace_stop`.
18. `close` at end.

Concrete `read` pattern:
1. `syms {"name_filter":"read"}` and pick the current session's `loaded_address`.
2. `bp_add {"address":"<read_loaded_address>"}`.
3. `send_line {"line":"AAAA"}` or `send_bytes` / `send_file` to queue stdin input for the target.
4. `advance {"mode":"continue"}` until the breakpoint hits `read`.
5. `regs {"names":["rsi","rdx"]}` on x86_64 SysV to capture `buf` and `count` at function entry.
6. `advance {"mode":"return"}` so execution pauses after `read` returns and the destination buffer is filled from stdin.
7. `symbolize_mem {"address":"<buf>", "size":<count>, "name":"stdin_buf"}` while paused.
8. `mem {"address":"<buf>", "size":8}` to verify non-zero symbolic labels in `result.symbolic_bytes`.
9. `expr {"label":"<first_nonzero_label>"}` if you need the expression for one byte/word.
10. `advance {"mode":"continue"}` to keep running with that symbolic buffer.

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
- `send_line`: appends newline automatically.
- `send_bytes`: use `data` (text) or `data_hex` (raw bytes), not both.
- `send_file`: stream bytes from local file to stdin.
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
- For user-controlled input, first send the stdin payload, then identify where the bytes live after the program reads them. For `read`-style functions, this usually means breaking on `read`, capturing `buf`/`count` at entry, pausing right after return, then symbolizing the now-populated destination buffer with `symbolize_mem`.
- For symbolic reasoning, discover labels through `regs` or `mem` first, then call `expr` on the specific non-zero label you want to inspect.
- For path-condition reasoning in scripting, use `recent_path_constraints()` to choose a label, then `path_constraint_closure(label)` to see the earlier constraints it depends on.
- For call-chain context, call `bt` after a breakpoint hit before deeper `disasm`/`mem`.
- Do not reuse addresses from previous sessions.
- If tool output indicates malformed arguments, fix input shape before retrying.

# Interactive Dynamic Analysis

Instrumented `qemu-user` runtime for interactive userspace binary analysis.

This repository currently contains:

- normalized runtime models
- backend interfaces
- a session scaffold
- design notes in `design.md`
- project planning in `docs/project_plan.md`
- a live backend contract in `docs/live_backend_contract.md`
- example target/instrumentation skeletons in `examples/`

## Tests

Run the default test suite with:

```bash
PYTHONPATH=src .venv/bin/pytest -q
```

Live integration tests are opt-in and require a running backend plus instrumentation endpoints.

Set:

- `RUN_LIVE_QEMU=1`
- `IA_LIVE_EVENT_SOCKET`
- `IA_LIVE_RPC_SOCKET`
- `IA_LIVE_TARGET`

Optional:

- `IA_LIVE_QMP_SOCKET`
- `IA_LIVE_ARGS`
- `IA_LIVE_CWD`
- `IA_LIVE_LAUNCH=1`
- `IA_LIVE_QEMU_USER_PATH`
- `IA_LIVE_QEMU_ARGS`

Then run:

```bash
PYTHONPATH=src .venv/bin/pytest -q -m live_qemu
```

`IA_LIVE_LAUNCH=1` tells the backend to launch `qemu-user` itself using the runtime launch contract. If unset, the live test assumes the backend endpoints already exist.

## Live Backend Contract

See [docs/live_backend_contract.md](docs/live_backend_contract.md) for the minimum event/RPC contract expected by the runtime.

Example artifacts:

- [examples/sample_target.c](examples/sample_target.c)
- [examples/instrumentation_sidecar.py](examples/instrumentation_sidecar.py)
- [examples/demo_live_session.py](examples/demo_live_session.py)
- [examples/demo_qemu_rpc_m1.py](examples/demo_qemu_rpc_m1.py)

## Demo

If `qemu-x86_64` and `gcc` are installed, you can run the end-to-end example with:

```bash
PYTHONPATH=src python examples/demo_live_session.py
```

This will:

1. compile `examples/sample_target.c`
2. start `examples/instrumentation_sidecar.py`
3. launch the target through the runtime using `qemu-user`
4. execute a short analysis session

For the current real-QEMU M1 slice, where only the RPC channel is implemented in QEMU, use:

```bash
PYTHONPATH=src python examples/demo_qemu_rpc_m1.py
```

This path expects your locally built QEMU binary at `/home/heng/git/qemu/build-ia/qemu-x86_64` and exercises:

1. `query_status`
2. `get_registers`
3. `advance_basic_blocks(1)`
4. `disassemble(...)` from the live runtime `rip`
5. `run_until_address(...)` against a future instruction address from that disassembly
6. `read_memory`

## MCP Server (stdio)

This repository provides a minimal MCP server for external coding platforms (for example Claude Code/OpenCode style integrations).

Start it with:

```bash
PYTHONPATH=src .venv/bin/python -m interactive_analysis.mcp_server
```

Supported MCP methods:

- `initialize`
- `tools/list`
- `tools/call`

Current tools exposed:

- `session_start`
- `session_close`
- `capabilities`
- `get_state`
- `resume`
- `pause`
- `get_registers`
- `disassemble`
- `read_memory`
- `list_memory_maps`
- `run_until_address`
- `step`
- `advance_basic_blocks`
- `write_stdin`
- `close_stdin`
- `read_stdout`
- `read_stderr`

### MCP quickstart for interactive stdin/stdout

Use this order for interactive programs:

1. `session_start`
2. `resume`
3. one or more `write_stdin`
4. `close_stdin` (if program expects EOF)
5. poll `read_stdout` and `read_stderr`

Example `tools/call` arguments:

- `session_start`
```json
{
  "target": "/home/heng/work2/KPRCA_00021",
  "cwd": "/home/heng/work2"
}
```

- `resume`
```json
{
  "timeout": 5.0
}
```

- `write_stdin` (required `data`)
```json
{
  "data": "1\n"
}
```

- `close_stdin`
```json
{}
```

- `read_stdout` / `read_stderr`
```json
{
  "cursor": 0,
  "max_chars": 4096
}
```

`read_stdout` and `read_stderr` return `data`, `cursor`, and `eof`. Reuse returned `cursor` for the next poll.

### MCP troubleshooting

- `write_stdin` appears stuck:
  Call includes no `data`. Always send `{"data":"...\\n"}`.
- Session is `idle` and target is not running:
  Use `session_start` (MCP now defaults to launch mode), then `resume`.
- Large multiline payloads fail in tool UI:
  Send escaped newlines or split into multiple `write_stdin` calls.

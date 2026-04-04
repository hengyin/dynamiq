---
name: dynamiq-scripting
description: Use when implementing autonomous program analysis, testing, or security scanning workflows. For persistent session control with Python, including stepping, breakpoints, memory inspection, and event tracing—without JSON-RPC round-trips.
---

# Dynamiq Scripting API Skill

Use this skill when building autonomous systems that need to control and analyze target programs programmatically. This is the Python scripting interface (not MCP).

Examples below assume one of these setups:
- dynamiq is installed into the active Python environment, or
- you are running from the repo root with `PYTHONPATH=src`

Repo-local example runner:
```bash
cd /home/heng/git/dynamiq
PYTHONPATH=src .venv/bin/python your_script.py
```

## When to Use Scripting API

The **Scripting API** (`ScriptSession` class) is designed for:
- **Autonomous testing**: Deterministic test suites with checkpoints and assertions
- **Security scanning**: Continuous analysis with breakpoints, memory watches, syscall tracing
- **CI/CD pipelines**: Automated validation of binary behavior before deployment
- **Complex workflows**: Multi-step analysis where session state must persist between operations

**Avoid scripting if:** You need interactive exploration with an LLM (use MCP instead).

## Quick Start

```python
from dynamiq.script_api import ScriptSession

# Simplest usage - QEMU auto-configured
with ScriptSession(target="/path/to/binary", args=["arg1"]) as session:
    session.step(5)                           # Step 5 instructions
    regs = session.get_registers(["rax"])    # Read registers
    session.bp_add("0x401000")                # Add breakpoint
    session.bp_run(timeout=2.0)               # Execute until breakpoint
    trace = session.trace_get(limit=100)      # Get execution trace
```

## Core Concepts

### 1. Session Lifecycle (context manager)
```python
# Automatic cleanup
with ScriptSession(target="/bin/ls", auto_start=True) as session:
    # Session started; ready for commands
    session.step(10)
    # Session auto-closes on exit
```

### 2. All 31 AnalysisSession Methods Available
- **Lifecycle**: `start()`, `close()`, `capabilities()`
- **Execution**: `step()`, `run()`, `pause()`, `advance_basic_blocks()`, `run_until_address()`
- **Breakpoints**: `bp_add()`, `bp_del()`, `bp_list()`, `bp_clear()`, `bp_run()`
- **Inspection**: `get_registers()`, `read_memory()`, `backtrace()`, `disassemble()`, `symbols()`, `list_memory_maps()`, `get_state()`
- **I/O**: `write_stdin()`, `read_stdout()`, `read_stderr()`
- **Tracing**: `trace_start()`, `trace_stop()`, `trace_status()`, `trace_get()`, `get_recent_events()`
- **Snapshots**: `take_snapshot()`, `restore_snapshot()`, `diff_snapshots()`
- **Annotations**: `annotate()`, `list_annotations()`

### 3. Symbolic Execution Support

The scripting API now exposes symbolic-execution helpers through `AnalysisSession`:
- `symbolize_memory(address, size, name=None)`
- `symbolize_register(register, name=None)`
- `get_symbolic_expression(label)`
- `recent_path_constraints(limit=16)`
- `path_constraint_closure(label)`

Important:
- Dynamiq does not symbolize stdin, argv, stack buffers, or heap buffers automatically.
- Input is concrete by default until you explicitly call `symbolize_memory(...)` or `symbolize_register(...)`.
- For `read` / `fgets`-style input, first send or arrange stdin data, then use breakpoints and execution control so you pause after the function returns and the destination buffer is already populated. Then symbolize that concrete buffer before continuing.

Typical symbolic workflow:
```python
with ScriptSession(target="/path/to/target", auto_start=True) as session:
    read_syms = session.symbols(name_filter="read")
    read_addr = read_syms["result"]["symbols"][0]["loaded_address"]
    session.bp_add(read_addr)
    session.write_stdin("AAAA\n")
    session.bp_run(timeout=2.0)

    regs = session.get_registers(["rsi", "rdx"])
    buf = regs["result"]["registers"]["rsi"]
    size = int(regs["result"]["registers"]["rdx"], 16)

    session.advance(mode="return", timeout=2.0)
    session.symbolize_memory(buf, size, name="input_buf")
    mem = session.read_memory(buf, min(size, 16))
    label = mem["result"]["symbolic_bytes"][0]["label"]

    expr = session.get_symbolic_expression(label)
    recent = session.recent_path_constraints(limit=8)
    closure = session.path_constraint_closure(recent["result"]["constraints"][0]["label"])
```

### 4. Auto-Detection (Zero Configuration)
```python
# QEMU binary path auto-detected from target architecture
# RPC socket auto-created in temp directory
# Everything just works
with ScriptSession(target="/bin/ls") as session:
    pass
```

## Helper Utilities

Import from `dynamiq.script_helpers`:

### Convenience Functions
```python
from dynamiq.script_helpers import (
    run_until_event,
    run_until_instruction,
    collect_trace_between_addresses,
    inspect_function_with_trace,
)

# Run until syscall event
event = run_until_event(session, ["syscall"], timeout=2.0)

# Run until instruction mnemonic
if run_until_instruction(session, "call"):
    print("Found call instruction")

# Trace execution between two addresses
trace = collect_trace_between_addresses(session, "0x401000", "0x401100")
```

### Context Managers
```python
from dynamiq.script_helpers import (
    breakpoint_group,
    trace_region_context,
    MemoryWatch,
)

# Temporary breakpoint group
with breakpoint_group(session, ["0x401000", "0x401100"]):
    session.bp_run(timeout=10.0)

# Trace specific region
with trace_region_context(session, "0x401000", "0x402000"):
    session.run(timeout=5.0)

# Watch memory for changes
watch = MemoryWatch(session, "0x404000", 32)
watch.check()  # Returns True if memory changed
```

### Assertions for Testing
```python
from dynamiq.script_helpers import (
    assert_memory_pattern,
    assert_register_value,
    checkpoint_restore_test,
)

# Validate memory
assert_memory_pattern(session, "0x401000", b"\x55\x48\x89", "function prologue")

# Validate registers
assert_register_value(session, "rax", "0x42", "return value")

# Repeatable testing via checkpoint/restore
def test_scenario(s):
    s.step(10)
    return s.get_registers(["rax"])

results = checkpoint_restore_test(session, test_scenario, num_iterations=3)
```

## Common Workflows

### Workflow 1: Breakpoint-Driven Analysis
```python
with ScriptSession(target="/bin/ls", auto_start=True) as session:
    # Find main
    symbols = session.symbols(name_filter="main")
    main_addr = symbols["result"]["symbols"][0]["loaded_address"]
    
    # Run to main
    session.bp_add(main_addr)
    session.bp_run(timeout=2.0)
    
    # Inspect at main
    regs = session.get_registers(["rsp", "rip"])
    print(f"At main: RIP={regs['result']['registers']['rip']}")
```

### Workflow 2: Trace Syscalls
```python
with ScriptSession(target="/bin/ls", auto_start=True) as session:
    session.trace_start(event_types=["syscall"])
    
    for _ in range(100):
        session.step(count=10, timeout=1.0)
    
    trace = session.trace_get(limit=1000)
    for event in trace["result"]["trace"]:
        print(f"Syscall: {event.get('name')}")
```

### Workflow 3: Automated Testing
```python
def test_function():
    with ScriptSession(target="/bin/myapp", auto_start=True) as session:
        # Set breakpoint at function
        session.bp_add("0x401234")
        session.bp_run(timeout=2.0)
        
        # Verify state at breakpoint
        state = session.get_state()
        assert state["state"]["session_status"] == "paused"
        
        # Read memory, inspect registers
        memory = session.read_memory("0x404000", 32)
        assert memory["result"]["bytes"] == "deadbeef..."
        
        # Verify function was called
        return True
```

### Workflow 4: Memory Watching
```python
from dynamiq.script_helpers import MemoryWatch

def on_change(addr, old, new):
    print(f"Memory changed at {addr}: {old.hex()} → {new.hex()}")

with ScriptSession(target="/bin/ls", auto_start=True) as session:
    watch = MemoryWatch(session, "0x404000", 8, on_change=on_change)
    
    with watch:
        while not watch.check():
            session.step(count=1, timeout=1.0)
            # Check triggers on_change callback if memory changed
```

### Workflow 5: Break on `read`, Send Stdin, Wait for Return, Then Symbolize
```python
with ScriptSession(target="/bin/myapp", auto_start=True) as session:
    read_syms = session.symbols(name_filter="read")
    read_addr = read_syms["result"]["symbols"][0]["loaded_address"]

    # Break when read() is entered.
    session.bp_add(read_addr)

    # Queue stdin data, then run until read() is hit.
    session.write_stdin("AAAA\n")
    session.bp_run(timeout=2.0)

    # On x86_64 SysV, read(fd, buf, count) uses:
    #   rdi = fd, rsi = buf, rdx = count
    entry_regs = session.get_registers(["rsi", "rdx"])
    buf = entry_regs["result"]["registers"]["rsi"]
    size = int(entry_regs["result"]["registers"]["rdx"], 16)

    # Wait until read() returns so the destination buffer is populated.
    session.advance(mode="return", timeout=2.0)

    # Now symbolize the concrete buffer that read() just filled.
    session.symbolize_memory(buf, size, name="stdin_buf")
    mem = session.read_memory(buf, min(size, 8))
    first_label = mem["result"]["symbolic_bytes"][0]["label"]
    expr = session.get_symbolic_expression(first_label)

    print(expr["result"]["expression"])
    session.run(timeout=2.0)
```

## Required Operating Rules

1. **Always use context manager for cleanup**
   ```python
   with ScriptSession(target=...) as session:
       # Session will be properly closed even if exception occurs
   ```

2. **Check session status before operations**
   ```python
   if session.is_paused:
       regs = session.get_registers()
   ```

3. **Use helper functions for complex patterns**
   - Don't manually loop checking PC; use `run_until_event()`, `run_until_instruction()`
   - Don't manually manage breakpoint sets; use `breakpoint_group()`
   - Don't manually track checkpoints; use `checkpoint_restore_test()`

4. **Understand instruction vs. basic block stepping**
   ```python
   session.step(count=5)                    # Step 5 instructions
   session.advance_basic_blocks(count=3)    # Advance 3 basic blocks
   ```

5. **Use assertions for test validation**
   ```python
   assert_register_value(session, "rax", "0x42")  # Fails loudly if mismatch
   assert_memory_pattern(session, "0x401000", b"...")
   ```

6. **Override only what you need**
   ```python
   # Default QEMU auto-detection works; override only if needed
   with ScriptSession(
       target="/bin/ls",
       qemu_config={"qemu_user_path": "/custom/qemu-x86_64"}  # Override only QEMU path
   ) as session:
       pass
   ```

7. **Treat symbolic state injection as explicit**
   ```python
   # Wrong assumption: input becomes symbolic automatically
   # Correct: stop after the program has written the concrete bytes,
   # then symbolize the specific buffer or register you want to track.
   session.symbolize_memory(buf, size, name="input_buf")
   ```

8. **Verify symbolic state immediately**
   ```python
   mem = session.read_memory(buf, 8)
   assert mem["result"]["symbolic_bytes"][0]["symbolic"] is True
   label = mem["result"]["symbolic_bytes"][0]["label"]
   expr = session.get_symbolic_expression(label)
   ```

## Error Handling

Errors are Python exceptions (not JSON), making debugging easier:

```python
from dynamiq.errors import InvalidStateError

try:
    session.read_memory("0x401000", 1000000)  # Size too large
except InvalidStateError as e:
    print(f"Error: {e}")
    # Handle gracefully in autonomous context
```

## Integration with Autonomous Systems

The Scripting API is designed for **non-interactive automation**:

- **No human intervention needed**: QEMU auto-detected, sockets auto-created
- **Deterministic execution**: Checkpoint/restore for repeatable test scenarios
- **Full state access**: Get complete ExecutionState dict, not just formatted JSON
- **Long-running safe**: Context managers and assertions prevent resource leaks

Example autonomous security scanner:

```python
def scan_binary(binary_path):
    issues = []
    
    with ScriptSession(target=binary_path, auto_start=True) as session:
        # Find all syscalls
        session.trace_start(event_types=["syscall"])
        for _ in range(1000):
            session.step(count=10, timeout=1.0)
        
        trace = session.trace_get(limit=10000)
        
        # Detect dangerous syscalls
        dangerous = ["execve", "system", "setuid"]
        for event in trace["result"]["trace"]:
            if event.get("name") in dangerous:
                issues.append(f"Dangerous syscall: {event['name']}")
        
        # Check for stack buffer overflows
        # ... more analysis ...
    
    return issues
```

## Comparison: MCP vs Scripting API

| Operation | MCP | Scripting |
|-----------|-----|----------|
| One line of Python to step 5x | ❌ Multiple JSON-RPC calls | ✅ `session.step(5)` |
| Maintain session state | ❌ Manual in LLM | ✅ Automatic |
| Set 3 breakpoints | ❌ 3 separate tool calls | ✅ `session.bp_add()` × 3 (auto-batched) |
| Checkpoint/restore | ❌ Manual snapshots | ✅ `checkpoint_restore_test()` |
| Error handling | ❌ JSON errors | ✅ Python exceptions |
| Real-time feedback | ✅ Interactive with human | ❌ Not interactive |
| Setup overhead | ✅ None (MCP server) | ❌ Python environment needed |

## Examples

See `examples/` directory:
- `script_basic_control.py` — Basic session start/step/inspect operations
- `script_automated_testing.py` — Test harness with assertions and checkpoint/restore
- `script_security_analysis.py` — Syscall tracing, memory analysis, function detection

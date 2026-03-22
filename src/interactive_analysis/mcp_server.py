from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .backends.qemu_user_instrumented import QemuUserInstrumentedBackend
from .errors import InvalidStateError
from .session import AnalysisSession


JSON = dict[str, Any]

MCP_PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "ida"
SERVER_VERSION = "0.1.0"


@dataclass(slots=True)
class ToolSpec:
    name: str
    description: str
    input_schema: JSON

    def to_mcp(self) -> JSON:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }


class InteractiveAnalysisMcpServer:
    def __init__(self, session_factory: Callable[[], AnalysisSession] | None = None) -> None:
        self._session_factory = session_factory or (lambda: AnalysisSession(backend=QemuUserInstrumentedBackend()))
        self._session: AnalysisSession | None = None
        self._tools: dict[str, ToolSpec] = {tool.name: tool for tool in self._build_tools()}

    def handle_request(self, request: JSON) -> JSON | None:
        method = request.get("method")
        request_id = request.get("id")
        params = request.get("params")
        params_dict = params if isinstance(params, dict) else {}

        if not isinstance(method, str):
            if request_id is None:
                return None
            return self._error(request_id, -32600, "invalid request: method must be a string")

        if method == "initialize":
            if request_id is None:
                return None
            return self._ok(
                request_id,
                {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                    "capabilities": {"tools": {}},
                },
            )

        if method == "notifications/initialized":
            return None

        if method == "tools/list":
            if request_id is None:
                return None
            return self._ok(request_id, {"tools": [tool.to_mcp() for tool in self._tools.values()]})

        if method == "tools/call":
            if request_id is None:
                return None
            name = params_dict.get("name")
            arguments = params_dict.get("arguments")
            if not isinstance(name, str):
                return self._error(request_id, -32602, "tools/call: missing tool name")
            if arguments is None:
                arguments_dict: JSON = {}
            elif isinstance(arguments, dict):
                arguments_dict = arguments
            else:
                return self._error(request_id, -32602, "tools/call: arguments must be an object")
            return self._ok(request_id, self._call_tool(name, arguments_dict))

        if method == "ping":
            if request_id is None:
                return None
            return self._ok(request_id, {})

        if request_id is None:
            return None
        return self._error(request_id, -32601, f"method not found: {method}")

    def _ensure_session(self) -> AnalysisSession:
        if self._session is None:
            self._session = self._session_factory()
        return self._session

    def _call_tool(self, name: str, arguments: JSON) -> JSON:
        if name not in self._tools:
            return self._tool_error(f"unknown tool: {name}")

        try:
            if name == "start":
                session = self._ensure_session()
                qemu_config = dict(arguments.get("qemu_config") or {})
                qemu_config.setdefault("launch", True)
                target = str(arguments["target"])
                args = [str(item) for item in arguments.get("args", [])]
                cwd = str(arguments["cwd"]) if "cwd" in arguments and arguments["cwd"] is not None else None
                try:
                    result = session.start(
                        target=target,
                        args=args,
                        cwd=cwd,
                        qemu_config=qemu_config,
                    )
                except InvalidStateError as exc:
                    if "session already started" not in str(exc):
                        raise
                    session.close()
                    result = session.start(
                        target=target,
                        args=args,
                        cwd=cwd,
                        qemu_config=qemu_config,
                    )
                return self._tool_ok(result)

            if name == "close":
                session = self._ensure_session()
                result = session.close()
                return self._tool_ok(result)

            if name == "caps":
                return self._tool_ok(self._ensure_session().capabilities())
            if name == "state":
                return self._tool_ok(self._ensure_session().get_state())
            if name == "syms":
                return self._tool_ok(
                    self._ensure_session().symbols(
                        max_count=int(arguments.get("max_count", 500)),
                        name_filter=str(arguments["name_filter"]) if "name_filter" in arguments and arguments["name_filter"] is not None else None,
                    )
                )
            if name == "run":
                return self._tool_ok(self._ensure_session().resume(timeout=float(arguments.get("timeout", 5.0))))
            if name == "pause":
                return self._tool_ok(self._ensure_session().pause(timeout=float(arguments.get("timeout", 5.0))))
            if name == "regs":
                names = arguments.get("names")
                if names is not None and not isinstance(names, list):
                    return self._tool_error("get_registers.names must be an array of strings")
                return self._tool_ok(self._ensure_session().get_registers(names))
            if name == "disasm":
                return self._tool_ok(
                    self._ensure_session().disassemble(
                        address=str(arguments["address"]),
                        count=int(arguments.get("count", 16)),
                    )
                )
            if name == "mem":
                return self._tool_ok(
                    self._ensure_session().read_memory(
                        address=str(arguments["address"]),
                        size=int(arguments["size"]),
                    )
                )
            if name == "maps":
                return self._tool_ok(self._ensure_session().list_memory_maps())
            if name == "until":
                return self._tool_ok(
                    self._ensure_session().run_until_address(
                        address=str(arguments["address"]),
                        timeout=float(arguments.get("timeout", 5.0)),
                    )
                )
            if name == "step":
                return self._tool_ok(
                    self._ensure_session().step(
                        count=int(arguments.get("count", 1)),
                        timeout=float(arguments.get("timeout", 5.0)),
                    )
                )
            if name == "bb":
                return self._tool_ok(
                    self._ensure_session().advance_basic_blocks(
                        count=int(arguments.get("count", 1)),
                        timeout=float(arguments.get("timeout", 5.0)),
                    )
                )
            if name == "bp_add":
                return self._tool_ok(self._ensure_session().bp_add(address=str(arguments["address"])))
            if name == "bp_del":
                return self._tool_ok(self._ensure_session().bp_del(address=str(arguments["address"])))
            if name == "bp_list":
                return self._tool_ok(self._ensure_session().bp_list())
            if name == "bp_clear":
                return self._tool_ok(self._ensure_session().bp_clear())
            if name == "bp_run":
                return self._tool_ok(
                    self._ensure_session().bp_run(
                        timeout=float(arguments.get("timeout", 5.0)),
                        max_steps=int(arguments.get("max_steps", 10000)),
                    )
                )
            if name == "stdin":
                data = arguments.get("data")
                if not isinstance(data, str) or data == "":
                    return self._tool_error(
                        "write_stdin requires non-empty string argument `data` "
                        '(example: {"data":"1\\n"})'
                    )
                return self._tool_ok(self._ensure_session().write_stdin(data=data))
            if name == "stdin_file":
                path_value = arguments.get("path")
                if not isinstance(path_value, str) or path_value.strip() == "":
                    return self._tool_error(
                        "write_stdin_file requires non-empty string argument `path` "
                        '(example: {"path":"/tmp/pov_input.txt"})'
                    )
                chunk_size = int(arguments.get("chunk_size", 4096))
                if chunk_size < 1:
                    return self._tool_error("write_stdin_file.chunk_size must be >= 1")
                path = Path(path_value)
                if not path.exists() or not path.is_file():
                    return self._tool_error(f"write_stdin_file path is not a readable file: {path_value}")
                total_written = 0
                session = self._ensure_session()
                with path.open("r", encoding="utf-8", errors="replace") as fp:
                    while True:
                        chunk = fp.read(chunk_size)
                        if not chunk:
                            break
                        write_result = session.write_stdin(data=chunk)
                        total_written += int(write_result["result"].get("written", 0))
                return self._tool_ok({"written": total_written, "path": str(path), "chunk_size": chunk_size})
            if name == "stdin_close":
                return self._tool_ok(self._ensure_session().close_stdin())
            if name == "stdout":
                return self._tool_ok(
                    self._ensure_session().read_stdout(
                        cursor=int(arguments.get("cursor", 0)),
                        max_chars=int(arguments.get("max_chars", 4096)),
                    )
                )
            if name == "stderr":
                return self._tool_ok(
                    self._ensure_session().read_stderr(
                        cursor=int(arguments.get("cursor", 0)),
                        max_chars=int(arguments.get("max_chars", 4096)),
                    )
                )
            return self._tool_error(f"tool not implemented: {name}")
        except KeyError as exc:
            return self._tool_error(f"missing required argument: {exc.args[0]}")
        except Exception as exc:  # noqa: BLE001
            return self._tool_error(str(exc))

    def shutdown(self) -> None:
        if self._session is None:
            return
        try:
            self._session.close()
        except Exception:
            pass
        self._session = None

    @staticmethod
    def _tool_ok(payload: JSON) -> JSON:
        text = json.dumps(payload, sort_keys=True)
        return {
            "content": [{"type": "text", "text": text}],
            "structuredContent": payload,
            "isError": False,
        }

    @staticmethod
    def _tool_error(message: str) -> JSON:
        return {
            "content": [{"type": "text", "text": message}],
            "isError": True,
        }

    @staticmethod
    def _ok(request_id: Any, result: JSON) -> JSON:
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    @staticmethod
    def _error(request_id: Any, code: int, message: str) -> JSON:
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}

    @staticmethod
    def _build_tools() -> list[ToolSpec]:
        return [
            ToolSpec(
                name="start",
                description=(
                    "Start an analysis session for a target binary. "
                    "After start, session is typically paused; call resume before write_stdin."
                ),
                input_schema={
                    "type": "object",
                    "description": "Session launch options.",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Absolute path to the guest binary to execute.",
                            "minLength": 1,
                        },
                        "args": {
                            "type": "array",
                            "description": "Command-line arguments passed to the guest binary.",
                            "items": {"type": "string"},
                            "default": [],
                        },
                        "cwd": {
                            "type": ["string", "null"],
                            "description": "Working directory for process launch.",
                            "default": None,
                        },
                        "qemu_config": {
                            "type": "object",
                            "description": (
                                "Optional backend launch settings. "
                                "If omitted, launch defaults to true."
                            ),
                            "properties": {
                                "launch": {
                                    "type": "boolean",
                                    "description": "Whether backend should launch qemu-user.",
                                    "default": True,
                                },
                                "qemu_user_path": {
                                    "type": "string",
                                    "description": "Path to qemu-x86_64 binary.",
                                },
                                "launch_connect_timeout": {
                                    "type": "number",
                                    "exclusiveMinimum": 0,
                                    "description": "Seconds to wait for RPC socket connectivity.",
                                },
                                "instrumentation_rpc_socket_path": {
                                    "type": "string",
                                    "description": "UNIX socket path for instrumentation RPC.",
                                },
                            },
                            "additionalProperties": True,
                            "default": {},
                        },
                    },
                    "required": ["target"],
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="close",
                description="Close the active analysis session.",
                input_schema={"type": "object", "properties": {}, "additionalProperties": False},
            ),
            ToolSpec(
                name="caps",
                description="Return backend capabilities.",
                input_schema={"type": "object", "properties": {}, "additionalProperties": False},
            ),
            ToolSpec(
                name="state",
                description="Return full session state.",
                input_schema={"type": "object", "properties": {}, "additionalProperties": False},
            ),
            ToolSpec(
                name="syms",
                description="List ELF symbols and resolve loaded addresses using current memory maps.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "max_count": {"type": "integer", "minimum": 1, "default": 500},
                        "name_filter": {"type": ["string", "null"]},
                    },
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="run",
                description="Resume target execution (expected state transition: paused -> running).",
                input_schema={
                    "type": "object",
                    "properties": {
                        "timeout": {
                            "type": "number",
                            "exclusiveMinimum": 0,
                            "description": "RPC timeout in seconds.",
                            "default": 5.0,
                        }
                    },
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="pause",
                description="Pause target execution.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "timeout": {
                            "type": "number",
                            "exclusiveMinimum": 0,
                            "description": "RPC timeout in seconds.",
                            "default": 5.0,
                        }
                    },
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="regs",
                description="Read selected registers (or default set).",
                input_schema={
                    "type": "object",
                    "properties": {
                        "names": {
                            "type": "array",
                            "description": "Optional register names to read. If omitted, backend defaults are used.",
                            "items": {"type": "string"},
                        }
                    },
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="disasm",
                description="Disassemble code at a guest address.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "address": {"type": "string", "description": "Guest virtual address (hex string)."},
                        "count": {
                            "type": "integer",
                            "minimum": 1,
                            "description": "Maximum number of instructions to decode.",
                            "default": 16,
                        },
                    },
                    "required": ["address"],
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="mem",
                description="Read guest memory bytes.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "address": {"type": "string", "description": "Guest virtual address (hex string)."},
                        "size": {
                            "type": "integer",
                            "minimum": 0,
                            "description": "Number of bytes to read.",
                        },
                    },
                    "required": ["address", "size"],
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="maps",
                description="List current memory map regions.",
                input_schema={"type": "object", "properties": {}, "additionalProperties": False},
            ),
            ToolSpec(
                name="until",
                description="Resume execution and pause when an address is reached.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "address": {"type": "string", "description": "Guest instruction address to stop at."},
                        "timeout": {
                            "type": "number",
                            "exclusiveMinimum": 0,
                            "description": "Maximum wait in seconds.",
                            "default": 5.0,
                        },
                    },
                    "required": ["address"],
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="step",
                description="Single-step a number of instructions.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "count": {
                            "type": "integer",
                            "minimum": 1,
                            "description": "Instruction count to step.",
                            "default": 1,
                        },
                        "timeout": {
                            "type": "number",
                            "exclusiveMinimum": 0,
                            "description": "Maximum wait in seconds.",
                            "default": 5.0,
                        },
                    },
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="bb",
                description="Advance by a number of basic blocks.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "count": {
                            "type": "integer",
                            "minimum": 1,
                            "description": "Number of basic blocks to execute before pausing.",
                            "default": 1,
                        },
                        "timeout": {
                            "type": "number",
                            "exclusiveMinimum": 0,
                            "description": "Maximum wait in seconds.",
                            "default": 5.0,
                        },
                    },
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="bp_add",
                description="Add a persistent breakpoint address.",
                input_schema={
                    "type": "object",
                    "properties": {"address": {"type": "string", "minLength": 1}},
                    "required": ["address"],
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="bp_del",
                description="Remove a persistent breakpoint address.",
                input_schema={
                    "type": "object",
                    "properties": {"address": {"type": "string", "minLength": 1}},
                    "required": ["address"],
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="bp_list",
                description="List configured persistent breakpoints.",
                input_schema={"type": "object", "properties": {}, "additionalProperties": False},
            ),
            ToolSpec(
                name="bp_clear",
                description="Clear all configured persistent breakpoints.",
                input_schema={"type": "object", "properties": {}, "additionalProperties": False},
            ),
            ToolSpec(
                name="bp_run",
                description="Run until a selected address from configured breakpoints is reached (nearest forward strategy).",
                input_schema={
                    "type": "object",
                    "properties": {
                        "timeout": {"type": "number", "exclusiveMinimum": 0, "default": 5.0},
                        "max_steps": {"type": "integer", "minimum": 0, "default": 10000},
                    },
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="stdin",
                description=(
                    "Write UTF-8 text to target stdin. Session must be running (call resume first). "
                    "Argument `data` is required."
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "data": {
                            "type": "string",
                            "description": (
                                "Input bytes as text. Include '\\n' explicitly for line-oriented programs."
                            ),
                            "minLength": 1,
                        }
                    },
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="stdin_close",
                description="Close target stdin (send EOF).",
                input_schema={"type": "object", "properties": {}, "additionalProperties": False},
            ),
            ToolSpec(
                name="stdin_file",
                description=(
                    "Write stdin from a local UTF-8 text file in chunks. "
                    "Use this for large PoV inputs to avoid inline argument formatting issues."
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Absolute or relative path to input file.",
                            "minLength": 1,
                        },
                        "chunk_size": {
                            "type": "integer",
                            "minimum": 1,
                            "description": "Chunk size per write_stdin call.",
                            "default": 4096,
                        },
                    },
                    "required": ["path"],
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="stdout",
                description="Read buffered stdout chunk. Reuse returned cursor for incremental polling.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "cursor": {
                            "type": "integer",
                            "minimum": 0,
                            "description": "Byte cursor from previous read; start with 0.",
                            "default": 0,
                        },
                        "max_chars": {
                            "type": "integer",
                            "minimum": 1,
                            "description": "Maximum characters to return in this chunk.",
                            "default": 4096,
                        },
                    },
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="stderr",
                description="Read buffered stderr chunk. Reuse returned cursor for incremental polling.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "cursor": {
                            "type": "integer",
                            "minimum": 0,
                            "description": "Byte cursor from previous read; start with 0.",
                            "default": 0,
                        },
                        "max_chars": {
                            "type": "integer",
                            "minimum": 1,
                            "description": "Maximum characters to return in this chunk.",
                            "default": 4096,
                        },
                    },
                    "additionalProperties": False,
                },
            ),
        ]


def run_stdio(server: InteractiveAnalysisMcpServer) -> int:
    try:
        for raw in sys.stdin:
            raw = raw.strip()
            if not raw:
                continue
            try:
                request = json.loads(raw)
            except json.JSONDecodeError:
                response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
            else:
                if not isinstance(request, dict):
                    response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "invalid request"}}
                else:
                    response = server.handle_request(request)
            if response is not None:
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()
    finally:
        server.shutdown()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Interactive Dynamic Analysis MCP server (stdio)")
    parser.add_argument("--transport", choices=["stdio"], default="stdio")
    parser.parse_args()
    server = InteractiveAnalysisMcpServer()
    return run_stdio(server)


if __name__ == "__main__":
    raise SystemExit(main())

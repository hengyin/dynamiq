from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .backends.qemu_user_instrumented import QemuUserInstrumentedBackend
from .session import AnalysisSession


JSON = dict[str, Any]

MCP_PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "interactive-dynamic-analysis"
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
            if name == "session_start":
                session = self._ensure_session()
                result = session.start(
                    target=str(arguments["target"]),
                    args=[str(item) for item in arguments.get("args", [])],
                    cwd=str(arguments["cwd"]) if "cwd" in arguments and arguments["cwd"] is not None else None,
                    qemu_config=dict(arguments.get("qemu_config") or {}),
                )
                return self._tool_ok(result)

            if name == "session_close":
                session = self._ensure_session()
                result = session.close()
                return self._tool_ok(result)

            if name == "capabilities":
                return self._tool_ok(self._ensure_session().capabilities())
            if name == "get_state":
                return self._tool_ok(self._ensure_session().get_state())
            if name == "get_registers":
                names = arguments.get("names")
                if names is not None and not isinstance(names, list):
                    return self._tool_error("get_registers.names must be an array of strings")
                return self._tool_ok(self._ensure_session().get_registers(names))
            if name == "disassemble":
                return self._tool_ok(
                    self._ensure_session().disassemble(
                        address=str(arguments["address"]),
                        count=int(arguments.get("count", 16)),
                    )
                )
            if name == "read_memory":
                return self._tool_ok(
                    self._ensure_session().read_memory(
                        address=str(arguments["address"]),
                        size=int(arguments["size"]),
                    )
                )
            if name == "list_memory_maps":
                return self._tool_ok(self._ensure_session().list_memory_maps())
            if name == "run_until_address":
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
            if name == "advance_basic_blocks":
                return self._tool_ok(
                    self._ensure_session().advance_basic_blocks(
                        count=int(arguments.get("count", 1)),
                        timeout=float(arguments.get("timeout", 5.0)),
                    )
                )
            return self._tool_error(f"tool not implemented: {name}")
        except KeyError as exc:
            return self._tool_error(f"missing required argument: {exc.args[0]}")
        except Exception as exc:  # noqa: BLE001
            return self._tool_error(str(exc))

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
                name="session_start",
                description="Start an analysis session.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string"},
                        "args": {"type": "array", "items": {"type": "string"}},
                        "cwd": {"type": ["string", "null"]},
                        "qemu_config": {"type": "object"},
                    },
                    "required": ["target"],
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="session_close",
                description="Close the active analysis session.",
                input_schema={"type": "object", "properties": {}, "additionalProperties": False},
            ),
            ToolSpec(
                name="capabilities",
                description="Return backend capabilities.",
                input_schema={"type": "object", "properties": {}, "additionalProperties": False},
            ),
            ToolSpec(
                name="get_state",
                description="Return full session state.",
                input_schema={"type": "object", "properties": {}, "additionalProperties": False},
            ),
            ToolSpec(
                name="get_registers",
                description="Read selected registers (or default set).",
                input_schema={
                    "type": "object",
                    "properties": {"names": {"type": "array", "items": {"type": "string"}}},
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="disassemble",
                description="Disassemble code at a guest address.",
                input_schema={
                    "type": "object",
                    "properties": {"address": {"type": "string"}, "count": {"type": "integer", "minimum": 1}},
                    "required": ["address"],
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="read_memory",
                description="Read guest memory bytes.",
                input_schema={
                    "type": "object",
                    "properties": {"address": {"type": "string"}, "size": {"type": "integer", "minimum": 0}},
                    "required": ["address", "size"],
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="list_memory_maps",
                description="List current memory map regions.",
                input_schema={"type": "object", "properties": {}, "additionalProperties": False},
            ),
            ToolSpec(
                name="run_until_address",
                description="Resume execution and pause when an address is reached.",
                input_schema={
                    "type": "object",
                    "properties": {"address": {"type": "string"}, "timeout": {"type": "number", "exclusiveMinimum": 0}},
                    "required": ["address"],
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="step",
                description="Single-step a number of instructions.",
                input_schema={
                    "type": "object",
                    "properties": {"count": {"type": "integer", "minimum": 1}, "timeout": {"type": "number", "exclusiveMinimum": 0}},
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="advance_basic_blocks",
                description="Advance by a number of basic blocks.",
                input_schema={
                    "type": "object",
                    "properties": {"count": {"type": "integer", "minimum": 1}, "timeout": {"type": "number", "exclusiveMinimum": 0}},
                    "additionalProperties": False,
                },
            ),
        ]


def run_stdio(server: InteractiveAnalysisMcpServer) -> int:
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
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Interactive Dynamic Analysis MCP server (stdio)")
    parser.add_argument("--transport", choices=["stdio"], default="stdio")
    parser.parse_args()
    server = InteractiveAnalysisMcpServer()
    return run_stdio(server)


if __name__ == "__main__":
    raise SystemExit(main())

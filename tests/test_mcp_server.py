from __future__ import annotations

from interactive_analysis.mcp_server import InteractiveAnalysisMcpServer


class FakeSession:
    def __init__(self) -> None:
        self.started = False

    def start(self, target, args=None, cwd=None, qemu_config=None):  # noqa: ANN001
        self.started = True
        return {"ok": True, "command": "start", "result": {"target": target}}

    def close(self):
        self.started = False
        return {"ok": True, "command": "close", "result": {}}

    def capabilities(self):
        return {"ok": True, "command": "capabilities", "result": {"capabilities": {"read_memory": True}}}

    def get_state(self):
        return {"ok": True, "command": "get_state", "result": {"session_status": "paused"}}

    def get_registers(self, names=None):  # noqa: ANN001
        return {"ok": True, "command": "get_registers", "result": {"registers": {"rip": "0x401000"}}}

    def disassemble(self, address, count=16):  # noqa: ANN001
        return {"ok": True, "command": "disassemble", "result": {"instructions": [{"address": address, "size": count}]}}

    def read_memory(self, address, size):  # noqa: ANN001
        return {"ok": True, "command": "read_memory", "result": {"address": address, "size": size, "bytes": "00"}}

    def list_memory_maps(self):
        return {"ok": True, "command": "list_memory_maps", "result": {"maps": {"regions": []}}}

    def run_until_address(self, address, timeout=5.0):  # noqa: ANN001
        return {"ok": True, "command": "run_until_address", "result": {"matched_address": address, "timeout": timeout}}

    def step(self, count=1, timeout=5.0):  # noqa: ANN001
        return {"ok": True, "command": "step", "result": {"count": count, "timeout": timeout}}

    def advance_basic_blocks(self, count=1, timeout=5.0):  # noqa: ANN001
        return {"ok": True, "command": "advance_basic_blocks", "result": {"count": count, "timeout": timeout}}


def _server() -> InteractiveAnalysisMcpServer:
    return InteractiveAnalysisMcpServer(session_factory=FakeSession)


def test_mcp_initialize() -> None:
    server = _server()
    response = server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert response is not None
    assert response["result"]["serverInfo"]["name"] == "interactive-dynamic-analysis"
    assert "tools" in response["result"]["capabilities"]


def test_mcp_tools_list_contains_session_start() -> None:
    server = _server()
    response = server.handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    assert response is not None
    names = {item["name"] for item in response["result"]["tools"]}
    assert "session_start" in names
    assert "step" in names


def test_mcp_tool_call_session_start() -> None:
    server = _server()
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "session_start",
                "arguments": {"target": "/tmp/a.out", "args": ["x"], "qemu_config": {}},
            },
        }
    )
    assert response is not None
    result = response["result"]
    assert result["isError"] is False
    assert result["structuredContent"]["result"]["target"] == "/tmp/a.out"


def test_mcp_tool_call_unknown_tool_returns_error() -> None:
    server = _server()
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "nope", "arguments": {}},
        }
    )
    assert response is not None
    assert response["result"]["isError"] is True

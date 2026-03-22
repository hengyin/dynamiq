from __future__ import annotations

import pytest

from interactive_analysis.backends.qemu_user_instrumented import QemuUserInstrumentedBackend


@pytest.mark.live_qemu
def test_live_qemu_backend_rpc_run_until_address(live_qemu_start_kwargs: dict[str, object]) -> None:
    backend = QemuUserInstrumentedBackend()
    backend.start(**live_qemu_start_kwargs)
    try:
        caps = backend.capabilities()
        regs = backend.get_registers(["rip"])
        rip = regs["result"]["registers"]["rip"]
        disassembly = backend.disassemble(rip, count=8)
        instructions = disassembly["result"]["instructions"]
        assert len(instructions) >= 2
        target_address = str(instructions[min(3, len(instructions) - 1)]["address"])

        stop = backend.run_until_address(target_address, timeout=5.0)
        regs_after = backend.get_registers(["rip"])
        state = backend.get_state()

        assert caps["read_registers"] is True
        assert caps["disassemble"] is True
        assert caps["run_until_address"] is True
        assert stop["result"]["matched"] is True
        assert stop["result"]["matched_pc"] == target_address
        assert stop["result"]["pc"] == target_address
        assert regs_after["result"]["registers"]["rip"] == target_address
        assert state["pc"] == target_address
        assert state["backend"] == "qemu_user_instrumented"
    finally:
        backend.close()

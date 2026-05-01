from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from dynamiq.backends.qemu_user_instrumented import QemuUserInstrumentedBackend


def _read_pc(backend: QemuUserInstrumentedBackend) -> str:
    registers = backend.get_registers(["pc"])["result"]["registers"]
    return str(registers["pc"])


def _resolve_aarch64_instrumented_qemu() -> Path:
    configured = os.environ.get("IA_LIVE_AARCH64_QEMU_USER_PATH")
    sibling_symfit = Path(__file__).resolve().parents[2].parent / "symfit"
    candidates = [
        Path(configured) if configured else None,
        sibling_symfit / "build/symfit-symsan/aarch64-linux-user/symfit-aarch64",
    ]
    for candidate in candidates:
        if candidate is not None and candidate.exists():
            return candidate
    pytest.skip("instrumented AArch64 QEMU not found; set IA_LIVE_AARCH64_QEMU_USER_PATH")


def _compile_aarch64_smoke_target(tmp_path: Path) -> Path:
    compiler = shutil.which(
        os.environ.get("IA_LIVE_AARCH64_CC", "aarch64-linux-gnu-gcc")
    )
    if compiler is None:
        pytest.skip("AArch64 cross-compiler not found; set IA_LIVE_AARCH64_CC")

    source = tmp_path / "aarch64_step.c"
    target = tmp_path / "aarch64_step"
    source.write_text(
        (
            "#include <stdint.h>\n"
            "\n"
            "volatile uint64_t sink;\n"
            "\n"
            "int main(void) {\n"
            "    sink += 1;\n"
            "    sink += 2;\n"
            "    return (int)sink & 0;\n"
            "}\n"
        ),
        encoding="utf-8",
    )
    subprocess.run(
        [compiler, "-static", "-O0", "-g", "-o", str(target), str(source)],
        check=True,
    )
    return target


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
        assert state["rpc_protocol_version"] == 1
        assert state["rpc_capabilities"]["read_registers"] is True
        assert state["rpc_capabilities"]["run_until_address"] is True
        assert stop["result"]["matched"] is True
        assert stop["result"]["matched_pc"] == target_address
        assert stop["result"]["pc"] == target_address
        assert regs_after["result"]["registers"]["rip"] == target_address
        assert state["pc"] == target_address
        assert state["backend"] == "qemu_user_instrumented"
    finally:
        backend.close()


@pytest.mark.live_qemu
def test_live_qemu_backend_list_memory_maps_schema(live_qemu_start_kwargs: dict[str, object]) -> None:
    backend = QemuUserInstrumentedBackend()
    backend.start(**live_qemu_start_kwargs)
    try:
        result = backend.list_memory_maps()
        maps = result["result"]["maps"]
        regions = maps["regions"]

        assert isinstance(regions, list)
        assert len(regions) > 0
        first = regions[0]
        assert {"start", "end", "perm", "name"} <= set(first.keys())
        assert isinstance(first["start"], str) and first["start"].startswith("0x")
        assert isinstance(first["end"], str) and first["end"].startswith("0x")
        assert isinstance(first["perm"], str) and len(first["perm"]) == 3
        assert first["name"] is None or isinstance(first["name"], str)

        target = str(Path(live_qemu_start_kwargs["target"]).resolve())
        names = {region.get("name") for region in regions if isinstance(region.get("name"), str)}
        assert target in names or "[stack]" in names
    finally:
        backend.close()


@pytest.mark.live_qemu
def test_live_qemu_backend_single_step(live_qemu_start_kwargs: dict[str, object]) -> None:
    backend = QemuUserInstrumentedBackend()
    backend.start(**live_qemu_start_kwargs)
    try:
        caps = backend.capabilities()
        assert caps["single_step"] is True

        pc = _read_pc(backend)
        disassembly = backend.disassemble(pc, count=2)
        instructions = disassembly["result"]["instructions"]
        assert len(instructions) >= 2

        step = backend.step(1, timeout=5.0)
        pc_after = _read_pc(backend)

        assert step["result"]["status"] == "paused"
        assert step["result"]["executed"] == 1
        assert step["result"]["pc"] != pc
        assert pc_after == step["result"]["pc"]
    finally:
        backend.close()


@pytest.mark.live_qemu
def test_live_qemu_backend_aarch64_single_step(tmp_path: Path) -> None:
    target = _compile_aarch64_smoke_target(tmp_path)
    qemu_user_path = _resolve_aarch64_instrumented_qemu()
    rpc_socket = tmp_path / "aarch64-step-rpc.sock"

    backend = QemuUserInstrumentedBackend()
    backend.start(
        target=str(target),
        args=[],
        cwd=str(tmp_path),
        qemu_config={
            "launch": True,
            "qemu_user_path": str(qemu_user_path),
            "instrumentation_rpc_socket_path": str(rpc_socket),
            "instrumentation_rpc_timeout": 5.0,
            "launch_connect_timeout": 8.0,
        },
    )
    try:
        caps = backend.capabilities()
        pc = _read_pc(backend)

        step = backend.step(1, timeout=5.0)
        pc_after = _read_pc(backend)

        assert caps["single_step"] is True
        assert step["result"]["status"] == "paused"
        assert step["result"]["executed"] == 1
        assert step["result"]["pc"] != pc
        assert pc_after == step["result"]["pc"]
        assert backend.get_state()["pc"] == step["result"]["pc"]
    finally:
        backend.close()

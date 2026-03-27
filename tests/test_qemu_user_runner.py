from __future__ import annotations

import time
from pathlib import Path

from interactive_analysis.qemu_user import QemuUserLaunchConfig, QemuUserProcessRunner, _resolve_qemu_from_candidates


def test_qemu_user_launch_config_builds_command_and_env() -> None:
    config = QemuUserLaunchConfig.from_target(
        target="./bin/sample",
        args=["a", "b"],
        cwd="/tmp/work",
        qemu_config={
            "qemu_user_path": "/usr/bin/qemu-x86_64",
            "qemu_args": ["-strace"],
            "instrumentation_socket_path": "/tmp/events.sock",
            "instrumentation_rpc_socket_path": "/tmp/rpc.sock",
            "env": {"FOO": "bar"},
        },
    )

    assert config.command() == ["/usr/bin/qemu-x86_64", "-strace", "./bin/sample", "a", "b"]
    env = config.environment()
    assert env["FOO"] == "bar"
    assert env["IA_EVENT_SOCKET"] == "/tmp/events.sock"
    assert env["IA_RPC_SOCKET"] == "/tmp/rpc.sock"


def test_qemu_user_launch_config_prefers_local_build_when_available(monkeypatch, tmp_path: Path) -> None:
    home = tmp_path / "home"
    preferred = home / "git" / "qemu" / "build-ia" / "qemu-x86_64"
    preferred.parent.mkdir(parents=True)
    preferred.write_text("", encoding="utf-8")

    monkeypatch.setattr("interactive_analysis.qemu_user.Path.home", lambda: home)
    monkeypatch.setattr("interactive_analysis.qemu_user.shutil.which", lambda _name: "/usr/bin/qemu-x86_64")

    config = QemuUserLaunchConfig.from_target(target="./bin/sample", qemu_config={})

    qemu_name = Path(config.qemu_user_path).name
    assert qemu_name in {"qemu-x86_64", "qemu-x86_64-instrumented"}


def test_qemu_user_launch_config_selects_i386_for_32bit_elf(monkeypatch, tmp_path: Path) -> None:
    home = tmp_path / "home"
    home_preferred = home / "git" / "qemu" / "build-ia" / "qemu-i386"
    home_preferred.parent.mkdir(parents=True)
    home_preferred.write_text("", encoding="utf-8")

    target = tmp_path / "sample-32"
    # ELF32 + little-endian + ET_EXEC + EM_386
    target.write_bytes(b"\x7fELF\x01\x01\x01" + b"\x00" * 9 + b"\x02\x00\x03\x00")

    monkeypatch.setattr("interactive_analysis.qemu_user.Path.home", lambda: home)
    monkeypatch.setattr("interactive_analysis.qemu_user.shutil.which", lambda _name: None)

    config = QemuUserLaunchConfig.from_target(target=str(target), qemu_config={})

    qemu_name = Path(config.qemu_user_path).name
    assert qemu_name in {"qemu-i386", "qemu-i386-instrumented"}


def test_qemu_user_launch_config_falls_back_to_x86_64_when_arch_unknown(monkeypatch, tmp_path: Path) -> None:
    home = tmp_path / "home"
    preferred = home / "git" / "qemu" / "build-ia" / "qemu-x86_64"
    preferred.parent.mkdir(parents=True)
    preferred.write_text("", encoding="utf-8")

    target = tmp_path / "not-elf"
    target.write_text("plain text", encoding="utf-8")

    monkeypatch.setattr("interactive_analysis.qemu_user.Path.home", lambda: home)
    monkeypatch.setattr("interactive_analysis.qemu_user.shutil.which", lambda _name: None)

    config = QemuUserLaunchConfig.from_target(target=str(target), qemu_config={})

    qemu_name = Path(config.qemu_user_path).name
    assert qemu_name in {"qemu-x86_64", "qemu-x86_64-instrumented"}


def test_qemu_user_launch_config_honors_explicit_qemu_path(monkeypatch, tmp_path: Path) -> None:
    target = tmp_path / "sample-32"
    target.write_bytes(b"\x7fELF\x01\x01\x01" + b"\x00" * 9 + b"\x02\x00\x03\x00")

    monkeypatch.setattr("interactive_analysis.qemu_user.shutil.which", lambda _name: "/usr/bin/qemu-i386")

    config = QemuUserLaunchConfig.from_target(
        target=str(target),
        qemu_config={"qemu_user_path": "/custom/qemu-user"},
    )

    assert config.qemu_user_path == "/custom/qemu-user"


def test_resolve_qemu_prefers_repo_tools_qemu_folder(monkeypatch, tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    home = tmp_path / "home"
    preferred = repo_root / "tools" / "qemu" / "qemu-i386-instrumented"
    fallback = home / "git" / "qemu" / "build-ia" / "qemu-i386"
    preferred.parent.mkdir(parents=True)
    fallback.parent.mkdir(parents=True)
    preferred.write_text("", encoding="utf-8")
    fallback.write_text("", encoding="utf-8")

    monkeypatch.setattr("interactive_analysis.qemu_user.shutil.which", lambda _name: None)

    resolved = _resolve_qemu_from_candidates(["qemu-i386"], repo_root=repo_root, home=home)

    assert resolved == str(preferred)


def test_qemu_user_process_runner_reads_stdout_and_stderr_nonblocking() -> None:
    runner = QemuUserProcessRunner()
    config = QemuUserLaunchConfig(
        qemu_user_path="/bin/sh",
        target="-c",
        args=["printf 'out-line\\n'; printf 'err-line\\n' >&2"],
        cwd=None,
    )
    runner.start(config)
    assert runner.process is not None
    runner.process.wait(timeout=2.0)
    time.sleep(0.05)

    out = runner.read_stdout(cursor=0, max_chars=4096)
    err = runner.read_stderr(cursor=0, max_chars=4096)

    assert "out-line" in out["data"]
    assert "err-line" in err["data"]
    assert out["eof"] is True
    assert err["eof"] is True
    runner.close()

from __future__ import annotations

import time
from pathlib import Path

from interactive_analysis.qemu_user import QemuUserLaunchConfig, QemuUserProcessRunner


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

    assert config.qemu_user_path == str(preferred)


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

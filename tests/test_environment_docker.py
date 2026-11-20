"""Docker prerequisite checks: CLI missing versus daemon unreachable."""

from __future__ import annotations

import subprocess

import pytest

from strix.interface import environment
from strix.interface.tui.live_view import _friendly_error


def test_daemon_unreachable_exits_with_clear_message(monkeypatch, capsys) -> None:
    monkeypatch.setattr(environment.shutil, "which", lambda _name: "/usr/local/bin/docker")

    def boom(*_args, **_kwargs):
        raise subprocess.CalledProcessError(1, "docker")

    monkeypatch.setattr(environment.subprocess, "run", boom)
    monkeypatch.setattr(environment, "report_error", lambda *_a, **_k: None)

    with pytest.raises(SystemExit) as exc:
        environment.check_docker_installed()

    assert exc.value.code == 1
    assert "Docker 未运行" in capsys.readouterr().out


def test_daemon_reachable_passes(monkeypatch) -> None:
    monkeypatch.setattr(environment.shutil, "which", lambda _name: "/usr/local/bin/docker")
    monkeypatch.setattr(environment.subprocess, "run", lambda *_a, **_k: None)

    environment.check_docker_installed()


def test_agent_error_translation_for_vanished_sandbox() -> None:
    raw = (
        '404 Client Error for http+docker://localhost/v1.54/containers/abc/json : '
        'Not Found ("No such container: abc")'
    )
    message = _friendly_error(raw)
    assert "沙箱容器已不存在" in message
    assert _friendly_error("other failure") == "other failure"

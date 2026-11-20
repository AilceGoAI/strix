"""Docker prerequisite checks: CLI missing versus daemon unreachable."""

from __future__ import annotations

import subprocess

import pytest

from strix.interface import environment


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

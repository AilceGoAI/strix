"""Tests for ``strix local schedule``: every case runs in a tmp sandbox.

The sandbox fixture points ``STRIX_LOCAL_HOME`` and ``STRIX_LOCAL_LAUNCHD_DIR`` at
tmp directories and replaces ``launchctl``, so no real home directory is read or
written and no process is launched.
"""

from __future__ import annotations

import argparse
import json
import os
import plistlib
from types import SimpleNamespace
from typing import TYPE_CHECKING

import pytest

from strix.local import schedule


if TYPE_CHECKING:
    from pathlib import Path


def _parse(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="strix local")
    subparsers = parser.add_subparsers(dest="command", metavar="<命令>")
    schedule.register(subparsers)
    return parser.parse_args(["schedule", *argv])


def _run(argv: list[str]) -> int:
    args = _parse(argv)
    assert args.func is schedule.run
    return schedule.run(args)


@pytest.fixture
def sandbox(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    state = tmp_path / "state"
    launch = tmp_path / "LaunchAgents"
    monkeypatch.setenv(schedule.LOCAL_HOME_ENV, str(state))
    monkeypatch.setenv(schedule.LAUNCHD_DIR_ENV, str(launch))
    monkeypatch.setattr(schedule, "_is_macos", lambda: True)
    monkeypatch.setattr(schedule, "_working_directory", lambda: tmp_path / "work")
    monkeypatch.setattr(schedule, "_strix_command", lambda: ["/opt/strix"])

    calls: list[tuple[str, ...]] = []

    def fake_launchctl(*arguments: str) -> tuple[bool, str]:
        calls.append(arguments)
        return True, ""

    monkeypatch.setattr(schedule, "_launchctl", fake_launchctl)
    return SimpleNamespace(state=state, launch=launch, calls=calls, root=tmp_path)


def _registry(sandbox: SimpleNamespace) -> list[dict[str, object]]:
    path = sandbox.state / "schedules.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    schedules = payload["schedules"]
    assert isinstance(schedules, list)
    return schedules


def _plist_path(sandbox: SimpleNamespace, name: str = "nightly") -> Path:
    return sandbox.launch / f"ai.strix.local.schedule.{name}.plist"


def _add_argv(name: str = "nightly") -> list[str]:
    return [
        "add",
        "--name",
        name,
        "--cron",
        "0 3 * * *",
        "--target",
        "https://example.test",
    ]


def test_add_writes_plist_and_registry(
    sandbox: SimpleNamespace, capsys: pytest.CaptureFixture[str]
) -> None:
    code = _run([*_add_argv(), "--mode", "standard", "--budget", "12.5"])
    assert code == 0

    plist_path = _plist_path(sandbox)
    assert plist_path.is_file()
    payload = plistlib.loads(plist_path.read_bytes())
    assert payload["Label"] == "ai.strix.local.schedule.nightly"
    assert payload["ProgramArguments"] == [
        "/opt/strix",
        "-n",
        "--target",
        "https://example.test",
        "--scan-mode",
        "standard",
        "--max-budget",
        "12.5",
    ]
    assert payload["StartCalendarInterval"] == [{"Minute": 0, "Hour": 3}]
    assert payload["RunAtLoad"] is False
    assert payload["WorkingDirectory"] == str(sandbox.root / "work")
    assert payload["StandardOutPath"] == str(sandbox.state / "logs" / "nightly.out.log")
    assert payload["StandardErrorPath"] == str(sandbox.state / "logs" / "nightly.err.log")
    assert plist_path.stat().st_mode & 0o777 == 0o644

    entries = _registry(sandbox)
    assert entries[0]["name"] == "nightly"
    assert entries[0]["backend"] == "launchd"
    assert entries[0]["budget"] == 12.5
    assert entries[0]["plist_path"] == str(plist_path)

    assert (sandbox.state / "schedules.json").stat().st_mode & 0o777 == 0o600
    assert sandbox.state.stat().st_mode & 0o777 == 0o700

    assert sandbox.calls[0] == ("bootstrap", f"gui/{os.getuid()}", str(plist_path))
    assert "nightly" in capsys.readouterr().out


def test_add_defaults_to_quick_mode(sandbox: SimpleNamespace) -> None:
    assert _run(_add_argv()) == 0
    payload = plistlib.loads(_plist_path(sandbox).read_bytes())
    arguments = payload["ProgramArguments"]
    assert arguments[arguments.index("--scan-mode") + 1] == "quick"
    assert "--max-budget" not in arguments


def test_add_dry_run_writes_nothing(
    sandbox: SimpleNamespace, capsys: pytest.CaptureFixture[str]
) -> None:
    code = _run([*_add_argv(), "--dry-run"])
    out = capsys.readouterr().out

    assert code == 0
    assert "<key>Label</key>" in out
    assert "ai.strix.local.schedule.nightly" in out
    assert "StartCalendarInterval" in out
    assert not (sandbox.state / "schedules.json").exists()
    assert not sandbox.launch.exists()
    assert sandbox.calls == []


def test_add_dry_run_json(sandbox: SimpleNamespace, capsys: pytest.CaptureFixture[str]) -> None:
    code = _run([*_add_argv(), "--budget", "10", "--dry-run", "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert code == 0
    assert payload["dry_run"] is True
    assert payload["schedule"]["name"] == "nightly"
    assert payload["schedule"]["budget"] == 10.0
    assert "ai.strix.local.schedule.nightly" in payload["plist"]
    assert not sandbox.launch.exists()


def test_add_json_reports_loaded_state(
    sandbox: SimpleNamespace, capsys: pytest.CaptureFixture[str]
) -> None:
    code = _run([*_add_argv(), "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert code == 0
    assert payload["loaded"] is True
    assert payload["schedule"]["plist_path"].endswith("nightly.plist")
    assert payload["warnings"] == []
    assert _plist_path(sandbox).is_file()


@pytest.mark.parametrize(
    "expression",
    [
        "0 3 * *",
        "0 3 * * * *",
        "60 * * * *",
        "* 24 * * *",
        "0 0 0 * *",
        "* * * 13 *",
        "* * * * 8",
        "*/0 * * * *",
        "abc * * * *",
    ],
)
def test_add_rejects_invalid_cron(
    sandbox: SimpleNamespace,
    capsys: pytest.CaptureFixture[str],
    expression: str,
) -> None:
    code = _run(["add", "--name", "bad", "--cron", expression, "--target", "example.test"])
    captured = capsys.readouterr()

    assert code == 2
    assert "cron" in captured.err
    assert not (sandbox.state / "schedules.json").exists()
    assert sandbox.calls == []


def test_add_rejects_invalid_name_and_budget(
    sandbox: SimpleNamespace, capsys: pytest.CaptureFixture[str]
) -> None:
    bad_name = _run(["add", "--name", "../evil", "--cron", "0 3 * * *", "--target", "example.test"])
    assert bad_name == 2
    assert "计划名称无效" in capsys.readouterr().err

    bad_budget = _run([*_add_argv(), "--budget", "0"])
    assert bad_budget == 2
    assert "预算无效" in capsys.readouterr().err
    assert not (sandbox.state / "schedules.json").exists()


def test_add_duplicate_requires_force(
    sandbox: SimpleNamespace, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _run(_add_argv()) == 0
    assert _run(_add_argv()) == 2
    assert "已存在同名计划" in capsys.readouterr().err

    assert _run([*_add_argv(), "--force"]) == 0
    assert len(_registry(sandbox)) == 1
    assert ("bootout", f"gui/{os.getuid()}/ai.strix.local.schedule.nightly") in sandbox.calls


def test_launchctl_failure_keeps_plist(
    sandbox: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(schedule, "_launchctl", lambda *_arguments: (False, "已经加载"))

    code = _run(_add_argv())
    out = capsys.readouterr().out

    assert code == 0
    assert "launchctl 装载失败" in out
    assert _plist_path(sandbox).is_file()
    assert len(_registry(sandbox)) == 1


def test_add_non_macos_prints_crontab_line(
    sandbox: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(schedule, "_is_macos", lambda: False)

    code = _run([*_add_argv(), "--mode", "deep", "--budget", "3"])
    out = capsys.readouterr().out

    assert code == 0
    assert "0 3 * * *" in out
    assert "/opt/strix -n --target https://example.test --scan-mode deep --max-budget 3" in out
    assert "crontab" in out
    assert not sandbox.launch.exists()
    assert sandbox.calls == []

    entry = _registry(sandbox)[0]
    assert entry["backend"] == "crontab"
    assert entry["plist_path"] is None


def test_list_empty_creates_nothing(
    sandbox: SimpleNamespace, capsys: pytest.CaptureFixture[str]
) -> None:
    code = _run(["list"])
    out = capsys.readouterr().out

    assert code == 0
    assert "尚无定时扫描计划" in out
    assert not sandbox.state.exists()


def test_list_table_and_json(sandbox: SimpleNamespace, capsys: pytest.CaptureFixture[str]) -> None:
    assert _run(_add_argv()) == 0
    capsys.readouterr()

    assert _run(["list"]) == 0
    table = capsys.readouterr().out
    assert "nightly" in table
    assert "0 3 * * *" in table

    assert _run(["list", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["count"] == 1
    assert payload["schedules"][0]["target"] == "https://example.test"
    assert len(_registry(sandbox)) == 1


def test_remove_unloads_and_deletes_plist(
    sandbox: SimpleNamespace, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _run(_add_argv()) == 0
    plist_path = _plist_path(sandbox)
    sandbox.calls.clear()

    code = _run(["remove", "nightly"])
    out = capsys.readouterr().out

    assert code == 0
    assert sandbox.calls[0] == (
        "bootout",
        f"gui/{os.getuid()}/ai.strix.local.schedule.nightly",
    )
    assert not plist_path.exists()
    assert _registry(sandbox) == []
    assert "已删除计划" in out


def test_remove_json(sandbox: SimpleNamespace, capsys: pytest.CaptureFixture[str]) -> None:
    assert _run(_add_argv()) == 0
    capsys.readouterr()

    assert _run(["remove", "nightly", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["removed"]["name"] == "nightly"
    assert payload["unloaded"] is True
    assert payload["plist_removed"] is True
    assert not _plist_path(sandbox).exists()


def test_remove_unknown_name(sandbox: SimpleNamespace, capsys: pytest.CaptureFixture[str]) -> None:
    assert _run(["remove", "missing"]) == 1
    assert "计划不存在" in capsys.readouterr().err

    assert _run(["remove", "missing", "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert "计划不存在" in payload["error"]
    assert not (sandbox.state / "schedules.json").exists()


def test_remove_non_macos_prints_crontab_line(
    sandbox: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(schedule, "_is_macos", lambda: False)
    assert _run(_add_argv()) == 0
    capsys.readouterr()

    code = _run(["remove", "nightly"])
    out = capsys.readouterr().out

    assert code == 0
    assert "crontab -e" in out
    assert "0 3 * * *" in out
    assert _registry(sandbox) == []


def test_parse_cron_expands_ranges_steps_and_names() -> None:
    fields = schedule.parse_cron("*/15 9-17 * jan-mar mon-fri")

    assert fields[0] == {0, 15, 30, 45}
    assert fields[1] == set(range(9, 18))
    assert fields[2] == set(range(1, 32))
    assert fields[3] == {1, 2, 3}
    assert fields[4] == {1, 2, 3, 4, 5}


def test_parse_cron_maps_sunday_7_to_0() -> None:
    fields = schedule.parse_cron("0 0 * * 7")
    assert fields[4] == {0}

    both = schedule.parse_cron("0 0 * * 0,7")
    assert both[4] == {0}


def test_parse_cron_supports_aliases() -> None:
    fields = schedule.parse_cron("@daily")
    assert fields[0] == {0}
    assert fields[1] == {0}
    assert fields[4] == set(range(7))


def test_calendar_intervals_for_quarter_hours() -> None:
    intervals = schedule.cron_to_calendar_intervals(schedule.parse_cron("*/15 2 * * *"))

    assert len(intervals) == 4
    assert {item["Minute"] for item in intervals} == {0, 15, 30, 45}
    assert all(item["Hour"] == 2 for item in intervals)
    assert all("Day" not in item for item in intervals)


def test_calendar_intervals_rejects_dense_cron() -> None:
    with pytest.raises(schedule.ScheduleError) as excinfo:
        schedule.cron_to_calendar_intervals(schedule.parse_cron("*/2 * * * *"))

    assert excinfo.value.exit_code == 2
    assert "上限" in str(excinfo.value)


def test_every_minute_uses_start_interval(tmp_path: Path) -> None:
    payload = schedule.build_plist_payload(
        label="ai.strix.local.schedule.every",
        cron_fields=schedule.parse_cron("* * * * *"),
        target="example.test",
        mode="quick",
        budget=None,
        working_directory=tmp_path / "work",
        log_path=tmp_path / "out.log",
        error_log_path=tmp_path / "err.log",
    )

    assert payload["StartInterval"] == 60
    assert "StartCalendarInterval" not in payload


def test_day_and_weekday_warning() -> None:
    warnings = schedule.cron_warnings(schedule.parse_cron("0 0 1 * 1"))
    assert len(warnings) == 1
    assert "同时" in warnings[0]

    assert schedule.cron_warnings(schedule.parse_cron("0 0 * * *")) == []


def test_bare_schedule_prints_usage(capsys: pytest.CaptureFixture[str]) -> None:
    args = _parse([])

    assert args.schedule_command is None
    assert schedule.run(args) == 0
    assert "用法" in capsys.readouterr().out


def test_help_lists_subcommands(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        _parse(["--help"])

    assert excinfo.value.code == 0
    out = capsys.readouterr().out
    assert "add" in out
    assert "list" in out
    assert "remove" in out

    with pytest.raises(SystemExit) as add_exit:
        _parse(["add", "--help"])

    assert add_exit.value.code == 0
    add_help = capsys.readouterr().out
    assert "--cron" in add_help
    assert "--dry-run" in add_help
    assert "--json" in add_help

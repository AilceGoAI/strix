"""Tests for strix.local.runs — 本地运行索引与历史。

全程使用 tmp_path + STRIX_LOCAL_HOME / STRIX_MCP_ROOT / STRIX_PENTEST_ROOT
隔离、不读写真实家目录。
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import stat
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import pytest

from strix.local import runs


if TYPE_CHECKING:
    from pathlib import Path


FINDINGS = [
    {
        "id": "vuln-0001",
        "title": "未授权注册管理员账户",
        "severity": "critical",
        "target": "http://192.168.5.2:3000",
    },
    {
        "id": "vuln-0002",
        "title": "Verbose errors",
        "severity": "low",
        "target": "",
    },
]


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    home = tmp_path / "home"
    pentest = home / "pentest"
    mcp = pentest / "strix-mcp-runs"
    local = tmp_path / "dot-strix" / "local"
    mcp.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("STRIX_LOCAL_HOME", str(local))
    monkeypatch.setenv("STRIX_MCP_ROOT", str(mcp))
    monkeypatch.setenv("STRIX_PENTEST_ROOT", str(pentest))
    return SimpleNamespace(tmp=tmp_path, home=home, pentest=pentest, mcp=mcp, local=local)


def _write_run(
    base: Path,
    name: str,
    record: dict[str, Any] | str,
    *,
    findings: list[dict[str, Any]] | None = None,
) -> Path:
    run_dir = base / name
    run_dir.mkdir(parents=True)
    text = record if isinstance(record, str) else json.dumps(record, ensure_ascii=False)
    (run_dir / "run.json").write_text(text, encoding="utf-8")
    if findings is not None:
        (run_dir / "vulnerabilities.json").write_text(
            json.dumps(findings, ensure_ascii=False), encoding="utf-8"
        )
    return run_dir


def _record(
    *,
    target: str = "https://example.com",
    status: str = "completed",
    start: str = "2026-11-19T07:28:05+00:00",
    end: str | None = "2026-11-19T07:40:00+00:00",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "run_id": f"id-{status}",
        "status": status,
        "start_time": start,
        "end_time": end,
        "targets_info": [{"type": "web_application", "original": target}],
    }
    record.update(extra or {})
    return record


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="strix")
    root = parser.add_subparsers(dest="command")
    local = root.add_parser("local")
    local_sub = local.add_subparsers(dest="local_command")
    runs.register(local_sub)
    return parser


def _invoke(argv: list[str]) -> tuple[int, str, str]:
    args = _parser().parse_args(["local", "runs", *argv])
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = runs.run(args)
    return code, out.getvalue(), err.getvalue()


def test_list_indexes_mcp_and_workspace_runs_with_secure_state(env: SimpleNamespace) -> None:
    _write_run(
        env.mcp,
        "example-com_1111",
        _record(target="https://example.com"),
        findings=FINDINGS,
    )
    _write_run(
        env.pentest / "lab" / "strix_runs",
        "192-168-5-2-3000_e372",
        _record(target="http://192.168.5.2:3000", status="failed"),
    )

    code, out, err = _invoke(["list", "--json"])

    assert code == 0, err
    payload = json.loads(out)
    assert payload["total"] == 2
    by_name = {item["run_name"]: item for item in payload["runs"]}
    assert set(by_name) == {"example-com_1111", "192-168-5-2-3000_e372"}
    assert by_name["example-com_1111"]["source"] == "mcp"
    assert by_name["example-com_1111"]["findings"] == 2
    assert by_name["example-com_1111"]["severity_counts"] == {"critical": 1, "low": 1}
    assert by_name["192-168-5-2-3000_e372"]["source"] == "workspace"
    assert stat.S_IMODE(env.local.stat().st_mode) == 0o700
    assert stat.S_IMODE((env.local / "runs.jsonl").stat().st_mode) == 0o600


def test_index_is_append_only_and_reindexes_only_changed_runs(env: SimpleNamespace) -> None:
    run_dir = _write_run(env.mcp, "run-a", _record(status="running", end=None))

    assert _invoke(["list"])[0] == 0
    index = env.local / "runs.jsonl"
    first_lines = index.read_text(encoding="utf-8").splitlines()
    assert len(first_lines) == 1

    assert _invoke(["list"])[0] == 0
    assert index.read_text(encoding="utf-8").splitlines() == first_lines

    record_path = run_dir / "run.json"
    record_path.write_text(
        json.dumps(_record(status="completed"), ensure_ascii=False), encoding="utf-8"
    )
    bumped = record_path.stat().st_mtime_ns + 1_000_000
    os.utime(record_path, ns=(bumped, bumped))

    code, out, _ = _invoke(["list", "--json"])
    assert code == 0
    assert [item["status"] for item in json.loads(out)["runs"]] == ["completed"]
    assert len(index.read_text(encoding="utf-8").splitlines()) == 2


def test_target_and_status_filters(env: SimpleNamespace) -> None:
    _write_run(env.mcp, "run-a", _record(target="https://Example.COM", status="completed"))
    _write_run(env.mcp, "run-b", _record(target="http://192.168.5.2:3000", status="failed"))
    _write_run(env.pentest / "strix_runs", "run-c", _record(target="https://api.example.com"))

    _, out, _ = _invoke(["list", "--json", "--target", "example.com"])
    assert {item["run_name"] for item in json.loads(out)["runs"]} == {"run-a", "run-c"}

    _, out, _ = _invoke(["list", "--json", "--target", "192.168", "--status", "failed"])
    assert [item["run_name"] for item in json.loads(out)["runs"]] == ["run-b"]

    _, out, _ = _invoke(["list", "--json", "--target", "example.com", "--limit", "1"])
    assert len(json.loads(out)["runs"]) == 1

    _, out, _ = _invoke(["list", "--json", "--target", "no-such-host"])
    assert json.loads(out) == {
        "runs": [],
        "total": 0,
        "index": str(env.local / "runs.jsonl"),
    }


def test_list_human_output_uses_simplified_chinese(env: SimpleNamespace) -> None:
    _write_run(env.mcp, "run-a", _record(status="completed"), findings=FINDINGS)

    code, out, _ = _invoke(["list"])

    assert code == 0
    assert "开始时间" in out
    assert "已完成" in out
    assert "run-a" in out
    assert "https://example.com" in out
    assert "共 1 条" in out


def test_show_by_name_and_json(env: SimpleNamespace) -> None:
    run_dir = _write_run(env.mcp, "run-a", _record(), findings=FINDINGS)

    code, out, _ = _invoke(["show", "run-a", "--json"])

    assert code == 0
    payload = json.loads(out)
    assert payload["run_name"] == "run-a"
    assert payload["path"] == str(run_dir.resolve())
    assert payload["missing"] is False
    assert [item["id"] for item in payload["findings_detail"]] == ["vuln-0001", "vuln-0002"]

    code, out, _ = _invoke(["show", str(run_dir)])
    assert code == 0
    assert "发现明细" in out
    assert "[critical] 未授权注册管理员账户" in out


def test_show_unknown_and_ambiguous_names(env: SimpleNamespace) -> None:
    code, _, err = _invoke(["show", "does-not-exist"])
    assert code == 1
    assert "未找到运行" in err

    _write_run(env.mcp, "dup", _record())
    _write_run(env.pentest / "strix_runs", "dup", _record())

    code, _, err = _invoke(["show", "dup"])
    assert code == 1
    assert "对应多个目录" in err


def test_show_reports_history_for_a_removed_run_dir(env: SimpleNamespace) -> None:
    run_dir = _write_run(env.mcp, "run-a", _record(), findings=FINDINGS)
    assert _invoke(["list"])[0] == 0
    for child in run_dir.iterdir():
        child.unlink()
    run_dir.rmdir()

    code, out, _ = _invoke(["show", "run-a"])
    assert code == 0
    assert "运行目录已不存在" in out


def test_export_markdown_to_file(env: SimpleNamespace) -> None:
    _write_run(env.mcp, "run-a", _record(), findings=FINDINGS)
    _write_run(env.mcp, "run-b", _record(target="https://other.test", status="failed"))
    output = env.tmp / "reports" / "summary.md"

    code, out, _ = _invoke(["export", "--target", "example.com", "-o", str(output)])

    assert code == 0
    assert "已写入" in out
    assert "运行 1 个，发现 2 个" in out
    text = output.read_text(encoding="utf-8")
    assert text.startswith("# Strix 运行汇总")
    assert "运行数量：1 · 发现总数：2" in text
    assert "critical 1 / low 1" in text
    assert "| `run-a` | https://example.com |" in text
    assert "**critical** 未授权注册管理员账户" in text
    assert "run-b" not in text


def test_export_stdout_and_json(env: SimpleNamespace) -> None:
    _write_run(env.mcp, "run-a", _record(), findings=FINDINGS)

    code, out, _ = _invoke(["export"])
    assert code == 0
    assert out.startswith("# Strix 运行汇总")

    code, out, _ = _invoke(["export", "--json"])
    assert code == 0
    payload = json.loads(out)
    assert payload["total_runs"] == 1
    assert payload["total_findings"] == 2
    assert payload["output"] is None
    assert payload["severity_counts"] == {"critical": 1, "low": 1}
    assert payload["runs"][0]["findings_detail"][0]["id"] == "vuln-0001"

    written = env.tmp / "combo.md"
    code, out, _ = _invoke(["export", "--json", "-o", str(written)])
    assert code == 0
    payload = json.loads(out)
    assert payload["output"] == str(written)
    assert written.read_text(encoding="utf-8").startswith("# Strix 运行汇总")


def test_broken_run_json_is_listed_as_unknown(env: SimpleNamespace) -> None:
    _write_run(env.mcp, "broken", "{not json")
    binary = env.mcp / "binary"
    binary.mkdir()
    (binary / "run.json").write_bytes(b"\xff\xfe\x00")

    code, out, _ = _invoke(["list", "--json"])

    assert code == 0
    runs = {item["run_name"]: item for item in json.loads(out)["runs"]}
    assert set(runs) == {"broken", "binary"}
    for item in runs.values():
        assert item["status"] == "unknown"
        assert item["target"] == ""
        assert item["findings"] == 0


def test_register_sets_local_handler_and_rejects_bare_runs() -> None:
    args = _parser().parse_args(["local", "runs", "list", "--json"])
    assert args.runs_command == "list"
    assert args.local_handler is runs.run

    with pytest.raises(SystemExit):
        _parser().parse_args(["local", "runs"])


def test_empty_scan_reports_roots(env: SimpleNamespace) -> None:
    code, out, _ = _invoke(["list"])

    assert code == 0
    assert "未找到运行记录" in out
    assert str(env.mcp) in out
    assert "strix_runs" in out

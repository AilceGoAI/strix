"""Tests for ``strix local serve`` (read-only dashboard)."""

from __future__ import annotations

import argparse
import json
import os
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from strix.local import serve


if TYPE_CHECKING:
    from collections.abc import Iterator


# --------------------------------------------------------------------------- fixtures


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "local-home"
    monkeypatch.setenv("STRIX_LOCAL_HOME", str(home))
    monkeypatch.delenv("STRIX_LOCAL_RUNS_DIR", raising=False)
    return home


def _write_run(
    runs_dir: Path,
    run_id: str,
    *,
    status: str = "completed",
    end_time: str | None = "2026-11-20T10:00:00Z",
    findings: list[dict[str, Any]] | None = None,
    sarif: dict[str, Any] | None = None,
    mtime: float = 1_000.0,
) -> Path:
    run_dir = runs_dir / run_id
    run_dir.mkdir(parents=True)
    record = {
        "run_id": run_id,
        "run_name": run_id,
        "start_time": "2026-11-20T09:00:00Z",
        "end_time": end_time,
        "status": status,
        "scan_mode": "quick",
        "targets_info": [{"type": "web_app", "original": "https://example.com"}],
    }
    record_path = run_dir / "run.json"
    record_path.write_text(json.dumps(record), encoding="utf-8")
    os.utime(record_path, (mtime, mtime))
    if findings is not None:
        (run_dir / "vulnerabilities.json").write_text(json.dumps(findings), encoding="utf-8")
    if sarif is not None:
        (run_dir / "findings.sarif").write_text(json.dumps(sarif), encoding="utf-8")
    return run_dir


@pytest.fixture
def runs_dir(tmp_path: Path) -> Path:
    base = tmp_path / "strix_runs"
    _write_run(
        base,
        "run-old",
        findings=[
            {"id": "vuln-1", "title": "SQL 注入", "severity": "critical", "description": "..."},
            {"id": "vuln-2", "title": "信息泄露", "severity": "info", "description": "..."},
        ],
        sarif={"version": "2.1.0", "runs": []},
        mtime=1_000.0,
    )
    _write_run(base, "run-new", status="running", end_time=None, findings=[], mtime=2_000.0)
    return base


def _write_users(home: Path) -> Path:
    home.mkdir(parents=True, exist_ok=True)
    path = home / "users.json"
    path.write_text(
        json.dumps(
            {
                "users": [
                    {"name": "alice", "role": "admin", "token": "token-alice"},
                    {"name": "bob", "role": "viewer", "token": "token-bob"},
                ]
            }
        ),
        encoding="utf-8",
    )
    return path


@contextmanager
def _serve(runs_dir: Path, users_path: Path | None = None) -> Iterator[str]:
    state = serve.build_state(runs_dir=runs_dir, users_path=users_path)
    httpd = serve.create_server(state=state, host="127.0.0.1", port=0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def _request(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
) -> tuple[int, bytes, Any]:
    request = urllib.request.Request(url, method=method)  # noqa: S310 - 仅用于本地回环测试
    for name, value in (headers or {}).items():
        request.add_header(name, value)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=5) as response:
            return response.status, response.read(), response.headers
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), exc.headers


def _json(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any], Any]:
    status, raw, response_headers = _request(url, method=method, headers=headers)
    return status, json.loads(raw or b"{}"), response_headers


def _serve_args(**overrides: Any) -> argparse.Namespace:
    values: dict[str, Any] = {
        "host": "127.0.0.1",
        "port": 0,
        "json": True,
        "runs_dir": None,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


# --------------------------------------------------------------------------- 读取接口


def test_health_is_public_and_reports_open_mode(runs_dir: Path) -> None:
    with _serve(runs_dir) as base:
        status, body, _ = _json(base + "/api/health")
    assert status == 200
    assert body["status"] == "ok"
    assert body["service"] == "strix-local-serve"
    assert body["auth_required"] is False
    assert "/api/runs" in body["endpoints"]


def test_runs_list_is_newest_first_with_severity_counts(runs_dir: Path) -> None:
    with _serve(runs_dir) as base:
        status, body, _ = _json(base + "/api/runs")
    assert status == 200
    assert body["count"] == 2
    assert [run["id"] for run in body["runs"]] == ["run-new", "run-old"]
    old = body["runs"][1]
    assert old["finished"] is True
    assert old["findings_count"] == 2
    assert old["severity_counts"] == {
        "critical": 1,
        "high": 0,
        "medium": 0,
        "low": 1,
    }
    assert body["runs"][0]["finished"] is False


def test_run_detail_includes_record_and_artifacts(runs_dir: Path) -> None:
    with _serve(runs_dir) as base:
        status, body, _ = _json(base + "/api/runs/run-old")
    assert status == 200
    assert body["run"]["target"] == "https://example.com"
    assert body["record"]["run_name"] == "run-old"
    assert body["artifacts"]["findings_json"] is True
    assert body["artifacts"]["findings_sarif"] is True
    assert body["artifacts"]["report"] is False
    assert body["severity_counts"]["critical"] == 1


def test_findings_endpoint_and_sarif_format(runs_dir: Path) -> None:
    with _serve(runs_dir) as base:
        status, body, _ = _json(base + "/api/runs/run-old/findings")
        sarif_status, sarif, _ = _json(base + "/api/runs/run-old/findings?format=sarif")
    assert status == 200
    assert body["count"] == 2
    assert body["findings"][0]["title"] == "SQL 注入"
    assert sarif_status == 200
    assert sarif["format"] == "sarif"
    assert sarif["sarif"]["version"] == "2.1.0"


def test_unknown_and_traversal_runs_return_404(runs_dir: Path) -> None:
    with _serve(runs_dir) as base:
        missing, missing_body, _ = _json(base + "/api/runs/run-missing")
        traversal, _, _ = _json(base + "/api/runs/..%2Fetc")
        unknown_api, _, _ = _json(base + "/api/nope")
    assert missing == 404
    assert missing_body["error"] == "unknown_run"
    assert traversal == 404
    assert unknown_api == 404


def test_symlinked_run_dir_is_not_exposed(runs_dir: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside-run"
    outside.mkdir()
    (outside / "run.json").write_text(json.dumps({"run_name": "outside"}), encoding="utf-8")
    try:
        (runs_dir / "linked-run").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("当前文件系统不支持符号链接")
    with _serve(runs_dir) as base:
        _, body, _ = _json(base + "/api/runs")
        status, _, _ = _json(base + "/api/runs/linked-run")
    assert [run["id"] for run in body["runs"]] == ["run-new", "run-old"]
    assert status == 404


def test_dashboard_page_is_served(runs_dir: Path) -> None:
    with _serve(runs_dir) as base:
        status, raw, headers = _request(base + "/")
    assert status == 200
    assert headers["Content-Type"].startswith("text/html")
    assert "Strix 本地看板" in raw.decode("utf-8")


def test_non_get_methods_are_rejected(runs_dir: Path) -> None:
    with _serve(runs_dir) as base:
        status, body, headers = _json(base + "/api/runs", method="POST")
    assert status == 405
    assert body["error"] == "method_not_allowed"
    assert headers["Allow"] == "GET"


# --------------------------------------------------------------------------- 鉴权


def test_token_is_required_when_users_are_configured(runs_dir: Path, _isolated_home: Path) -> None:
    users_path = _write_users(_isolated_home)
    with _serve(runs_dir, users_path) as base:
        assert _json(base + "/api/health")[1]["auth_required"] is True
        assert _json(base + "/api/runs")[0] == 401
        assert _json(base + "/api/runs", headers={"Authorization": "Bearer wrong"})[0] == 401
        assert _json(base + "/api/runs", headers={"Authorization": "Bearer token-alice"})[0] == 200
        assert _json(base + "/api/runs", headers={"X-Strix-Token": "token-bob"})[0] == 200
        assert _json(base + "/api/runs?token=token-alice")[0] == 200
        status, body, _ = _json(base + "/api/runs", headers={"X-Strix-Token": "token-bob"})
        assert status == 200
        assert body["count"] == 2


def test_build_state_reads_users_from_strix_local_home(
    runs_dir: Path, _isolated_home: Path
) -> None:
    _write_users(_isolated_home)
    state = serve.build_state(runs_dir=runs_dir)
    assert state.users_path == _isolated_home / "users.json"
    assert state.auth_required is True
    assert state.user_count == 2


def test_malformed_users_file_is_a_configuration_error(
    runs_dir: Path, _isolated_home: Path
) -> None:
    _isolated_home.mkdir(parents=True)
    (_isolated_home / "users.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(serve.ServeError) as caught:
        serve.build_state(runs_dir=runs_dir)
    assert caught.value.exit_code == 2
    assert serve.run(_serve_args(host="127.0.0.1")) == 2


# --------------------------------------------------------------------------- 启动策略


def test_no_users_on_non_loopback_host_is_refused(
    runs_dir: Path, _isolated_home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    args = _serve_args(host="0.0.0.0", json=False, runs_dir=str(runs_dir))
    assert serve.run(args) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "拒绝在 0.0.0.0 上无鉴权启动" in captured.err
    assert str(_isolated_home / "users.json") in captured.err


def test_json_mode_prints_startup_payload(
    runs_dir: Path,
    _isolated_home: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    closed = {"value": False}

    class _FakeServer:
        server_address = ("127.0.0.1", 43210)

        def serve_forever(self) -> None:
            raise KeyboardInterrupt

        def server_close(self) -> None:
            closed["value"] = True

    def _fake_create_server(**_: Any) -> _FakeServer:
        return _FakeServer()

    monkeypatch.setattr(serve, "create_server", _fake_create_server)
    args = _serve_args(runs_dir=str(runs_dir))
    assert serve.run(args) == 0

    captured = capsys.readouterr()
    payload = json.loads(captured.out.strip().splitlines()[0])
    assert payload["status"] == "serving"
    assert payload["port"] == 43210
    assert payload["auth_required"] is False
    assert payload["warning"] == "no_users"
    assert "未配置本地用户" in captured.err
    assert closed["value"] is True


def test_human_output_is_chinese(
    runs_dir: Path,
    _isolated_home: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class _FakeServer:
        server_address = ("127.0.0.1", 43211)

        def serve_forever(self) -> None:
            raise KeyboardInterrupt

        def server_close(self) -> None:
            return None

    monkeypatch.setattr(serve, "create_server", lambda **_: _FakeServer())
    args = _serve_args(json=False, runs_dir=str(runs_dir))
    assert serve.run(args) == 0
    captured = capsys.readouterr()
    assert "只读看板已启动" in captured.out
    assert "按 Ctrl-C 停止" in captured.out
    assert "看板服务已停止" in captured.err


def test_resolve_runs_dir_precedence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env_dir = tmp_path / "env-runs"
    cli_dir = tmp_path / "cli-runs"
    monkeypatch.setenv("STRIX_LOCAL_RUNS_DIR", str(env_dir))
    assert serve.resolve_runs_dir(None) == env_dir
    assert serve.resolve_runs_dir(cli_dir) == cli_dir
    monkeypatch.delenv("STRIX_LOCAL_RUNS_DIR")
    assert serve.resolve_runs_dir(None) == Path.cwd() / "strix_runs"


def test_is_loopback() -> None:
    assert serve.is_loopback("127.0.0.1") is True
    assert serve.is_loopback("localhost") is True
    assert serve.is_loopback("::1") is True
    assert serve.is_loopback("0.0.0.0") is False
    assert serve.is_loopback("192.168.1.10") is False


# --------------------------------------------------------------------------- 子命令注册


def test_register_adds_serve_subcommand(tmp_path: Path) -> None:
    parser = argparse.ArgumentParser(prog="strix local")
    subparsers = parser.add_subparsers(dest="command")
    serve.register(subparsers)

    args = parser.parse_args(["serve"])
    assert args.func is serve.run
    assert args.host == "127.0.0.1"
    assert args.port == 8765
    assert args.json is False

    runs_dir = str(tmp_path / "runs")
    args = parser.parse_args(["serve", "--port", "9001", "--json", "--runs-dir", runs_dir])
    assert args.port == 9001
    assert args.json is True
    assert args.runs_dir == runs_dir

    with pytest.raises(SystemExit):
        parser.parse_args(["serve", "--port", "70000"])

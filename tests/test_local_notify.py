"""Tests for ``strix.local.notify`` — local-edition three-way notifications."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

import pytest

from strix.local import notify


CREDENTIAL_ENV = (
    "SLACK_WEBHOOK_URL",
    "JIRA_BASE_URL",
    "JIRA_EMAIL",
    "JIRA_TOKEN",
    "JIRA_PROJECT_KEY",
    "JIRA_ISSUE_TYPE",
    "LINEAR_API_KEY",
    "LINEAR_TEAM_ID",
)


class FakeResponse:
    def __init__(
        self,
        *,
        status_code: int = 200,
        payload: Any = None,
        text: str | None = None,
    ) -> None:
        self.status_code = status_code
        self._payload = payload
        if text is None:
            text = json.dumps(payload, ensure_ascii=False) if payload is not None else ""
        self.text = text

    def json(self) -> Any:
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


@pytest.fixture(autouse=True)
def _isolate_environment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("STRIX_LOCAL_HOME", str(tmp_path / "local-home"))
    for name in CREDENTIAL_ENV:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def runs_root(tmp_path: Path) -> Path:
    root = tmp_path / "strix_runs"
    run_dir = root / "run-abc123"
    run_dir.mkdir(parents=True)
    (run_dir / "run.json").write_text(
        json.dumps(
            {
                "run_id": "run-abc123",
                "run_name": "nightly",
                "status": "completed",
                "start_time": "2026-11-19T07:28:05+00:00",
                "end_time": "2026-11-19T08:01:00+00:00",
                "targets_info": [{"original": "https://app.example.com"}],
                "llm_usage": {"cost": 0.0123},
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    (run_dir / "vulnerabilities.json").write_text(
        json.dumps(
            [
                {
                    "id": "vuln-0001",
                    "title": "反射型 XSS",
                    "severity": "medium",
                    "target": "https://app.example.com/search",
                },
                {
                    "id": "vuln-0002",
                    "title": "远程代码执行",
                    "severity": "critical",
                    "target": "https://app.example.com/api",
                    "cvss": 9.8,
                    "cve": "CVE-2026-1234",
                    "cwe": "CWE-78",
                },
                {
                    "id": "vuln-0003",
                    "title": "信息泄露",
                    "severity": "low",
                    "endpoint": "https://app.example.com/debug",
                },
                {
                    "id": "vuln-0004",
                    "title": "越权访问",
                    "severity": "high",
                    "target": "https://app.example.com/admin",
                },
            ],
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    return root


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="strix local")
    subparsers = parser.add_subparsers(dest="command")
    notify.register(subparsers)
    return parser


def _args(*argv: str) -> argparse.Namespace:
    return _parser().parse_args(["notify", *argv])


def _run_id_args(runs_root: Path, *extra: str) -> list[str]:
    return [
        "--from-run",
        "run-abc123",
        "--runs-dir",
        str(runs_root),
        *extra,
    ]


def _install_post(
    monkeypatch: pytest.MonkeyPatch,
    response: FakeResponse,
) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    def fake_post(url: str, **kwargs: Any) -> FakeResponse:
        calls.append({"url": url, **kwargs})
        return response

    monkeypatch.setattr(notify.requests, "post", fake_post)
    return calls


def test_register_adds_notify_command_with_all_options(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        _parser().parse_args(["notify", "--help"])
    assert exc_info.value.code == 0
    output = capsys.readouterr().out
    for option in ("--from-run", "--to", "--dry-run", "--json", "--runs-dir", "--project"):
        assert option in output
    for target in ("slack", "jira", "linear"):
        assert target in output


def test_dry_run_builds_summary_without_network_or_state(
    runs_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def boom(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("--dry-run 不应发起网络请求")

    monkeypatch.setattr(notify.requests, "post", boom)

    code = notify.run(_args(*_run_id_args(runs_root, "--to", "slack", "--dry-run", "--json")))

    assert code == 0
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is True
    assert result["dry_run"] is True
    assert result["request"]["method"] == "POST"
    assert result["request"]["url"] == "$SLACK_WEBHOOK_URL"
    assert result["request"]["body"]["text"].startswith("【Strix 渗透测试摘要】")
    summary = result["summary"]
    assert summary["severity_counts"] == {
        "critical": 1,
        "high": 1,
        "medium": 1,
        "low": 1,
        "info": 0,
        "unknown": 0,
    }
    assert [finding["severity"] for finding in summary["findings"]] == [
        "critical",
        "high",
        "medium",
        "low",
    ]
    assert summary["findings"][0]["cve"] == "CVE-2026-1234"
    assert summary["findings"][0]["cvss"] == "9.8"
    assert "【Strix 渗透测试摘要】" in result["request"]["body"]["text"]
    assert "严重 1" in result["request"]["body"]["text"]
    assert not (Path(os.environ["STRIX_LOCAL_HOME"])).exists()


def test_dry_run_human_output_prints_request_body(
    runs_root: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = notify.run(_args(*_run_id_args(runs_root, "--to", "jira", "--dry-run")))

    assert code == 0
    output = capsys.readouterr().out
    assert "请求预览（Jira，未发送）" in output
    assert '"fields"' in output
    assert "https://app.example.com" in output


def test_run_can_be_addressed_by_run_json_path(
    runs_root: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run_json = runs_root / "run-abc123" / "run.json"

    code = notify.run(
        _args(
            "--from-run",
            str(run_json),
            "--to",
            "slack",
            "--dry-run",
            "--json",
        ),
    )

    assert code == 0
    assert json.loads(capsys.readouterr().out)["run_id"] == "run-abc123"


def test_run_can_be_found_through_local_runs_index(
    runs_root: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    index = Path(os.environ["STRIX_LOCAL_HOME"]) / "runs.jsonl"
    index.parent.mkdir(parents=True)
    index.write_text(
        json.dumps(
            {
                "run_id": "run-abc123",
                "run_dir": str(runs_root / "run-abc123"),
            },
        )
        + "\n",
        encoding="utf-8",
    )
    empty = tmp_path / "empty-runs"
    empty.mkdir()

    code = notify.run(
        _args("--from-run", "run-abc123", "--runs-dir", str(empty), "--to", "slack", "--dry-run"),
    )

    assert code == 0
    assert "【Strix 渗透测试摘要】" in capsys.readouterr().out


def test_unknown_run_is_a_chinese_error(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    empty = tmp_path / "empty-runs"
    empty.mkdir()

    code = notify.run(
        _args("--from-run", "run-missing", "--runs-dir", str(empty), "--to", "slack", "--json"),
    )

    assert code == 2
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is False
    assert result["code"] == "run_not_found"
    assert "找不到运行 run-missing" in result["error"]


def test_missing_slack_webhook_fails_without_writing_state(
    runs_root: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = notify.run(_args(*_run_id_args(runs_root, "--to", "slack", "--json")))

    assert code == 2
    result = json.loads(capsys.readouterr().out)
    assert result["code"] == "missing_credentials"
    assert "SLACK_WEBHOOK_URL" in result["error"]
    assert "不会写入磁盘" in result["error"]
    assert not Path(os.environ["STRIX_LOCAL_HOME"]).exists()


def test_missing_slack_webhook_without_json_goes_to_stderr(
    runs_root: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = notify.run(_args(*_run_id_args(runs_root, "--to", "slack")))

    assert code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "错误：缺少 Slack 凭据" in captured.err


def test_slack_send_posts_webhook_and_redacts_url(
    runs_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    webhook = "https://hooks.slack.com/services/T000/B000/secret-webhook-path"
    monkeypatch.setenv("SLACK_WEBHOOK_URL", webhook)
    calls = _install_post(monkeypatch, FakeResponse(text="ok"))

    code = notify.run(_args(*_run_id_args(runs_root, "--to", "slack", "--json")))

    assert code == 0
    assert len(calls) == 1
    assert calls[0]["url"] == webhook
    assert calls[0]["timeout"] == notify.HTTP_TIMEOUT_SECONDS
    assert calls[0]["auth"] is None
    assert calls[0]["json"]["text"].startswith("【Strix 渗透测试摘要】")
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is True
    assert result["response"]["status_code"] == 200
    assert result["request"]["url"] == "https://hooks.slack.com/***"
    assert "secret-webhook-path" not in json.dumps(result, ensure_ascii=False)


def test_slack_http_error_is_reported_with_status(
    runs_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/T/B/x")
    _install_post(monkeypatch, FakeResponse(status_code=500, text="server error"))

    code = notify.run(_args(*_run_id_args(runs_root, "--to", "slack", "--json")))

    assert code == 1
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is False
    assert result["code"] == "http_error"
    assert result["status_code"] == 500
    assert "HTTP 500" in result["error"]


def test_slack_connection_error_redacts_webhook_token(
    runs_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    webhook = "https://hooks.slack.com/services/T000/B000/secret-webhook-path"
    monkeypatch.setenv("SLACK_WEBHOOK_URL", webhook)

    def fail(url: str, **_kwargs: Any) -> None:
        raise notify.requests.ConnectionError(f"Max retries exceeded with url: {url}")

    monkeypatch.setattr(notify.requests, "post", fail)

    code = notify.run(_args(*_run_id_args(runs_root, "--to", "slack", "--json")))

    assert code == 1
    output = capsys.readouterr().out
    assert "secret-webhook-path" not in output
    assert "hooks.slack.com/***" in output


def test_jira_requires_project_key(
    runs_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("JIRA_BASE_URL", "https://jira.example.com")
    monkeypatch.setenv("JIRA_EMAIL", "dev@example.com")
    monkeypatch.setenv("JIRA_TOKEN", "credential-value")

    code = notify.run(_args(*_run_id_args(runs_root, "--to", "jira", "--json")))

    assert code == 2
    result = json.loads(capsys.readouterr().out)
    assert result["code"] == "missing_credentials"
    assert "JIRA_PROJECT_KEY" in result["error"]


def test_jira_send_uses_rest_v3_basic_auth_and_adf(
    runs_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("JIRA_BASE_URL", "https://jira.example.com")
    monkeypatch.setenv("JIRA_EMAIL", "dev@example.com")
    monkeypatch.setenv("JIRA_TOKEN", "credential-value")
    calls = _install_post(
        monkeypatch,
        FakeResponse(
            status_code=201,
            payload={
                "id": "10001",
                "key": "SEC-42",
                "self": "https://jira.example.com/rest/api/3/issue/10001",
            },
        ),
    )

    code = notify.run(
        _args(
            *_run_id_args(runs_root, "--to", "jira", "--json"),
            "--project",
            "SEC",
            "--issue-type",
            "Bug",
        ),
    )

    assert code == 0
    assert calls[0]["url"] == "https://jira.example.com/rest/api/3/issue"
    assert calls[0]["auth"] == ("dev@example.com", "credential-value")
    assert calls[0]["headers"]["Accept"] == "application/json"
    fields = calls[0]["json"]["fields"]
    assert fields["project"] == {"key": "SEC"}
    assert fields["issuetype"] == {"name": "Bug"}
    assert "run-abc123" in fields["summary"]
    assert fields["description"]["type"] == "doc"
    assert fields["description"]["version"] == 1
    assert "远程代码执行" in json.dumps(fields["description"], ensure_ascii=False)

    result = json.loads(capsys.readouterr().out)
    assert result["response"]["issue_key"] == "SEC-42"
    assert "credential-value" not in json.dumps(result, ensure_ascii=False)


def test_jira_rejects_invalid_base_url(
    runs_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("JIRA_BASE_URL", "jira.example.com")
    monkeypatch.setenv("JIRA_EMAIL", "dev@example.com")
    monkeypatch.setenv("JIRA_TOKEN", "credential-value")

    code = notify.run(
        _args(*_run_id_args(runs_root, "--to", "jira", "--json"), "--project", "SEC"),
    )

    assert code == 2
    result = json.loads(capsys.readouterr().out)
    assert result["code"] == "invalid_argument"
    assert "JIRA_BASE_URL" in result["error"]


def test_linear_send_uses_graphql_issue_create(
    runs_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("LINEAR_API_KEY", "lin_api_credential")
    monkeypatch.setenv("LINEAR_TEAM_ID", "team-123")
    calls = _install_post(
        monkeypatch,
        FakeResponse(
            payload={
                "data": {
                    "issueCreate": {
                        "success": True,
                        "issue": {
                            "id": "uuid-1",
                            "identifier": "SEC-7",
                            "url": "https://linear.app/acme/issue/SEC-7",
                        },
                    },
                },
            },
        ),
    )

    code = notify.run(_args(*_run_id_args(runs_root, "--to", "linear", "--json")))

    assert code == 0
    assert calls[0]["url"] == notify.LINEAR_GRAPHQL_URL
    assert calls[0]["headers"]["Authorization"] == "lin_api_credential"
    assert "issueCreate" in calls[0]["json"]["query"]
    variables = calls[0]["json"]["variables"]["input"]
    assert variables["teamId"] == "team-123"
    assert "run-abc123" in variables["title"]
    assert "远程代码执行" in variables["description"]

    result = json.loads(capsys.readouterr().out)
    assert result["response"]["issue_key"] == "SEC-7"
    assert "lin_api_credential" not in json.dumps(result, ensure_ascii=False)


def test_linear_graphql_errors_fail_loudly(
    runs_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("LINEAR_API_KEY", "lin_api_credential")
    monkeypatch.setenv("LINEAR_TEAM_ID", "team-123")
    _install_post(
        monkeypatch,
        FakeResponse(payload={"errors": [{"message": "团队不存在"}]}),
    )

    code = notify.run(_args(*_run_id_args(runs_root, "--to", "linear", "--json")))

    assert code == 1
    result = json.loads(capsys.readouterr().out)
    assert result["code"] == "http_error"
    assert "团队不存在" in result["error"]


def test_linear_reports_unsuccessful_create(
    runs_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("LINEAR_API_KEY", "lin_api_credential")
    monkeypatch.setenv("LINEAR_TEAM_ID", "team-123")
    _install_post(
        monkeypatch,
        FakeResponse(payload={"data": {"issueCreate": {"success": False, "issue": None}}}),
    )

    code = notify.run(_args(*_run_id_args(runs_root, "--to", "linear", "--json")))

    assert code == 1
    assert json.loads(capsys.readouterr().out)["code"] == "invalid_response"


def test_max_findings_limits_list_and_reports_omitted(
    runs_root: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = notify.run(
        _args(
            *_run_id_args(runs_root, "--to", "slack", "--dry-run", "--json"),
            "--max-findings",
            "2",
        ),
    )

    assert code == 0
    summary = json.loads(capsys.readouterr().out)["summary"]
    assert len(summary["findings"]) == 2
    assert summary["omitted_findings"] == 2
    assert summary["findings_total"] == 4


def test_max_findings_zero_lists_everything(
    runs_root: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = notify.run(
        _args(
            *_run_id_args(runs_root, "--to", "slack", "--dry-run", "--json"),
            "--max-findings",
            "0",
        ),
    )

    assert code == 0
    summary = json.loads(capsys.readouterr().out)["summary"]
    assert len(summary["findings"]) == 4
    assert summary["omitted_findings"] == 0


def test_corrupt_vulnerabilities_json_is_a_read_error(
    runs_root: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (runs_root / "run-abc123" / "vulnerabilities.json").write_text("{not json", encoding="utf-8")

    code = notify.run(_args(*_run_id_args(runs_root, "--to", "slack", "--dry-run", "--json")))

    assert code == 1
    result = json.loads(capsys.readouterr().out)
    assert result["code"] == "read_error"
    assert "不是有效的 JSON" in result["error"]


def test_unknown_target_is_rejected_before_reading_runs(
    capsys: pytest.CaptureFixture[str],
) -> None:
    args = argparse.Namespace(from_run="run-abc123", to="email", json=True)

    code = notify.run(args)

    assert code == 2
    result = json.loads(capsys.readouterr().out)
    assert result["code"] == "invalid_argument"
    assert "slack、jira、linear" in result["error"]


def test_local_home_honours_environment_override(tmp_path: Path) -> None:
    assert notify.local_home() == tmp_path / "local-home"

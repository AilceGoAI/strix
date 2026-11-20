"""Local-edition three-way notifications: Slack, Jira, and Linear.

Credentials are read from environment variables only and never persisted:

- Slack: ``SLACK_WEBHOOK_URL`` (incoming webhook)
- Jira: ``JIRA_BASE_URL`` + ``JIRA_EMAIL`` + ``JIRA_TOKEN`` (REST v3, HTTP Basic),
  plus ``JIRA_PROJECT_KEY`` or ``--project`` for the target project
- Linear: ``LINEAR_API_KEY`` + ``LINEAR_TEAM_ID`` (GraphQL ``issueCreate``)
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import requests


if TYPE_CHECKING:
    import argparse
    from argparse import _SubParsersAction


TARGET_LABELS = {"slack": "Slack", "jira": "Jira", "linear": "Linear"}

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info", "unknown")
SEVERITY_LABELS = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "信息",
    "unknown": "未知",
}

STATUS_LABELS = {
    "running": "运行中",
    "in_progress": "运行中",
    "completed": "已完成",
    "complete": "已完成",
    "failed": "失败",
    "error": "失败",
    "stopped": "已停止",
    "cancelled": "已取消",
    "canceled": "已取消",
    "unknown": "未知",
}

LINEAR_GRAPHQL_URL = "https://api.linear.app/graphql"
LINEAR_ISSUE_MUTATION = """mutation StrixIssueCreate($input: IssueCreateInput!) {
  issueCreate(input: $input) {
    success
    issue {
      id
      identifier
      url
    }
  }
}"""

HTTP_TIMEOUT_SECONDS = 20
MAX_MESSAGE_CHARS = 3800
MAX_TITLE_CHARS = 250
MAX_RESPONSE_PREVIEW = 300


class NotifyError(Exception):
    """A user-facing failure carrying a machine-readable code and exit status."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "error",
        exit_code: int = 1,
        status_code: int | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.exit_code = exit_code
        self.status_code = status_code


@dataclass(frozen=True)
class Finding:
    id: str
    title: str
    severity: str
    target: str
    cvss: str
    cve: str
    cwe: str


@dataclass(frozen=True)
class RunSnapshot:
    run_dir: Path
    run_id: str
    run_name: str
    status: str
    started_at: str
    ended_at: str
    targets: tuple[str, ...]
    cost: str
    findings: tuple[Finding, ...]


@dataclass(frozen=True)
class RequestPlan:
    target: str
    url: str
    headers: dict[str, str]
    body: dict[str, Any]
    auth: tuple[str, str] | None = None
    api_key: str | None = None


def local_home() -> Path:
    """The local state root, overridable with ``STRIX_LOCAL_HOME`` for tests."""
    override = os.environ.get("STRIX_LOCAL_HOME", "").strip()
    return Path(override).expanduser() if override else Path.home() / ".strix" / "local"


def register(subparsers: _SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser(
        "notify",
        help="把一次运行的发现摘要推送到 Slack、Jira 或 Linear",
        description=(
            "从 strix_runs/<run_id>/run.json 与 vulnerabilities.json 生成中文摘要，"
            "推送到 Slack incoming webhook、Jira REST v3 或 Linear GraphQL。"
            "凭据只从环境变量读取。"
        ),
    )
    parser.add_argument(
        "--from-run",
        required=True,
        metavar="RUN_ID",
        help="运行 ID 或运行目录路径（目录需包含 run.json）",
    )
    parser.add_argument(
        "--to",
        required=True,
        choices=("slack", "jira", "linear"),
        metavar="{slack,jira,linear}",
        help="通知目标",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="只打印将要发送的请求体，不发起网络请求",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="以 JSON 输出，便于脚本消费",
    )
    parser.add_argument(
        "--runs-dir",
        metavar="DIR",
        default=None,
        help="运行目录的父目录（默认 ./strix_runs）",
    )
    parser.add_argument(
        "--max-findings",
        type=int,
        default=20,
        metavar="N",
        help="摘要中最多列出多少个发现（默认 20，0 表示全部）",
    )
    parser.add_argument(
        "--project",
        metavar="KEY",
        default=None,
        help="Jira 项目键（默认读 JIRA_PROJECT_KEY）",
    )
    parser.add_argument(
        "--issue-type",
        metavar="NAME",
        default=None,
        help="Jira 工单类型（默认读 JIRA_ISSUE_TYPE，再回退到 Task）",
    )
    parser.set_defaults(func=run)


def run(args: argparse.Namespace) -> int:
    as_json = bool(getattr(args, "json", False))
    try:
        run_id, target, max_findings = _request_options(args)
        run_dir = _locate_run(run_id, getattr(args, "runs_dir", None))
        snapshot = _load_snapshot(run_dir)
        summary = summarize(snapshot, max_findings=max_findings)
        dry_run = bool(getattr(args, "dry_run", False))
        plan = _build_plan(target, summary, args, require_credentials=not dry_run)
        request_view = _request_view(plan)

        if dry_run:
            result: dict[str, Any] = {
                "ok": True,
                "dry_run": True,
                "target": target,
                "run_id": summary["run_id"],
                "run_dir": str(snapshot.run_dir),
                "summary": summary,
                "request": request_view,
            }
            _emit(
                result,
                as_json=as_json,
                human=_dry_run_text(target, summary, plan),
            )
            return 0

        delivery = _send(plan)
    except NotifyError as exc:
        return _fail(exc, as_json=as_json)

    result = {
        "ok": True,
        "dry_run": False,
        "target": target,
        "run_id": summary["run_id"],
        "run_dir": str(snapshot.run_dir),
        "summary": summary,
        "request": request_view,
        "response": delivery,
    }
    _emit(
        result,
        as_json=as_json,
        human=_success_text(target, summary, delivery),
    )
    return 0


def _request_options(args: argparse.Namespace) -> tuple[str, str, int]:
    run_id = str(getattr(args, "from_run", "") or "").strip()
    target = str(getattr(args, "to", "") or "").strip().lower()
    if not run_id:
        raise NotifyError("缺少 --from-run 参数。", code="invalid_argument", exit_code=2)
    if target not in TARGET_LABELS:
        raise NotifyError(
            f"不支持的 --to 目标：{target or '（空）'}；可选值为 slack、jira、linear。",
            code="invalid_argument",
            exit_code=2,
        )

    max_findings = getattr(args, "max_findings", 20)
    if not isinstance(max_findings, int) or isinstance(max_findings, bool) or max_findings < 0:
        raise NotifyError(
            "--max-findings 必须是不小于 0 的整数。",
            code="invalid_argument",
            exit_code=2,
        )
    return run_id, target, max_findings


def _locate_run(run_id: str, runs_dir: str | None) -> Path:
    run_dir = _find_run_dir(run_id, runs_dir)
    if run_dir is None:
        raise NotifyError(
            f"找不到运行 {run_id}。请在 strix_runs/ 下确认运行 ID，"
            f"或用 --runs-dir 指定运行目录的父目录。",
            code="run_not_found",
            exit_code=2,
        )
    return run_dir


def summarize(snapshot: RunSnapshot, *, max_findings: int) -> dict[str, Any]:
    ordered = sorted(
        snapshot.findings,
        key=lambda finding: (
            SEVERITY_ORDER.index(finding.severity)
            if finding.severity in SEVERITY_ORDER
            else len(SEVERITY_ORDER),
            finding.title.casefold(),
        ),
    )
    counts = dict.fromkeys(SEVERITY_ORDER, 0)
    for finding in snapshot.findings:
        key = finding.severity if finding.severity in counts else "unknown"
        counts[key] += 1

    shown = ordered if max_findings == 0 else ordered[:max_findings]
    return {
        "run_id": snapshot.run_id,
        "run_name": snapshot.run_name,
        "status": snapshot.status,
        "status_label": STATUS_LABELS.get(snapshot.status, snapshot.status or "未知"),
        "started_at": snapshot.started_at,
        "ended_at": snapshot.ended_at,
        "targets": list(snapshot.targets),
        "cost": snapshot.cost,
        "findings_total": len(snapshot.findings),
        "severity_counts": counts,
        "findings": [_finding_dict(finding) for finding in shown],
        "omitted_findings": max(0, len(ordered) - len(shown)),
    }


def render_text(summary: dict[str, Any]) -> str:
    """The plain-text summary shared by Slack and Linear (Markdown-compatible)."""
    lines = ["【Strix 渗透测试摘要】"]
    run_name = summary.get("run_name")
    run_label = summary["run_id"]
    if run_name and run_name != run_label:
        run_label = f"{run_label}（{run_name}）"
    lines.append(f"运行：{run_label}｜状态：{summary['status_label']}")

    targets_line = _targets_line(summary.get("targets") or [])
    if targets_line:
        lines.append(f"目标：{targets_line}")

    started = summary.get("started_at") or "未知"
    ended = summary.get("ended_at") or "未结束"
    lines.append(f"时间：{started} ～ {ended}")

    if summary.get("cost"):
        lines.append(f"模型成本：${summary['cost']}")

    total = int(summary.get("findings_total") or 0)
    counts = summary.get("severity_counts") or {}
    if total:
        lines.append(f"发现：共 {total} 个（{_counts_line(counts)}）")
        lines.extend(_finding_lines(summary.get("findings") or []))
        omitted = int(summary.get("omitted_findings") or 0)
        if omitted:
            lines.append(f"另有 {omitted} 个发现未列出。")
    else:
        lines.append("发现：未记录漏洞。")

    lines.append("")
    lines.append("由 Strix 本地版自动生成。")
    return _clip("\n".join(lines), MAX_MESSAGE_CHARS)


def _finding_lines(findings: list[dict[str, Any]]) -> list[str]:
    lines = []
    for index, finding in enumerate(findings, start=1):
        severity = str(finding.get("severity") or "unknown")
        label = SEVERITY_LABELS.get(severity, severity or "未知")
        where = f" @ {finding['target']}" if finding.get("target") else ""
        extras = [
            value
            for value in (
                f"CVSS {finding['cvss']}" if finding.get("cvss") else "",
                str(finding.get("cve") or ""),
                str(finding.get("cwe") or ""),
            )
            if value
        ]
        suffix = f"（{'；'.join(extras)}）" if extras else ""
        lines.append(f"{index}. [{label}] {finding.get('title') or '（无标题）'}{where}{suffix}")
    return lines


def _counts_line(counts: dict[str, Any]) -> str:
    parts = []
    for key in SEVERITY_ORDER:
        value = int(counts.get(key) or 0)
        if value or key != "unknown":
            parts.append(f"{SEVERITY_LABELS[key]} {value}")
    return "、".join(parts)


def _targets_line(targets: list[str]) -> str:
    if not targets:
        return ""
    if len(targets) <= 3:
        return "、".join(targets)
    return "、".join(targets[:3]) + f" 等 {len(targets)} 个目标"


def _finding_dict(finding: Finding) -> dict[str, str]:
    return {
        "id": finding.id,
        "title": finding.title,
        "severity": finding.severity,
        "severity_label": SEVERITY_LABELS.get(finding.severity, finding.severity),
        "target": finding.target,
        "cvss": finding.cvss,
        "cve": finding.cve,
        "cwe": finding.cwe,
    }


def _find_run_dir(run_id: str, runs_dir: str | None) -> Path | None:
    candidate = Path(run_id).expanduser()
    if candidate.is_file() and candidate.name == "run.json":
        candidate = candidate.parent
    if candidate.is_dir() and (candidate / "run.json").is_file():
        return candidate

    base = Path(runs_dir).expanduser() if runs_dir else Path.cwd() / "strix_runs"
    direct = base / run_id
    if (direct / "run.json").is_file():
        return direct

    if base.is_dir():
        for child in sorted(base.iterdir()):
            record_path = child / "run.json"
            if not record_path.is_file():
                continue
            record = _read_json(record_path, missing_ok=True)
            if isinstance(record, dict) and str(record.get("run_id") or "") == run_id:
                return child

    return _run_dir_from_index(run_id)


def _run_dir_from_index(run_id: str) -> Path | None:
    """Look up a run in ``~/.strix/local/runs.jsonl`` written by the runs module."""
    index_path = local_home() / "runs.jsonl"
    try:
        lines = index_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return None
    for line in reversed(lines):
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            continue
        if str(row.get("run_id") or row.get("id") or "") != run_id:
            continue
        for key in ("run_dir", "path", "directory"):
            raw = row.get(key)
            if isinstance(raw, str) and raw.strip():
                candidate = Path(raw).expanduser()
                if (candidate / "run.json").is_file():
                    return candidate
    return None


def _load_snapshot(run_dir: Path) -> RunSnapshot:
    record = _load_object(run_dir / "run.json", label="run.json")
    findings_raw = _load_findings(run_dir / "vulnerabilities.json")

    targets = _targets_from_record(record)
    return RunSnapshot(
        run_dir=run_dir,
        run_id=_one_line(record.get("run_id")) or run_dir.name,
        run_name=_one_line(record.get("run_name")),
        status=_one_line(record.get("status")).lower() or "unknown",
        started_at=_one_line(record.get("start_time")),
        ended_at=_one_line(record.get("end_time")),
        targets=targets,
        cost=_cost_from_record(record),
        findings=tuple(_finding_from_raw(item) for item in findings_raw),
    )


def _load_object(path: Path, *, label: str) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise NotifyError(f"无法读取 {path}（{label}）：{exc}", code="read_error") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise NotifyError(f"{path} 不是有效的 JSON：{exc}", code="read_error") from exc
    if not isinstance(data, dict):
        raise NotifyError(f"{path} 的顶层不是 JSON 对象。", code="read_error")
    return data


def _load_findings(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise NotifyError(f"无法读取 {path}（vulnerabilities.json）：{exc}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise NotifyError(
            f"{path} 不是有效的 JSON：{exc}",
            code="read_error",
        ) from exc
    if not isinstance(data, list):
        raise NotifyError(f"{path} 的顶层不是 JSON 列表。", code="read_error")
    return [item for item in data if isinstance(item, dict)]


def _read_json(path: Path, *, missing_ok: bool) -> Any:
    if missing_ok and not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def _targets_from_record(record: dict[str, Any]) -> tuple[str, ...]:
    found: list[str] = []
    entries = record.get("targets_info")
    if isinstance(entries, list):
        for entry in entries:
            if isinstance(entry, dict):
                original = entry.get("original")
                if isinstance(original, str) and original.strip():
                    found.append(original.strip())
    if not found:
        mount = record.get("workspace_mount")
        if isinstance(mount, str) and mount.strip():
            found.append(f"{mount.strip()}（工作区）")
    if not found:
        instruction = _one_line(record.get("user_instruction") or record.get("instruction"))
        if instruction:
            found.append(instruction)
    return tuple(dict.fromkeys(found))


def _cost_from_record(record: dict[str, Any]) -> str:
    usage = record.get("llm_usage")
    if not isinstance(usage, dict):
        return ""
    raw = usage.get("cost")
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        return ""
    return f"{float(raw):.4f}"


def _finding_from_raw(raw: dict[str, Any]) -> Finding:
    return Finding(
        id=_one_line(raw.get("id")),
        title=_one_line(raw.get("title")) or "（无标题）",
        severity=_one_line(raw.get("severity")).lower() or "unknown",
        target=_one_line(raw.get("target") or raw.get("endpoint")),
        cvss=_format_number(raw.get("cvss")),
        cve=_one_line(raw.get("cve")),
        cwe=_one_line(raw.get("cwe")),
    )


def _build_plan(
    target: str,
    summary: dict[str, Any],
    args: argparse.Namespace,
    *,
    require_credentials: bool,
) -> RequestPlan:
    if target == "slack":
        return _slack_plan(summary, require_credentials=require_credentials)
    if target == "jira":
        return _jira_plan(summary, args, require_credentials=require_credentials)
    return _linear_plan(summary, require_credentials=require_credentials)


def _slack_plan(summary: dict[str, Any], *, require_credentials: bool) -> RequestPlan:
    webhook = os.environ.get("SLACK_WEBHOOK_URL", "").strip()
    if require_credentials and not webhook:
        _raise_missing("Slack", ["SLACK_WEBHOOK_URL"])
    return RequestPlan(
        target="slack",
        url=webhook or "$SLACK_WEBHOOK_URL",
        headers={"Content-Type": "application/json"},
        body={"text": render_text(summary)},
    )


def _jira_plan(
    summary: dict[str, Any],
    args: argparse.Namespace,
    *,
    require_credentials: bool,
) -> RequestPlan:
    base_url = os.environ.get("JIRA_BASE_URL", "").strip()
    email = os.environ.get("JIRA_EMAIL", "").strip()
    token = os.environ.get("JIRA_TOKEN", "").strip()
    project = (
        str(getattr(args, "project", "") or "").strip()
        or os.environ.get("JIRA_PROJECT_KEY", "").strip()
    )
    issue_type = (
        str(getattr(args, "issue_type", "") or "").strip()
        or os.environ.get("JIRA_ISSUE_TYPE", "").strip()
        or "Task"
    )

    if require_credentials:
        missing = [
            name
            for name, value in (
                ("JIRA_BASE_URL", base_url),
                ("JIRA_EMAIL", email),
                ("JIRA_TOKEN", token),
            )
            if not value
        ]
        if not project:
            missing.append("JIRA_PROJECT_KEY（或 --project）")
        if missing:
            _raise_missing("Jira", missing)

    if base_url:
        parsed = urlsplit(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise NotifyError(
                f"JIRA_BASE_URL 不是有效的 http(s) 地址：{base_url}",
                code="invalid_argument",
                exit_code=2,
            )

    url = (
        f"{base_url.rstrip('/')}/rest/api/3/issue"
        if base_url
        else "$JIRA_BASE_URL/rest/api/3/issue"
    )
    auth = (email, token) if email and token else None
    return RequestPlan(
        target="jira",
        url=url,
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        body={
            "fields": {
                "project": {"key": project or "$JIRA_PROJECT_KEY"},
                "summary": _issue_title(summary),
                "issuetype": {"name": issue_type},
                "description": _adf_document(summary),
            },
        },
        auth=auth,
    )


def _linear_plan(summary: dict[str, Any], *, require_credentials: bool) -> RequestPlan:
    api_key = os.environ.get("LINEAR_API_KEY", "").strip()
    team_id = os.environ.get("LINEAR_TEAM_ID", "").strip()
    if require_credentials:
        missing = [
            name
            for name, value in (
                ("LINEAR_API_KEY", api_key),
                ("LINEAR_TEAM_ID", team_id),
            )
            if not value
        ]
        if missing:
            _raise_missing("Linear", missing)

    return RequestPlan(
        target="linear",
        url=LINEAR_GRAPHQL_URL,
        headers={"Content-Type": "application/json"},
        body={
            "query": LINEAR_ISSUE_MUTATION,
            "variables": {
                "input": {
                    "teamId": team_id or "$LINEAR_TEAM_ID",
                    "title": _issue_title(summary),
                    "description": render_text(summary),
                },
            },
        },
        api_key=api_key or None,
    )


def _raise_missing(target_label: str, missing: list[str]) -> None:
    raise NotifyError(
        f"缺少 {target_label} 凭据或配置：{'、'.join(missing)}。"
        f"这些值只从环境变量读取，不会写入磁盘。",
        code="missing_credentials",
        exit_code=2,
    )


def _issue_title(summary: dict[str, Any]) -> str:
    total = int(summary.get("findings_total") or 0)
    suffix = f"{total} 个发现" if total else "无发现"
    return _clip(f"Strix 扫描摘要：{summary['run_id']}（{suffix}）", MAX_TITLE_CHARS)


def _adf_document(summary: dict[str, Any]) -> dict[str, Any]:
    """The Jira REST v3 description as an Atlassian Document Format tree."""
    content: list[dict[str, Any]] = [
        _paragraph(f"运行：{summary['run_id']}｜状态：{summary['status_label']}"),
    ]
    targets_line = _targets_line(summary.get("targets") or [])
    if targets_line:
        content.append(_paragraph(f"目标：{targets_line}"))
    content.append(
        _paragraph(
            f"时间：{summary.get('started_at') or '未知'} ～ {summary.get('ended_at') or '未结束'}",
        ),
    )
    if summary.get("cost"):
        content.append(_paragraph(f"模型成本：${summary['cost']}"))

    total = int(summary.get("findings_total") or 0)
    if total:
        content.append(
            _paragraph(
                f"发现：共 {total} 个（{_counts_line(summary.get('severity_counts') or {})}）",
            ),
        )
        items = [
            {"type": "listItem", "content": [_paragraph(line)]}
            for line in _finding_lines(summary.get("findings") or [])
        ]
        content.append(
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": "主要发现：", "marks": [{"type": "strong"}]}],
            },
        )
        content.append({"type": "orderedList", "content": items})
        omitted = int(summary.get("omitted_findings") or 0)
        if omitted:
            content.append(_paragraph(f"另有 {omitted} 个发现未列出。"))
    else:
        content.append(_paragraph("发现：未记录漏洞。"))

    content.append(_paragraph("由 Strix 本地版自动生成。"))
    return {"type": "doc", "version": 1, "content": content}


def _paragraph(text: str) -> dict[str, Any]:
    return {"type": "paragraph", "content": [{"type": "text", "text": text}]}


def _request_view(plan: RequestPlan) -> dict[str, Any]:
    auth_kind = "basic" if plan.auth else ("api_key" if plan.api_key else "none")
    return {
        "method": "POST",
        "url": _display_url(plan),
        "headers": dict(plan.headers),
        "auth": auth_kind,
        "body": plan.body,
    }


def _display_url(plan: RequestPlan) -> str:
    if plan.target == "slack" and plan.url.startswith(("http://", "https://")):
        parsed = urlsplit(plan.url)
        return f"{parsed.scheme}://{parsed.netloc}/***"
    return plan.url


def _error_detail(plan: RequestPlan, exc: Exception) -> str:
    """Keep the Slack webhook token out of connection-error text."""
    text = str(exc)
    if plan.target == "slack" and plan.url.startswith(("http://", "https://")):
        parsed = urlsplit(plan.url)
        text = text.replace(plan.url, _display_url(plan))
        if parsed.path:
            text = text.replace(parsed.path, "/***")
    return text


def _send(plan: RequestPlan) -> dict[str, Any]:
    headers = dict(plan.headers)
    if plan.api_key:
        headers["Authorization"] = plan.api_key
    try:
        response = requests.post(
            plan.url,
            json=plan.body,
            headers=headers,
            auth=plan.auth,
            timeout=HTTP_TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:
        raise NotifyError(
            f"请求 {TARGET_LABELS[plan.target]} 失败：{_error_detail(plan, exc)}",
            code="http_error",
        ) from exc

    if response.status_code >= 400:
        preview = _clip(
            _one_line(response.text, preserve_newlines=True) or "（空响应）",
            MAX_RESPONSE_PREVIEW,
        )
        raise NotifyError(
            f"{TARGET_LABELS[plan.target]} 返回 HTTP {response.status_code}：{preview}",
            code="http_error",
            status_code=response.status_code,
        )

    payload = _response_json(response)
    if plan.target == "jira":
        issue_key = str(payload.get("key") or "")
        return {
            "status_code": response.status_code,
            "issue_key": issue_key,
            "issue_url": str(payload.get("self") or ""),
            "detail": f"已创建 Jira 工单 {issue_key}。" if issue_key else "Jira 已接受请求。",
        }
    if plan.target == "linear":
        return _linear_delivery(response.status_code, payload)
    return {
        "status_code": response.status_code,
        "detail": _one_line(response.text) or "ok",
    }


def _linear_delivery(status_code: int, payload: dict[str, Any]) -> dict[str, Any]:
    errors = payload.get("errors")
    if isinstance(errors, list) and errors:
        messages = [
            str(item.get("message"))
            for item in errors
            if isinstance(item, dict) and item.get("message")
        ]
        raise NotifyError(
            "Linear GraphQL 返回错误：" + ("；".join(messages) or "未知错误"),
            code="http_error",
            status_code=status_code,
        )
    data = payload.get("data")
    create = data.get("issueCreate") if isinstance(data, dict) else None
    if not isinstance(create, dict) or not create.get("success"):
        raise NotifyError(
            "Linear 未确认工单创建成功（issueCreate.success 不为 true）。",
            code="invalid_response",
            status_code=status_code,
        )
    issue = create.get("issue")
    issue = issue if isinstance(issue, dict) else {}
    identifier = str(issue.get("identifier") or "")
    return {
        "status_code": status_code,
        "issue_key": identifier,
        "issue_url": str(issue.get("url") or ""),
        "detail": f"已创建 Linear 工单 {identifier}。" if identifier else "Linear 已接受请求。",
    }


def _response_json(response: requests.Response) -> dict[str, Any]:
    try:
        payload = response.json()
    except ValueError:
        return {}
    return payload if isinstance(payload, dict) else {}


def _dry_run_text(target: str, summary: dict[str, Any], plan: RequestPlan) -> str:
    lines = [
        render_text(summary),
        "",
        f"请求预览（{TARGET_LABELS[target]}，未发送）：",
        f"POST {_display_url(plan)}",
    ]
    if plan.auth:
        lines.append("认证：HTTP Basic（凭据来自环境变量）")
    elif plan.api_key:
        lines.append("认证：API Key（来自环境变量）")
    lines.append(json.dumps(plan.body, ensure_ascii=False, indent=2))
    return "\n".join(lines) + "\n"


def _success_text(
    target: str,
    summary: dict[str, Any],
    delivery: dict[str, Any],
) -> str:
    detail = str(delivery.get("detail") or "")
    if not detail:
        detail = f"已发送到 {TARGET_LABELS[target]}（HTTP {delivery.get('status_code')}）。"
    return render_text(summary) + "\n\n" + detail + "\n"


def _emit(payload: dict[str, Any], *, as_json: bool, human: str) -> None:
    if as_json:
        sys.stdout.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
    else:
        sys.stdout.write(human)


def _fail(exc: NotifyError, *, as_json: bool) -> int:
    if as_json:
        payload: dict[str, Any] = {
            "ok": False,
            "error": exc.message,
            "code": exc.code,
        }
        if exc.status_code is not None:
            payload["status_code"] = exc.status_code
        sys.stdout.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
    else:
        sys.stderr.write(f"错误：{exc.message}\n")
    return exc.exit_code


def _one_line(value: object, *, preserve_newlines: bool = False) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if preserve_newlines:
        return text
    return re.sub(r"\s+", " ", text)


def _format_number(value: object) -> str:
    if isinstance(value, bool) or value is None:
        return ""
    if isinstance(value, (int, float)):
        return f"{float(value):g}"
    return _one_line(value)


def _clip(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)].rstrip() + "…"

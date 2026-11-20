# ruff: noqa: RUF002
"""``strix local serve`` — 本地只读看板服务。

只用标准库 ``http.server`` 提供四个只读接口，运行数据每次请求时直接从
``strix_runs/<id>/`` 读盘（``run.json``、``vulnerabilities.json``、
``findings.sarif``），因此同一个服务既能看已完成的运行，也能看正在写入的运行。

鉴权复用 :mod:`strix.local.users` 的 ``users.json``：请求携带
``Authorization: Bearer <token>``、``X-Strix-Token: <token>`` 或 ``?token=``
即可。未配置用户时退化为仅本机回环可用的无鉴权模式，并在启动时给出警告；
此时拒绝绑定非回环地址，避免把运行数据无鉴权暴露到网络上。

所有接口均为只读；本模块不写任何状态文件。
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import re
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, unquote, urlsplit

from strix.core.paths import RUNS_DIR_NAME, run_record_path
from strix.local.users import (
    UsersError,
    default_users_path,
    list_users,
    verify_token,
)


if TYPE_CHECKING:
    from collections.abc import Sequence


logger = logging.getLogger(__name__)

LOCAL_RUNS_DIR_ENV = "STRIX_LOCAL_RUNS_DIR"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
SEVERITIES = ("critical", "high", "medium", "low")
TERMINAL_STATUSES = frozenset({"completed", "stopped", "failed", "interrupted"})
API_ENDPOINTS = (
    "/api/health",
    "/api/runs",
    "/api/runs/<id>",
    "/api/runs/<id>/findings",
)

_RUN_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,200}$")
_RUN_DETAIL_RE = re.compile(r"^/api/runs/([^/]+)$")
_RUN_FINDINGS_RE = re.compile(r"^/api/runs/([^/]+)/findings$")


@dataclass(frozen=True)
class ServeState:
    """一次看板进程的只读配置。"""

    runs_dir: Path
    users_path: Path
    user_count: int
    started_at: str

    @property
    def auth_required(self) -> bool:
        return self.user_count > 0


class ServeError(Exception):
    """看板启动失败，携带进程退出码。"""

    def __init__(self, message: str, exit_code: int = 1) -> None:
        super().__init__(message)
        self.exit_code = exit_code


# --------------------------------------------------------------------------- 路径与数据


def resolve_runs_dir(explicit: str | Path | None = None) -> Path:
    """运行目录：``--runs-dir`` > ``STRIX_LOCAL_RUNS_DIR`` > ``./strix_runs``。"""
    if explicit:
        return Path(explicit).expanduser()
    override = os.environ.get(LOCAL_RUNS_DIR_ENV, "").strip()
    if override:
        return Path(override).expanduser()
    return Path.cwd() / RUNS_DIR_NAME


def _load_json(path: Path, *, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _load_record(run_dir: Path) -> dict[str, Any]:
    record = _load_json(run_record_path(run_dir), default={})
    return record if isinstance(record, dict) else {}


def read_findings(run_dir: Path) -> list[dict[str, Any]]:
    """``vulnerabilities.json`` 中的发现列表（缺失或损坏时为空）。"""
    data = _load_json(run_dir / "vulnerabilities.json", default=[])
    if not isinstance(data, list):
        return []
    return [item for item in data if isinstance(item, dict)]


def severity_counts(findings: Sequence[dict[str, Any]]) -> dict[str, int]:
    """按 critical/high/medium/low 分桶；其余等级并入 low。"""
    counts = dict.fromkeys(SEVERITIES, 0)
    for finding in findings:
        severity = str(finding.get("severity") or "").strip().lower()
        if severity not in counts:
            severity = "low"
        counts[severity] += 1
    return counts


def _primary_target(record: dict[str, Any]) -> str | None:
    targets = record.get("targets_info")
    if isinstance(targets, list):
        for entry in targets:
            if isinstance(entry, dict):
                original = entry.get("original")
                if isinstance(original, str) and original:
                    return original
    mount = record.get("workspace_mount")
    if isinstance(mount, str) and mount:
        return mount
    return None


def iter_run_dirs(runs_dir: Path) -> list[Path]:
    """运行目录中带 ``run.json`` 的直接子目录，按记录修改时间倒序。"""
    if not runs_dir.is_dir():
        return []
    run_dirs = [child for child in runs_dir.iterdir() if child.is_dir()]
    run_dirs = [
        child for child in run_dirs if not child.is_symlink() and run_record_path(child).is_file()
    ]
    run_dirs.sort(key=_record_mtime, reverse=True)
    return run_dirs


def _record_mtime(run_dir: Path) -> float:
    try:
        return run_record_path(run_dir).stat().st_mtime
    except OSError:
        return 0.0


def run_summary(run_dir: Path) -> dict[str, Any]:
    """运行列表中的一条摘要。"""
    record = _load_record(run_dir)
    findings = read_findings(run_dir)
    status = str(record.get("status") or "")
    return {
        "id": run_dir.name,
        "name": str(record.get("run_name") or run_dir.name),
        "target": _primary_target(record),
        "scan_mode": record.get("scan_mode"),
        "status": status or None,
        "start_time": record.get("start_time"),
        "end_time": record.get("end_time"),
        "finished": status.lower() in TERMINAL_STATUSES and bool(record.get("end_time")),
        "findings_count": len(findings),
        "severity_counts": severity_counts(findings),
    }


def run_detail(run_dir: Path) -> dict[str, Any]:
    """单个运行的完整记录与产物清单（不含报告正文）。"""
    findings = read_findings(run_dir)
    vuln_dir = run_dir / "vulnerabilities"
    report_files = sorted(vuln_dir.glob("*.md")) if vuln_dir.is_dir() else []
    return {
        "run": run_summary(run_dir),
        "record": _load_record(run_dir),
        "findings_count": len(findings),
        "severity_counts": severity_counts(findings),
        "artifacts": {
            "run_record": run_record_path(run_dir).is_file(),
            "report": (run_dir / "penetration_test_report.md").is_file(),
            "findings_json": (run_dir / "vulnerabilities.json").is_file(),
            "findings_sarif": (run_dir / "findings.sarif").is_file(),
            "vulnerability_reports": len(report_files),
        },
    }


def resolve_run_dir(runs_dir: Path, run_id: str) -> Path | None:
    """把路径参数解析为运行目录；拒绝路径穿越与未知运行。"""
    if not _RUN_ID_RE.fullmatch(run_id):
        return None
    base = runs_dir.resolve()
    candidate = (base / run_id).resolve()
    if candidate.parent != base:
        return None
    if not run_record_path(candidate).is_file():
        return None
    return candidate


def is_loopback(host: str) -> bool:
    normalized = host.strip().strip("[]").lower()
    if normalized == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


# --------------------------------------------------------------------------- HTTP 处理


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _health_payload(state: ServeState) -> dict[str, Any]:
    return {
        "status": "ok",
        "service": "strix-local-serve",
        "version": 1,
        "time": _now_iso(),
        "started_at": state.started_at,
        "auth_required": state.auth_required,
        "users": state.user_count,
        "runs_dir": str(state.runs_dir),
        "endpoints": list(API_ENDPOINTS),
    }


def _make_handler(state: ServeState) -> type[BaseHTTPRequestHandler]:
    class LocalServeHandler(BaseHTTPRequestHandler):
        server_version = "StrixLocalServe/1.0"
        sys_version = ""

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            logger.debug("local serve %s - %s", self.address_string(), format % args)

        def do_GET(self) -> None:
            parts = urlsplit(self.path)
            try:
                self._route(parts.path, parse_qs(parts.query))
            except BrokenPipeError:
                logger.debug("看板客户端提前断开：%s", parts.path)
            except Exception:
                logger.exception("看板请求处理失败：%s", parts.path)
                self._send_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {"error": "internal_error", "message": "看板内部错误。"},
                )

        def do_POST(self) -> None:
            self._reject_method()

        def do_PUT(self) -> None:
            self._reject_method()

        def do_PATCH(self) -> None:
            self._reject_method()

        def do_DELETE(self) -> None:
            self._reject_method()

        def _route(self, path: str, query: dict[str, list[str]]) -> None:  # noqa: PLR0911
            if path in ("/", "/index.html"):
                self._send_html(_DASHBOARD_HTML)
                return
            if path == "/api/health":
                self._send_json(HTTPStatus.OK, _health_payload(state))
                return
            if not path.startswith("/api/"):
                self._send_json(
                    HTTPStatus.NOT_FOUND,
                    {"error": "not_found", "message": "未知路径。"},
                )
                return
            if not self._authorized(query):
                self._send_json(
                    HTTPStatus.UNAUTHORIZED,
                    {"error": "unauthorized", "message": "需要有效的访问令牌。"},
                    headers={"WWW-Authenticate": 'Bearer realm="strix-local"'},
                )
                return

            if path == "/api/runs":
                run_dirs = iter_run_dirs(state.runs_dir)
                runs = [run_summary(run_dir) for run_dir in run_dirs]
                self._send_json(
                    HTTPStatus.OK,
                    {"runs": runs, "count": len(runs), "runs_dir": str(state.runs_dir)},
                )
                return

            findings_match = _RUN_FINDINGS_RE.fullmatch(path)
            if findings_match:
                self._handle_findings(unquote(findings_match.group(1)), query)
                return

            detail_match = _RUN_DETAIL_RE.fullmatch(path)
            if detail_match:
                run_dir = resolve_run_dir(state.runs_dir, unquote(detail_match.group(1)))
                if run_dir is None:
                    self._unknown_run()
                    return
                self._send_json(HTTPStatus.OK, run_detail(run_dir))
                return

            self._send_json(
                HTTPStatus.NOT_FOUND,
                {"error": "not_found", "message": "未知接口。"},
            )

        def _handle_findings(self, run_id: str, query: dict[str, list[str]]) -> None:
            run_dir = resolve_run_dir(state.runs_dir, run_id)
            if run_dir is None:
                self._unknown_run()
                return
            fmt = (query.get("format") or ["json"])[0].strip().lower()
            if fmt == "sarif":
                sarif_path = run_dir / "findings.sarif"
                sarif = _load_json(sarif_path, default=None)
                if sarif is None:
                    self._send_json(
                        HTTPStatus.NOT_FOUND,
                        {
                            "error": "not_found",
                            "message": f"运行 {run_id} 没有 findings.sarif。",
                        },
                    )
                    return
                self._send_json(HTTPStatus.OK, {"run": run_id, "format": "sarif", "sarif": sarif})
                return
            findings = read_findings(run_dir)
            self._send_json(
                HTTPStatus.OK,
                {
                    "run": run_id,
                    "format": "json",
                    "count": len(findings),
                    "severity_counts": severity_counts(findings),
                    "findings": findings,
                },
            )

        def _unknown_run(self) -> None:
            self._send_json(
                HTTPStatus.NOT_FOUND,
                {"error": "unknown_run", "message": "运行不存在。"},
            )

        def _authorized(self, query: dict[str, list[str]]) -> bool:
            if not state.auth_required:
                return True
            token = self._presented_token(query)
            if not token:
                return False
            return verify_token(state.users_path, token) is not None

        def _presented_token(self, query: dict[str, list[str]]) -> str | None:
            header = self.headers.get("Authorization") or ""
            scheme, _, value = header.partition(" ")
            if scheme.lower() == "bearer" and value.strip():
                return value.strip()
            alt = (self.headers.get("X-Strix-Token") or "").strip()
            if alt:
                return alt
            values = query.get("token") or []
            query_token = values[0].strip() if values else ""
            return query_token or None

        def _reject_method(self) -> None:
            self._send_json(
                HTTPStatus.METHOD_NOT_ALLOWED,
                {"error": "method_not_allowed", "message": "看板只支持 GET 请求。"},
                headers={"Allow": "GET"},
            )

        def _send_json(
            self,
            status: HTTPStatus,
            payload: Any,
            *,
            headers: dict[str, str] | None = None,
        ) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def _send_html(self, html: str) -> None:
            body = html.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

    return LocalServeHandler


def build_state(*, runs_dir: Path, users_path: Path | None = None) -> ServeState:
    """读取用户配置，构造看板的只读状态；users.json 损坏时抛 ``ServeError``。"""
    resolved_users = users_path or default_users_path()
    try:
        configured = list_users(resolved_users) if resolved_users.is_file() else []
    except UsersError as exc:
        message = f"无法读取本地用户配置 {resolved_users}：{exc}"
        raise ServeError(message, exit_code=2) from exc
    return ServeState(
        runs_dir=Path(runs_dir).expanduser(),
        users_path=resolved_users,
        user_count=len(configured),
        started_at=_now_iso(),
    )


def create_server(
    *,
    state: ServeState,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
) -> ThreadingHTTPServer:
    """构造（但不启动）看板 HTTP 服务；端口传 0 时由系统分配。"""
    httpd = ThreadingHTTPServer((host, port), _make_handler(state))
    httpd.daemon_threads = True
    return httpd


# --------------------------------------------------------------------------- 看板页面

_DASHBOARD_HTML = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Strix 本地看板</title>
<style>
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body { margin: 0; background: #0b0f14; color: #d7dee8;
  font: 14px/1.6 -apple-system, "PingFang SC", "Microsoft YaHei", sans-serif; }
header { display: flex; gap: 16px; align-items: baseline; padding: 18px 24px;
  border-bottom: 1px solid #1e2833; }
h1 { margin: 0; font-size: 18px; font-weight: 600; }
h2 { margin: 0 0 12px; font-size: 16px; }
#status { color: #7d8b9c; font-size: 12px; }
main { display: grid; grid-template-columns: minmax(0, 1.2fr) minmax(0, 1fr);
  gap: 24px; padding: 24px; }
@media (max-width: 900px) { main { grid-template-columns: 1fr; } }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 8px 10px; text-align: left; border-bottom: 1px solid #1a222c;
  vertical-align: top; }
th { color: #8fa0b3; font-weight: 500; font-size: 12px; }
tbody tr { cursor: pointer; }
tbody tr:hover { background: #111820; }
section { border: 1px solid #1e2833; border-radius: 8px; padding: 16px; }
ol { margin: 0; padding-left: 20px; }
li { margin-bottom: 14px; }
li p { margin: 4px 0 0; color: #aeb9c7; white-space: pre-wrap; }
#auth { margin: 0 24px 16px; padding: 12px 16px; border: 1px solid #3a2a14;
  background: #1a1409; border-radius: 8px; }
#auth input { background: #0b0f14; color: inherit; border: 1px solid #33404e;
  border-radius: 6px; padding: 6px 8px; min-width: 280px; }
button { background: #1d4ed8; color: #fff; border: 0; border-radius: 6px;
  padding: 7px 14px; cursor: pointer; }
.muted { color: #7d8b9c; }
</style>
</head>
<body>
<header>
  <h1>Strix 本地看板</h1>
  <span id="status">加载中…</span>
</header>
<div id="auth" hidden>
  <p>该看板需要访问令牌。请粘贴 <code>strix local users add</code> 生成的令牌：</p>
  <input id="token-input" type="password" autocomplete="off" placeholder="访问令牌">
  <button id="token-save" type="button">保存并加载</button>
</div>
<main>
  <section>
    <table>
      <thead>
        <tr><th>运行</th><th>目标</th><th>状态</th><th>严重度</th></tr>
      </thead>
      <tbody id="runs"></tbody>
    </table>
  </section>
  <section id="detail"><p class="muted">选择左侧运行查看发现。</p></section>
</main>
<script>
const TOKEN_KEY = 'strix-local-token';
const params = new URLSearchParams(location.search);
const fromUrl = params.get('token');
if (fromUrl) {
  sessionStorage.setItem(TOKEN_KEY, fromUrl);
  history.replaceState(null, '', location.pathname);
}
function token() { return sessionStorage.getItem(TOKEN_KEY) || ''; }
function node(tag, text) {
  const el = document.createElement(tag);
  if (text !== undefined && text !== null) el.textContent = String(text);
  return el;
}
function fmtCounts(c) {
  c = c || {};
  return '严重 ' + (c.critical || 0) + ' / 高危 ' + (c.high || 0)
    + ' / 中危 ' + (c.medium || 0) + ' / 低危 ' + (c.low || 0);
}
async function api(path) {
  const headers = {};
  if (token()) headers['X-Strix-Token'] = token();
  const res = await fetch(path, { headers });
  if (!res.ok) {
    const err = new Error('HTTP ' + res.status);
    err.status = res.status;
    throw err;
  }
  return res.json();
}
let tokenPrompted = false;
function showTokenPrompt() {
  if (tokenPrompted) return;
  tokenPrompted = true;
  document.getElementById('auth').hidden = false;
}
document.getElementById('token-save').addEventListener('click', () => {
  const value = document.getElementById('token-input').value.trim();
  if (!value) return;
  sessionStorage.setItem(TOKEN_KEY, value);
  document.getElementById('auth').hidden = true;
  tokenPrompted = false;
  loadRuns();
  if (currentRun) loadDetail(currentRun);
});
let currentRun = null;
async function loadRuns() {
  const body = document.getElementById('runs');
  const status = document.getElementById('status');
  try {
    const data = await api('/api/runs');
    body.textContent = '';
    status.textContent = '共 ' + data.count + ' 个运行';
    if (!data.runs.length) {
      const row = node('tr');
      const cell = node('td', '暂无运行记录。');
      cell.colSpan = 4;
      cell.className = 'muted';
      row.append(cell);
      body.append(row);
      return;
    }
    for (const run of data.runs) {
      const row = node('tr');
      row.append(
        node('td', run.name),
        node('td', run.target || '—'),
        node('td', run.status || 'unknown'),
        node('td', fmtCounts(run.severity_counts))
      );
      row.addEventListener('click', () => loadDetail(run.id));
      body.append(row);
    }
  } catch (err) {
    status.textContent = '加载失败：' + err.message;
    if (err.status === 401) showTokenPrompt();
  }
}
async function loadDetail(id) {
  currentRun = id;
  const panel = document.getElementById('detail');
  panel.textContent = '';
  panel.append(node('h2', id));
  try {
    const base = '/api/runs/' + encodeURIComponent(id);
    const detail = await api(base);
    const findings = await api(base + '/findings');
    panel.append(
      node('p', '目标：' + (detail.run.target || '—')
        + '　状态：' + (detail.run.status || 'unknown')),
      node('p', '严重度：' + fmtCounts(detail.severity_counts))
    );
    if (!findings.findings.length) {
      panel.append(node('p', '该运行暂无发现。'));
      return;
    }
    const list = node('ol');
    for (const finding of findings.findings) {
      const item = node('li');
      const title = String(finding.severity || 'unknown').toUpperCase()
        + ' · ' + (finding.title || '未命名发现');
      item.append(node('strong', title));
      if (finding.description) item.append(node('p', finding.description));
      list.append(item);
    }
    panel.append(list);
  } catch (err) {
    panel.append(node('p', '加载失败：' + err.message));
    if (err.status === 401) showTokenPrompt();
  }
}
loadRuns();
</script>
</body>
</html>
"""


# --------------------------------------------------------------------------- CLI


def _port_type(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        message = "端口必须是整数"
        raise argparse.ArgumentTypeError(message) from exc
    if not 0 <= port <= 65535:
        message = "端口必须在 0-65535 之间"
        raise argparse.ArgumentTypeError(message)
    return port


def register(subparsers: Any) -> None:
    """注册 ``strix local serve`` 子命令。"""
    parser = subparsers.add_parser(
        "serve",
        help="启动只读看板服务（默认 http://127.0.0.1:8765）",
        description=(
            "启动只读 HTTP 看板，提供运行列表、运行详情与发现清单。"
            "令牌来自 ~/.strix/local/users.json；未配置用户时仅允许本机回环访问。"
        ),
    )
    parser.add_argument(
        "--host",
        default=DEFAULT_HOST,
        help=f"监听地址（默认：{DEFAULT_HOST}；非回环地址需要先配置本地用户）",
    )
    parser.add_argument(
        "--port",
        type=_port_type,
        default=DEFAULT_PORT,
        help=f"监听端口（默认：{DEFAULT_PORT}；0 表示由系统分配）",
    )
    parser.add_argument(
        "--runs-dir",
        default=None,
        metavar="DIR",
        help=f"运行目录（默认：./{RUNS_DIR_NAME}，也可用 STRIX_LOCAL_RUNS_DIR 指定）",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="以 JSON 输出启动信息，便于脚本消费",
    )
    parser.set_defaults(func=run)


def _write_stdout(text: str) -> None:
    sys.stdout.write(text + "\n")
    sys.stdout.flush()


def _write_stderr(text: str) -> None:
    sys.stderr.write(text + "\n")
    sys.stderr.flush()


def _fail(as_json: bool, message: str, *, code: str, exit_code: int) -> int:
    if as_json:
        payload = {"status": "error", "error": code, "message": message}
        _write_stdout(json.dumps(payload, ensure_ascii=False))
    else:
        _write_stderr(message)
    return exit_code


def run(args: argparse.Namespace) -> int:
    """执行 ``strix local serve``；返回进程退出码。"""
    host = str(getattr(args, "host", DEFAULT_HOST))
    port = int(getattr(args, "port", DEFAULT_PORT))
    as_json = bool(getattr(args, "json", False))
    runs_dir = resolve_runs_dir(getattr(args, "runs_dir", None))
    users_path = default_users_path()

    try:
        state = build_state(runs_dir=runs_dir, users_path=users_path)
    except ServeError as exc:
        return _fail(as_json, str(exc), code="users_unreadable", exit_code=exc.exit_code)

    if not state.auth_required and not is_loopback(host):
        message = (
            f"拒绝在 {host} 上无鉴权启动：未配置 {users_path}。"
            "请先运行 `strix local users add <用户名>`，或改用 --host 127.0.0.1。"
        )
        return _fail(as_json, message, code="no_users_non_loopback", exit_code=2)
    if not state.auth_required:
        _write_stderr(f"警告：未配置本地用户（{users_path}），看板退化为本机回环无鉴权模式。")

    try:
        httpd = create_server(state=state, host=host, port=port)
    except OSError as exc:
        message = f"无法在 {host}:{port} 启动看板服务：{exc}"
        return _fail(as_json, message, code="bind_failed", exit_code=1)

    bound_port = int(httpd.server_address[1])
    url = f"http://{host}:{bound_port}"
    if as_json:
        payload = {
            "status": "serving",
            "url": url,
            "host": host,
            "port": bound_port,
            "auth_required": state.auth_required,
            "users": state.user_count,
            "runs_dir": str(state.runs_dir),
            "endpoints": list(API_ENDPOINTS),
            "warning": None if state.auth_required else "no_users",
        }
        _write_stdout(json.dumps(payload, ensure_ascii=False))
    else:
        _write_stdout(f"只读看板已启动：{url}")
        if state.auth_required:
            _write_stdout(f"鉴权：已启用（{state.user_count} 个本地用户）")
        else:
            _write_stdout("鉴权：未启用（仅本机回环）")
        _write_stdout(f"运行目录：{state.runs_dir}")
        _write_stdout("接口：" + "、".join(API_ENDPOINTS))
        _write_stdout("按 Ctrl-C 停止。")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        if not as_json:
            _write_stderr("看板服务已停止。")
    finally:
        httpd.server_close()
    return 0


__all__ = [
    "API_ENDPOINTS",
    "DEFAULT_HOST",
    "DEFAULT_PORT",
    "ServeError",
    "ServeState",
    "build_state",
    "create_server",
    "is_loopback",
    "iter_run_dirs",
    "read_findings",
    "register",
    "resolve_run_dir",
    "resolve_runs_dir",
    "run",
    "run_detail",
    "run_summary",
    "severity_counts",
]

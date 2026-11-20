# ruff: noqa: RUF002
"""本地运行索引与历史：扫描 run.json，维护 ``~/.strix/local/runs.jsonl``。

扫描范围：

- ``STRIX_MCP_ROOT``（默认 ``~/pentest/strix-mcp-runs``）下任意层级的 run.json
- ``~/pentest/**/strix_runs`` 目录下的直接子运行目录（可用 ``STRIX_PENTEST_ROOT`` 改根）

索引是 append-only 的 JSONL：每行一条运行摘要，同一路径以最后一行为准，
只有 run.json / vulnerabilities.json 发生变化时才追加新行。

命令面由 ``register(subparsers)`` 注册到 ``strix local`` 下：

    strix local runs list [--target PATTERN] [--status STATUS] [--limit N] [--json]
    strix local runs show <运行名|run_id|路径> [--json]
    strix local runs export [--target PATTERN] [--status STATUS] [--output FILE] [--json]
"""

from __future__ import annotations

import contextlib
import json
import os
import stat
import sys
import unicodedata
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    import argparse
    from collections.abc import Iterable, Iterator


INDEX_FILENAME = "runs.jsonl"
RUN_RECORD_FILENAME = "run.json"
FINDINGS_FILENAME = "vulnerabilities.json"
RUNS_DIR_NAME = "strix_runs"
LOCAL_DIR_MODE = 0o700
INDEX_FILE_MODE = 0o600
_MAX_MCP_DEPTH = 6
_SKIP_DIR_NAMES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".cache",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "build",
        "dist",
    }
)

SEVERITIES = ("critical", "high", "medium", "low", "info")
_SEVERITY_RANK = {severity: index for index, severity in enumerate(SEVERITIES)}
_STATUS_LABELS = {
    "completed": "已完成",
    "running": "运行中",
    "failed": "失败",
    "stopped": "已停止",
    "interrupted": "已中断",
    "unknown": "未知",
}


class LocalRunsError(Exception):
    """面向用户的运行索引错误，由命令层转成退出码 1。"""


@dataclass
class RunEntry:
    """一条运行摘要，对应 runs.jsonl 中的一行。"""

    path: str
    run_name: str
    run_id: str
    target: str
    targets: list[str] = field(default_factory=list)
    status: str = "unknown"
    title: str = ""
    started_at: str = ""
    ended_at: str = ""
    findings: int = 0
    severity_counts: dict[str, int] = field(default_factory=dict)
    cost: float | None = None
    source: str = "workspace"
    indexed_at: str = ""
    fingerprint: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "run_name": self.run_name,
            "run_id": self.run_id,
            "target": self.target,
            "targets": list(self.targets),
            "status": self.status,
            "title": self.title,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "findings": self.findings,
            "severity_counts": dict(self.severity_counts),
            "cost": self.cost,
            "source": self.source,
            "indexed_at": self.indexed_at,
            "fingerprint": dict(self.fingerprint),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RunEntry:
        targets = data.get("targets")
        counts = data.get("severity_counts")
        fingerprint = data.get("fingerprint")
        cost = data.get("cost")
        return cls(
            path=str(data.get("path") or ""),
            run_name=str(data.get("run_name") or ""),
            run_id=str(data.get("run_id") or ""),
            target=str(data.get("target") or ""),
            targets=[str(item) for item in targets] if isinstance(targets, list) else [],
            status=str(data.get("status") or "unknown"),
            title=str(data.get("title") or ""),
            started_at=str(data.get("started_at") or ""),
            ended_at=str(data.get("ended_at") or ""),
            findings=_as_int(data.get("findings")),
            severity_counts=(
                {str(key): _as_int(value) for key, value in counts.items()}
                if isinstance(counts, dict)
                else {}
            ),
            cost=float(cost) if isinstance(cost, int | float) else None,
            source=str(data.get("source") or "workspace"),
            indexed_at=str(data.get("indexed_at") or ""),
            fingerprint=dict(fingerprint) if isinstance(fingerprint, dict) else {},
        )


# ---------------------------------------------------------------------------
# 状态目录


def local_home() -> Path:
    """本地状态目录，默认 ``~/.strix/local``，可用 ``STRIX_LOCAL_HOME`` 覆盖。"""
    override = os.environ.get("STRIX_LOCAL_HOME")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".strix" / "local"


def ensure_local_home() -> Path:
    home = local_home()
    home.mkdir(parents=True, exist_ok=True, mode=LOCAL_DIR_MODE)
    with contextlib.suppress(OSError):
        if stat.S_IMODE(home.stat().st_mode) != LOCAL_DIR_MODE:
            home.chmod(LOCAL_DIR_MODE)
    return home


def index_path() -> Path:
    return ensure_local_home() / INDEX_FILENAME


def mcp_root() -> Path:
    override = os.environ.get("STRIX_MCP_ROOT")
    if override:
        return Path(override).expanduser()
    return Path.home() / "pentest" / "strix-mcp-runs"


def pentest_root() -> Path:
    override = os.environ.get("STRIX_PENTEST_ROOT")
    if override:
        return Path(override).expanduser()
    return Path.home() / "pentest"


# ---------------------------------------------------------------------------
# 扫描


def _skip_dir(name: str) -> bool:
    return name.startswith(".") or name in _SKIP_DIR_NAMES


def _resolved(path: Path) -> Path:
    try:
        return path.resolve()
    except OSError:
        return path.absolute()


def _mcp_run_dirs(root: Path) -> Iterator[Path]:
    if not root.is_dir():
        return
    base_depth = len(root.parts)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        depth = len(current.parts) - base_depth
        dirnames[:] = sorted(
            name for name in dirnames if not _skip_dir(name) and depth < _MAX_MCP_DEPTH
        )
        if RUN_RECORD_FILENAME in filenames:
            dirnames[:] = []
            yield current


def _run_dirs_in(directory: Path) -> Iterator[Path]:
    if (directory / RUN_RECORD_FILENAME).is_file():
        yield directory
        return
    try:
        children = sorted(child for child in directory.iterdir() if child.is_dir())
    except OSError:
        return
    for child in children:
        if not _skip_dir(child.name) and (child / RUN_RECORD_FILENAME).is_file():
            yield child


def _workspace_run_dirs(root: Path) -> Iterator[Path]:
    if not root.is_dir():
        return
    for dirpath, dirnames, _filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        if current.name == RUNS_DIR_NAME:
            yield from _run_dirs_in(current)
            dirnames[:] = []
            continue
        dirnames[:] = sorted(name for name in dirnames if not _skip_dir(name))


def discover_run_dirs() -> list[tuple[Path, str]]:
    """返回 (运行目录, 来源) 列表，按解析后的路径去重。"""
    found: dict[str, tuple[Path, str]] = {}
    for run_dir in _mcp_run_dirs(mcp_root()):
        found.setdefault(str(_resolved(run_dir)), (run_dir, "mcp"))
    for run_dir in _workspace_run_dirs(pentest_root()):
        found.setdefault(str(_resolved(run_dir)), (run_dir, "workspace"))
    return list(found.values())


# ---------------------------------------------------------------------------
# 摘要与索引


def _read_json(path: Path, *, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def read_findings(run_dir: Path) -> list[dict[str, Any]]:
    payload = _read_json(run_dir / FINDINGS_FILENAME, default=[])
    if not isinstance(payload, list):
        return []
    return [item for item in payload if isinstance(item, dict)]


def _stat_fingerprint(path: Path) -> list[int | None]:
    with contextlib.suppress(OSError):
        info = path.stat()
        return [info.st_mtime_ns, info.st_size]
    return [None, None]


def _as_int(value: Any) -> int:
    return value if isinstance(value, int) else 0


def _severity_counts(findings: Iterable[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        severity = str(finding.get("severity") or "unknown").strip().lower() or "unknown"
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def _target_originals(record: dict[str, Any]) -> list[str]:
    targets = record.get("targets_info")
    if not isinstance(targets, list):
        return []
    return [
        str(entry["original"])
        for entry in targets
        if isinstance(entry, dict) and entry.get("original")
    ]


def _describe_target(record: dict[str, Any], originals: list[str]) -> str:
    if originals:
        if len(originals) == 1:
            return originals[0]
        return f"{originals[0]}（另有 {len(originals) - 1} 个）"
    mount = record.get("workspace_mount")
    if isinstance(mount, str) and mount:
        return f"{mount}（工作区）"
    instruction = str(record.get("user_instruction") or record.get("instruction") or "").strip()
    return instruction.splitlines()[0] if instruction else ""


def _title(record: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    instruction = str(record.get("user_instruction") or record.get("instruction") or "").strip()
    if instruction:
        return instruction.splitlines()[0]
    found = [finding for finding in findings if finding.get("title")]
    worst = min(
        found,
        key=lambda item: _SEVERITY_RANK.get(str(item.get("severity")).lower(), len(SEVERITIES)),
        default={},
    )
    return str(worst.get("title") or "")


def _cost(record: dict[str, Any]) -> float | None:
    usage = record.get("llm_usage")
    if not isinstance(usage, dict):
        return None
    cost = usage.get("cost")
    return float(cost) if isinstance(cost, int | float) else None


def build_entry(run_dir: Path, source: str) -> RunEntry:
    record = _read_json(run_dir / RUN_RECORD_FILENAME, default={})
    if not isinstance(record, dict):
        record = {}
    findings = read_findings(run_dir)
    originals = _target_originals(record)
    run_name = str(record.get("run_name") or run_dir.name)
    resolved = _resolved(run_dir)
    return RunEntry(
        path=str(resolved),
        run_name=run_name,
        run_id=str(record.get("run_id") or run_name),
        target=_describe_target(record, originals),
        targets=originals,
        status=str(record.get("status") or "unknown"),
        title=_title(record, findings),
        started_at=str(record.get("start_time") or ""),
        ended_at=str(record.get("end_time") or ""),
        findings=len(findings),
        severity_counts=_severity_counts(findings),
        cost=_cost(record),
        source=source,
        indexed_at=datetime.now(UTC).isoformat(timespec="seconds"),
        fingerprint={
            "record": _stat_fingerprint(run_dir / RUN_RECORD_FILENAME),
            "findings": _stat_fingerprint(run_dir / FINDINGS_FILENAME),
            "count": len(findings),
        },
    )


def load_index() -> dict[str, RunEntry]:
    """读取索引，同一路径以最后一行为准。"""
    path = index_path()
    entries: dict[str, RunEntry] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return entries
    for line in lines:
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict) or not payload.get("path"):
            continue
        entry = RunEntry.from_dict(payload)
        entries[entry.path] = entry
    return entries


def _append_index(entries: Iterable[RunEntry]) -> int:
    lines = [json.dumps(entry.to_dict(), ensure_ascii=False) + "\n" for entry in entries]
    if not lines:
        return 0
    path = index_path()
    with path.open("a", encoding="utf-8") as handle:
        handle.write("".join(lines))
        handle.flush()
    with contextlib.suppress(OSError):
        path.chmod(INDEX_FILE_MODE)
    return len(lines)


def sync_index() -> list[RunEntry]:
    """扫描文件系统，把新增或有变化的运行追加进索引，返回全部运行（新到旧）。"""
    existing = load_index()
    changed: list[RunEntry] = []
    for run_dir, source in discover_run_dirs():
        entry = build_entry(run_dir, source)
        previous = existing.get(entry.path)
        if previous is None or previous.fingerprint != entry.fingerprint:
            changed.append(entry)
    _append_index(changed)
    merged = dict(existing)
    for entry in changed:
        merged[entry.path] = entry
    return sorted(merged.values(), key=_sort_key, reverse=True)


def _timestamp(value: str) -> float:
    text = value.strip()
    if not text:
        return 0.0
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return 0.0
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.timestamp()


def _sort_key(entry: RunEntry) -> tuple[float, str]:
    return (_timestamp(entry.started_at), entry.run_name)


# ---------------------------------------------------------------------------
# 过滤与解析


def _matches_target(entry: RunEntry, patterns: Iterable[str]) -> bool:
    wanted = [pattern.lower() for pattern in patterns if pattern]
    if not wanted:
        return True
    haystack = [*entry.targets, entry.target]
    return any(pattern in value.lower() for pattern in wanted for value in haystack)


def _matches_status(entry: RunEntry, statuses: Iterable[str]) -> bool:
    wanted = [status.lower() for status in statuses if status]
    return not wanted or entry.status.lower() in wanted


def filter_entries(
    entries: Iterable[RunEntry],
    *,
    targets: Iterable[str] = (),
    statuses: Iterable[str] = (),
    limit: int | None = None,
) -> list[RunEntry]:
    selected = [
        entry
        for entry in entries
        if _matches_target(entry, targets) and _matches_status(entry, statuses)
    ]
    if limit is not None and limit >= 0:
        return selected[:limit]
    return selected


def _resolve_entry(entries: list[RunEntry], selector: str) -> RunEntry:
    path_match = _resolved(Path(selector).expanduser())
    matches = [entry for entry in entries if entry.path == str(path_match)]
    if not matches:
        name = selector.rstrip("/").split("/")[-1]
        matches = [entry for entry in entries if selector in (entry.run_name, entry.run_id, name)]
    if not matches:
        raise LocalRunsError(f"未找到运行：{selector}")
    unique = {entry.path: entry for entry in matches}
    if len(unique) > 1:
        listing = "\n".join(f"  {entry.run_name}  {entry.path}" for entry in unique.values())
        raise LocalRunsError(f"运行名 {selector} 对应多个目录，请用路径指定：\n{listing}")
    return next(iter(unique.values()))


# ---------------------------------------------------------------------------
# 文本格式


def _display_width(text: str) -> int:
    return sum(2 if unicodedata.east_asian_width(char) in ("W", "F") else 1 for char in text)


def _pad(text: str, width: int) -> str:
    return text + " " * max(0, width - _display_width(text))


def _truncate(text: str, limit: int) -> str:
    if _display_width(text) <= limit:
        return text
    out = ""
    width = 0
    for char in text:
        char_width = 2 if unicodedata.east_asian_width(char) in ("W", "F") else 1
        if width + char_width > limit - 1:
            break
        out += char
        width += char_width
    return out + "…"


def _short_time(value: str) -> str:
    if not value:
        return "—"
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return value
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone().strftime("%Y-%m-%d %H:%M")


def _status_label(status: str) -> str:
    return _STATUS_LABELS.get(status, status)


def _severity_line(counts: dict[str, int]) -> str:
    ordered = [severity for severity in SEVERITIES if counts.get(severity)]
    ordered += sorted(key for key, value in counts.items() if value and key not in _SEVERITY_RANK)
    return " / ".join(f"{severity} {counts[severity]}" for severity in ordered)


def _format_list(entries: list[RunEntry]) -> str:
    if not entries:
        return (
            "未找到运行记录。\n"
            f"扫描目录：{mcp_root()} 与 {pentest_root()} 下的 {RUNS_DIR_NAME} 目录。"
        )
    name_width = min(max((_display_width(entry.run_name) for entry in entries), default=8), 36)
    header = (
        f"{_pad('开始时间', 17)}  {_pad('状态', 8)}  "
        f"{_pad('运行', name_width)}  {_pad('发现', 5)}目标"
    )
    rows = [header]
    rows += [
        f"{_pad(_short_time(entry.started_at), 17)}  "
        f"{_pad(_status_label(entry.status), 8)}  "
        f"{_pad(_truncate(entry.run_name, name_width), name_width)}  "
        f"{_pad(str(entry.findings), 5)}{_truncate(entry.target, 60) or '—'}"
        for entry in entries
    ]
    rows.append("")
    rows.append(f"共 {len(entries)} 条；索引：{index_path()}")
    return "\n".join(rows)


def _format_show(entry: RunEntry, findings: list[dict[str, Any]]) -> str:
    lines = [
        f"运行：{entry.run_name}",
        f"状态：{_status_label(entry.status)}（{entry.status}）",
        f"目标：{entry.target or '—'}",
        f"标题：{entry.title or '—'}",
        f"开始：{_short_time(entry.started_at)}",
        f"结束：{_short_time(entry.ended_at)}",
        f"路径：{entry.path}",
    ]
    if entry.cost is not None:
        lines.append(f"成本：${entry.cost:.4f}")
    severity = _severity_line(entry.severity_counts)
    suffix = f"（{severity}）" if severity else ""
    lines.append(f"发现：{entry.findings}{suffix}")
    if findings:
        lines.append("")
        lines.append("发现明细：")
        for finding in _sorted_findings(findings):
            title = str(finding.get("title") or "（未命名）")
            severity_name = str(finding.get("severity") or "unknown").lower()
            target = str(finding.get("target") or "")
            tail = f"（受影响：{target}）" if target else ""
            lines.append(f"  [{severity_name}] {title}{tail}")
    elif not Path(entry.path).is_dir():
        lines.append("")
        lines.append("运行目录已不存在，展示的是索引中的历史摘要。")
    return "\n".join(lines)


def _sorted_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        findings,
        key=lambda item: (
            _SEVERITY_RANK.get(str(item.get("severity") or "").lower(), len(SEVERITIES)),
            str(item.get("title") or ""),
        ),
    )


# ---------------------------------------------------------------------------
# Markdown 导出


def _md_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ").strip() or "—"


def _now_label() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")


def render_markdown(
    entries: list[RunEntry],
    findings_by_path: dict[str, list[dict[str, Any]]],
    *,
    generated_at: str | None = None,
) -> str:
    total_findings = sum(len(findings_by_path.get(entry.path, [])) for entry in entries)
    merged_counts: dict[str, int] = {}
    for entry in entries:
        for severity, count in _severity_counts(findings_by_path.get(entry.path, [])).items():
            merged_counts[severity] = merged_counts.get(severity, 0) + count
    severity_text = _severity_line(merged_counts)
    meta = f"运行数量：{len(entries)} · 发现总数：{total_findings}"
    if severity_text:
        meta += f" · 严重程度：{severity_text}"

    lines = [
        "# Strix 运行汇总",
        "",
        f"生成时间：{generated_at or _now_label()}",
        "",
        meta,
        "",
        "## 运行列表",
        "",
    ]
    if entries:
        lines.append("| 运行 | 目标 | 状态 | 开始时间 | 结束时间 | 发现 |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        lines += [
            f"| `{_md_cell(entry.run_name)}` | {_md_cell(entry.target)} | "
            f"{_md_cell(_status_label(entry.status))} | "
            f"{_md_cell(_short_time(entry.started_at))} | "
            f"{_md_cell(_short_time(entry.ended_at))} | {entry.findings} |"
            for entry in entries
        ]
    else:
        lines.append("没有符合条件的运行。")

    lines += ["", "## 发现明细", ""]
    for entry in entries:
        findings = _sorted_findings(findings_by_path.get(entry.path, []))
        lines.append(f"### `{entry.run_name}` — {entry.target or '（无目标）'}")
        lines.append("")
        if not findings:
            lines.append("未记录发现。")
            lines.append("")
            continue
        for finding in findings:
            severity_name = str(finding.get("severity") or "unknown").lower()
            title = str(finding.get("title") or "（未命名）").replace("\n", " ")
            identifier = str(finding.get("id") or "").strip()
            target = str(finding.get("target") or "").strip()
            details = []
            if identifier:
                details.append(f"`{identifier}`")
            if target:
                details.append(f"受影响：{target}")
            suffix = f"（{'，'.join(details)}）" if details else ""
            lines.append(f"- **{severity_name}** {title}{suffix}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _export_payload(
    entries: list[RunEntry],
    findings_by_path: dict[str, list[dict[str, Any]]],
    *,
    generated_at: str,
    output: Path | None,
) -> dict[str, Any]:
    merged_counts: dict[str, int] = {}
    runs: list[dict[str, Any]] = []
    total_findings = 0
    for entry in entries:
        findings = findings_by_path.get(entry.path, [])
        total_findings += len(findings)
        for severity, count in _severity_counts(findings).items():
            merged_counts[severity] = merged_counts.get(severity, 0) + count
        item = entry.to_dict()
        item["findings_detail"] = findings
        runs.append(item)
    return {
        "generated_at": generated_at,
        "total_runs": len(entries),
        "total_findings": total_findings,
        "severity_counts": merged_counts,
        "output": str(output) if output else None,
        "runs": runs,
    }


# ---------------------------------------------------------------------------
# 命令实现


def _cmd_list(args: argparse.Namespace) -> int:
    entries = sync_index()
    selected = filter_entries(
        entries,
        targets=getattr(args, "target", []) or [],
        statuses=getattr(args, "status", []) or [],
        limit=getattr(args, "limit", None),
    )
    if getattr(args, "json", False):
        _emit_json(
            {
                "runs": [entry.to_dict() for entry in selected],
                "total": len(selected),
                "index": str(index_path()),
            }
        )
        return 0
    _out(_format_list(selected))
    return 0


def _cmd_show(args: argparse.Namespace) -> int:
    entries = sync_index()
    selector = str(getattr(args, "run", "") or "")
    if not selector:
        raise LocalRunsError("请提供运行名、run_id 或运行目录路径。")
    entry = _resolve_entry(entries, selector)
    findings = read_findings(Path(entry.path))
    if getattr(args, "json", False):
        payload = entry.to_dict()
        payload["findings_detail"] = findings
        payload["missing"] = not Path(entry.path).is_dir()
        _emit_json(payload)
        return 0
    _out(_format_show(entry, findings))
    return 0


def _cmd_export(args: argparse.Namespace) -> int:
    entries = sync_index()
    selected = filter_entries(
        entries,
        targets=getattr(args, "target", []) or [],
        statuses=getattr(args, "status", []) or [],
        limit=getattr(args, "limit", None),
    )
    findings_by_path = {entry.path: read_findings(Path(entry.path)) for entry in selected}
    generated_at = _now_label()
    markdown = render_markdown(selected, findings_by_path, generated_at=generated_at)

    output_arg = getattr(args, "output", None)
    output = Path(output_arg).expanduser() if output_arg else None
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(markdown, encoding="utf-8")

    if getattr(args, "json", False):
        _emit_json(
            _export_payload(
                selected,
                findings_by_path,
                generated_at=generated_at,
                output=output,
            )
        )
        return 0
    if output is None:
        _out(markdown.rstrip())
        return 0
    total_findings = sum(len(findings) for findings in findings_by_path.values())
    _out(f"已写入 {output}（运行 {len(selected)} 个，发现 {total_findings} 个）")
    return 0


def _out(text: str) -> None:
    sys.stdout.write(text + "\n")


def _emit_json(payload: Any) -> None:
    sys.stdout.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")


def _error(message: str) -> None:
    sys.stderr.write(message + "\n")


# ---------------------------------------------------------------------------
# CLI 注册


def register(subparsers: Any) -> None:
    """把 ``runs`` 子树注册到 ``strix local`` 的 subparsers 上。"""
    parser = subparsers.add_parser(
        "runs",
        help="运行历史与发现汇总",
        description=(
            "扫描 STRIX_MCP_ROOT（默认 ~/pentest/strix-mcp-runs）与 "
            "~/pentest/**/strix_runs 下的 run.json，维护 ~/.strix/local/runs.jsonl。"
        ),
    )
    nested = parser.add_subparsers(dest="runs_command", metavar="<list|show|export>")
    nested.required = True

    list_parser = nested.add_parser(
        "list",
        help="列出运行记录",
        description="按开始时间从新到旧列出运行记录，可附加 --target / --status 过滤。",
    )
    _add_filter_flags(list_parser)
    list_parser.add_argument("--limit", type=int, default=None, help="最多显示多少条。")
    list_parser.add_argument("--json", action="store_true", help="输出 JSON。")
    list_parser.set_defaults(func=run, local_handler=run)

    show_parser = nested.add_parser(
        "show",
        help="查看单个运行的详情",
        description="按运行名、run_id 或运行目录路径查看一次运行及其发现。",
    )
    show_parser.add_argument("run", help="运行名、run_id 或运行目录路径。")
    show_parser.add_argument("--json", action="store_true", help="输出 JSON。")
    show_parser.set_defaults(func=run, local_handler=run)

    export_parser = nested.add_parser(
        "export",
        help="导出 Markdown 汇总",
        description="把选中的运行与发现导出为 Markdown；不给 --output 时打印到标准输出。",
    )
    _add_filter_flags(export_parser)
    export_parser.add_argument("--limit", type=int, default=None, help="最多导出多少条。")
    export_parser.add_argument(
        "-o",
        "--output",
        default=None,
        metavar="FILE",
        help="写入 Markdown 文件（默认打印到标准输出）。",
    )
    export_parser.add_argument("--json", action="store_true", help="输出 JSON。")
    export_parser.set_defaults(func=run, local_handler=run)

    parser.set_defaults(func=run, local_handler=run)


def _add_filter_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--target",
        action="append",
        default=[],
        metavar="TARGET",
        help="按目标子串过滤（不区分大小写，可重复）。",
    )
    parser.add_argument(
        "--status",
        action="append",
        default=[],
        metavar="STATUS",
        help="按状态过滤，例如 completed、failed（可重复）。",
    )


def run(args: argparse.Namespace) -> int:
    """执行 ``strix local runs ...``，返回进程退出码。"""
    command = getattr(args, "runs_command", None)
    try:
        if command == "show":
            return _cmd_show(args)
        if command == "export":
            return _cmd_export(args)
        return _cmd_list(args)
    except LocalRunsError as exc:
        _error(f"错误：{exc}")
        return 1
    except OSError as exc:
        _error(f"错误：读写运行索引失败：{exc}")
        return 1


__all__ = [
    "LocalRunsError",
    "RunEntry",
    "build_entry",
    "discover_run_dirs",
    "filter_entries",
    "index_path",
    "load_index",
    "local_home",
    "register",
    "render_markdown",
    "run",
    "sync_index",
]

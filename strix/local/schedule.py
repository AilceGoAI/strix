# ruff: noqa: RUF002
"""本地定时扫描（``strix local schedule``）。

计划登记在 ``~/.strix/local/schedules.json``（0600）。macOS 上为每条计划生成
``~/Library/LaunchAgents/ai.strix.local.schedule.<名称>.plist`` 并交给 launchd 装载；
其他系统只打印对应的 crontab 行，不修改用户的 crontab，也不留下 plist。

状态目录可用 ``STRIX_LOCAL_HOME`` 覆盖；LaunchAgents 目录可用
``STRIX_LOCAL_LAUNCHD_DIR`` 覆盖，便于测试隔离。
"""

from __future__ import annotations

import json
import math
import os
import plistlib
import re
import shlex
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from strix.utils.secret_files import write_secret_text


if TYPE_CHECKING:
    import argparse


LOCAL_HOME_ENV = "STRIX_LOCAL_HOME"
LAUNCHD_DIR_ENV = "STRIX_LOCAL_LAUNCHD_DIR"
SCHEDULES_FILENAME = "schedules.json"
LABEL_PREFIX = "ai.strix.local.schedule"

SCAN_MODES = ("quick", "standard", "deep")
DEFAULT_MODE = "quick"

_DIR_MODE = 0o700
_FILE_MODE = 0o600
_PLIST_MODE = 0o644

# launchd's StartCalendarInterval can only enumerate explicit timestamps. Past this
# count, ask for a sparser expression (or crontab) instead of emitting a huge plist.
MAX_CALENDAR_INTERVALS = 512

_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

_USAGE = """用法：
  strix local schedule add --name <名称> --cron "<分 时 日 月 周>" --target <目标>
      [--mode quick|standard|deep] [--budget USD] [--dry-run]
  strix local schedule list
  strix local schedule remove <名称>

所有子命令都支持 --json。macOS 生成 launchd plist，其他系统只打印 crontab 行。"""

_MONTH_NAMES = {
    "jan": 1,
    "feb": 2,
    "mar": 3,
    "apr": 4,
    "may": 5,
    "jun": 6,
    "jul": 7,
    "aug": 8,
    "sep": 9,
    "oct": 10,
    "nov": 11,
    "dec": 12,
}
_DOW_NAMES = {
    "sun": 0,
    "mon": 1,
    "tue": 2,
    "wed": 3,
    "thu": 4,
    "fri": 5,
    "sat": 6,
}
_CRON_ALIASES = {
    "@hourly": "0 * * * *",
    "@daily": "0 0 * * *",
    "@midnight": "0 0 * * *",
    "@weekly": "0 0 * * 0",
    "@monthly": "0 0 1 * *",
    "@yearly": "0 0 1 1 *",
    "@annually": "0 0 1 1 *",
}
_FIELD_BOUNDS = ((0, 59), (0, 23), (1, 31), (1, 12), (0, 7))
_FIELD_LABELS = ("分钟", "小时", "日期", "月份", "星期")
_FULL_SETS = (
    set(range(60)),
    set(range(24)),
    set(range(1, 32)),
    set(range(1, 13)),
    set(range(7)),
)


class ScheduleError(Exception):
    """A schedule failure with the process exit code to report."""

    def __init__(self, message: str, exit_code: int = 1) -> None:
        super().__init__(message)
        self.exit_code = exit_code


# --------------------------------------------------------------------------- paths


def local_home() -> Path:
    """本地状态根目录，默认 ``~/.strix/local``，可由环境变量覆盖。"""
    override = os.environ.get(LOCAL_HOME_ENV, "").strip()
    if override:
        return Path(override).expanduser()
    return Path.home() / ".strix" / "local"


def schedules_path() -> Path:
    return local_home() / SCHEDULES_FILENAME


def logs_dir() -> Path:
    return local_home() / "logs"


def launch_agents_dir() -> Path:
    """launchd 用户级 LaunchAgents 目录，默认 ``~/Library/LaunchAgents``。"""
    override = os.environ.get(LAUNCHD_DIR_ENV, "").strip()
    if override:
        return Path(override).expanduser()
    return Path.home() / "Library" / "LaunchAgents"


def _is_macos() -> bool:
    return sys.platform == "darwin"


def _working_directory() -> Path:
    return Path.cwd()


def _ensure_dir(directory: Path, mode: int) -> None:
    try:
        directory.mkdir(parents=True, exist_ok=True, mode=mode)
        directory.chmod(mode)
    except OSError as exc:
        message = f"无法准备目录 {directory}：{exc}"
        raise ScheduleError(message) from exc


def _ensure_home_dir(directory: Path) -> None:
    _ensure_dir(directory, _DIR_MODE)


def _write_plist(path: Path, text: str) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f".{path.name}.tmp")
        tmp.write_text(text, encoding="utf-8")
        tmp.chmod(_PLIST_MODE)
        tmp.replace(path)
    except OSError as exc:
        message = f"无法写入 {path}：{exc}"
        raise ScheduleError(message) from exc


def _display_path(path: Path | None) -> str:
    if path is None:
        return "—"
    try:
        home = Path.home()
    except RuntimeError:
        return str(path)
    try:
        return f"~/{path.relative_to(home)}"
    except ValueError:
        return str(path)


# --------------------------------------------------------------------------- cron


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _parse_value(text: str, index: int) -> int:
    key = text.strip().lower()
    if index == 3 and key in _MONTH_NAMES:
        return _MONTH_NAMES[key]
    if index == 4 and key in _DOW_NAMES:
        return _DOW_NAMES[key]
    if key.isdigit():
        return int(key)
    message = f"cron 表达式无效：{key!r} 不是合法的{_FIELD_LABELS[index]}值。"
    raise ScheduleError(message, exit_code=2)


def _parse_field(token: str, index: int) -> set[int]:
    low, high = _FIELD_BOUNDS[index]
    label = _FIELD_LABELS[index]
    values: set[int] = set()
    for part in token.split(","):
        piece = part.strip()
        if not piece:
            message = f"cron 表达式无效：{label}字段包含空项（{token!r}）。"
            raise ScheduleError(message, exit_code=2)

        base = piece
        step = 1
        if "/" in piece:
            base, _, step_text = piece.partition("/")
            if not step_text.strip().isdigit() or int(step_text) < 1:
                message = f"cron 表达式无效：步长 {step_text!r} 必须是正整数。"
                raise ScheduleError(message, exit_code=2)
            step = int(step_text)

        if base.strip() == "*":
            start, end = low, high
        elif "-" in base:
            left, _, right = base.partition("-")
            start = _parse_value(left, index)
            end = _parse_value(right, index)
        else:
            start = _parse_value(base, index)
            end = high if step > 1 else start

        if start < low or end > high or start > end:
            message = f"cron 表达式无效：{label}字段的 {piece!r} 超出 {low}-{high} 范围或区间颠倒。"
            raise ScheduleError(message, exit_code=2)
        values.update(range(start, end + 1, step))
    return values


def parse_cron(expression: str) -> list[set[int]]:
    """把 5 字段 cron 表达式展开成五个集合：分、时、日、月、星期。"""
    text = expression.strip()
    if not text:
        raise ScheduleError("cron 表达式为空。", exit_code=2)

    alias = _CRON_ALIASES.get(text.lower())
    if alias is not None:
        text = alias

    parts = text.split()
    if len(parts) != 5:
        message = (
            "cron 表达式无效：需要 5 个字段（分 时 日 月 周），"
            f"实际得到 {len(parts)} 个：{text!r}。"
        )
        raise ScheduleError(message, exit_code=2)

    fields = [_parse_field(part, index) for index, part in enumerate(parts)]
    if 7 in fields[4]:
        fields[4].discard(7)
        fields[4].add(0)
    return fields


def _is_full(fields: list[set[int]], index: int) -> bool:
    return fields[index] == _FULL_SETS[index]


def cron_to_calendar_intervals(fields: list[set[int]]) -> list[dict[str, int]]:
    """把 cron 字段展开成 launchd 的 StartCalendarInterval 数组。"""
    minutes, hours, days, months, weekdays = fields
    day_any = _is_full(fields, 2)
    month_any = _is_full(fields, 3)
    weekday_any = _is_full(fields, 4)

    combinations = (
        len(minutes)
        * len(hours)
        * (1 if day_any else len(days))
        * (1 if month_any else len(months))
        * (1 if weekday_any else len(weekdays))
    )
    if combinations > MAX_CALENDAR_INTERVALS:
        message = (
            f"cron 表达式过于密集，launchd 需要 {combinations} 条时间条目"
            f"（上限 {MAX_CALENDAR_INTERVALS}）。请改用更稀疏的表达式"
            "（例如每小时或每天一次）。"
        )
        raise ScheduleError(message, exit_code=2)

    intervals: list[dict[str, int]] = []
    seen: set[tuple[int, int, int | None, int | None, int | None]] = set()
    for minute in sorted(minutes):
        for hour in sorted(hours):
            for day in [None] if day_any else sorted(days):
                for month in [None] if month_any else sorted(months):
                    for weekday in [None] if weekday_any else sorted(weekdays):
                        key = (minute, hour, day, month, weekday)
                        if key in seen:
                            continue
                        seen.add(key)
                        entry: dict[str, int] = {"Minute": minute, "Hour": hour}
                        if day is not None:
                            entry["Day"] = day
                        if month is not None:
                            entry["Month"] = month
                        if weekday is not None:
                            entry["Weekday"] = weekday
                        intervals.append(entry)
    return intervals


def cron_warnings(fields: list[set[int]]) -> list[str]:
    """返回 cron 与 launchd 语义差异的用户可见提示。"""
    if _is_full(fields, 2) or _is_full(fields, 4):
        return []
    message = (
        "cron 中“日期”与“星期”同时限定时为“任一匹配”，launchd 按“同时匹配”处理，"
        "实际触发时刻可能与 cron 预期不同。"
    )
    return [message]


# --------------------------------------------------------------------------- registry


def _index_of(entries: list[dict[str, Any]], name: str) -> int | None:
    for index, entry in enumerate(entries):
        if entry.get("name") == name:
            return index
    return None


def load_schedules() -> list[dict[str, Any]]:
    """读取调度登记表；文件不存在时返回空列表。"""
    path = schedules_path()
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    except OSError as exc:
        message = f"无法读取 {path}：{exc}"
        raise ScheduleError(message) from exc

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        message = f"{path} 不是有效的 JSON：{exc}"
        raise ScheduleError(message) from exc

    if not isinstance(data, dict):
        message = f"{path} 结构无效：顶层应为对象。"
        raise ScheduleError(message)
    entries = data.get("schedules")
    if not isinstance(entries, list):
        message = f"{path} 结构无效：缺少 schedules 数组。"
        raise ScheduleError(message)

    schedules: list[dict[str, Any]] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
            message = f"{path} 第 {index + 1} 条计划记录无效：需要 name 字段。"
            raise ScheduleError(message)
        schedules.append(dict(entry))
    return schedules


def save_schedules(entries: list[dict[str, Any]]) -> None:
    path = schedules_path()
    _ensure_home_dir(path.parent)
    payload = json.dumps({"schedules": entries}, ensure_ascii=False, indent=2) + "\n"
    try:
        write_secret_text(path, payload)
        path.chmod(_FILE_MODE)
    except OSError as exc:
        message = f"无法写入 {path}：{exc}"
        raise ScheduleError(message) from exc


# --------------------------------------------------------------------------- validation


def _validate_name(name: str) -> str:
    normalized = name.strip()
    if not _NAME_PATTERN.fullmatch(normalized):
        message = (
            "计划名称无效：需以字母或数字开头，仅含字母、数字、点、下划线或连字符，长度 1-64。"
        )
        raise ScheduleError(message, exit_code=2)
    return normalized


def _checked_budget(budget: float | None) -> float | None:
    if budget is None:
        return None
    if not math.isfinite(budget) or budget <= 0:
        message = f"预算无效：{budget}。必须是大于 0 的美元金额。"
        raise ScheduleError(message, exit_code=2)
    return budget


def _checked_target(target: str) -> str:
    normalized = target.strip()
    if not normalized:
        raise ScheduleError("目标不能为空。", exit_code=2)
    return normalized


def _label_for(name: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]", "-", name).strip("-.") or "job"
    return f"{LABEL_PREFIX}.{safe}"


# --------------------------------------------------------------------------- plist


def _strix_command() -> list[str]:
    executable = shutil.which("strix")
    if executable:
        return [executable]
    return [sys.executable, "-m", "strix.interface.main"]


def _scan_arguments(mode: str, target: str, budget: float | None) -> list[str]:
    arguments = ["-n", "--target", target, "--scan-mode", mode]
    if budget is not None:
        arguments.extend(["--max-budget", f"{budget:g}"])
    return arguments


def build_plist_payload(
    *,
    label: str,
    cron_fields: list[set[int]],
    target: str,
    mode: str,
    budget: float | None,
    working_directory: Path,
    log_path: Path,
    error_log_path: Path,
) -> dict[str, Any]:
    """构造 launchd plist 字典（键顺序稳定，便于测试与人工比对）。"""
    payload: dict[str, Any] = {
        "Label": label,
        "ProgramArguments": [*_strix_command(), *_scan_arguments(mode, target, budget)],
        "WorkingDirectory": str(working_directory),
        "RunAtLoad": False,
        "StandardOutPath": str(log_path),
        "StandardErrorPath": str(error_log_path),
    }
    if all(_is_full(cron_fields, index) for index in range(5)):
        payload["StartInterval"] = 60
    else:
        payload["StartCalendarInterval"] = cron_to_calendar_intervals(cron_fields)
    return payload


def render_plist(payload: dict[str, Any]) -> str:
    return plistlib.dumps(payload, fmt=plistlib.FMT_XML, sort_keys=False).decode("utf-8")


def _crontab_line(
    *,
    cron: str,
    target: str,
    mode: str,
    budget: float | None,
    working_directory: Path,
    log_path: Path,
) -> str:
    command = [*_strix_command(), *_scan_arguments(mode, target, budget)]
    body = f"cd {shlex.quote(str(working_directory))} && {shlex.join(command)}"
    return f"{cron} {body} >> {shlex.quote(str(log_path))} 2>&1"


# --------------------------------------------------------------------------- launchctl


def _current_uid() -> int:
    getuid = getattr(os, "getuid", None)
    return int(getuid()) if getuid is not None else 0


def _launchctl(*arguments: str) -> tuple[bool, str]:
    executable = shutil.which("launchctl")
    if executable is None:
        return False, "未找到 launchctl"
    try:
        completed = subprocess.run(  # noqa: S603
            [executable, *arguments],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        return False, str(exc)
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        return False, detail or f"launchctl 退出码 {completed.returncode}"
    return True, ""


def _bootstrap_plist(plist_path: Path) -> tuple[bool, str]:
    ok, detail = _launchctl("bootstrap", f"gui/{_current_uid()}", str(plist_path))
    if ok:
        return True, ""
    fallback_ok, _ = _launchctl("load", "-w", str(plist_path))
    if fallback_ok:
        return True, ""
    return False, detail


def _bootout_plist(label: str, plist_path: Path) -> tuple[bool, str]:
    ok, detail = _launchctl("bootout", f"gui/{_current_uid()}/{label}")
    if ok:
        return True, ""
    fallback_ok, _ = _launchctl("unload", "-w", str(plist_path))
    if fallback_ok:
        return True, ""
    return False, detail


# --------------------------------------------------------------------------- add


def _cmd_add(args: argparse.Namespace, console: Console) -> int:
    name = _validate_name(args.name)
    cron = args.cron.strip()
    fields = parse_cron(cron)
    target = _checked_target(args.target)
    mode = args.mode
    budget = _checked_budget(args.budget)
    json_mode = bool(getattr(args, "json", False))
    dry_run = bool(getattr(args, "dry_run", False))
    force = bool(getattr(args, "force", False))

    entries = load_schedules()
    existing = _index_of(entries, name)
    if existing is not None and not force:
        message = (
            f"已存在同名计划：{name}。先执行 strix local schedule remove {name}，"
            "或加 --force 覆盖。"
        )
        raise ScheduleError(message, exit_code=2)

    entry: dict[str, Any] = {
        "name": name,
        "label": _label_for(name),
        "cron": cron,
        "target": target,
        "mode": mode,
        "budget": budget,
        "backend": "launchd" if _is_macos() else "crontab",
        "plist_path": None,
        "log_path": None,
        "error_log_path": None,
        "working_directory": str(_working_directory()),
        "created_at": _utc_now(),
    }
    if _is_macos():
        return _add_launchd(
            entry,
            fields,
            entries,
            existing,
            console,
            json_mode=json_mode,
            dry_run=dry_run,
        )
    return _add_crontab(
        entry,
        fields,
        entries,
        existing,
        console,
        json_mode=json_mode,
        dry_run=dry_run,
    )


def _add_launchd(
    entry: dict[str, Any],
    fields: list[set[int]],
    entries: list[dict[str, Any]],
    existing: int | None,
    console: Console,
    *,
    json_mode: bool,
    dry_run: bool,
) -> int:
    name = str(entry["name"])
    label = str(entry["label"])
    plist_path = launch_agents_dir() / f"{label}.plist"
    log_path = logs_dir() / f"{name}.out.log"
    error_log_path = logs_dir() / f"{name}.err.log"
    entry["plist_path"] = str(plist_path)
    entry["log_path"] = str(log_path)
    entry["error_log_path"] = str(error_log_path)

    payload = build_plist_payload(
        label=label,
        cron_fields=fields,
        target=str(entry["target"]),
        mode=str(entry["mode"]),
        budget=entry["budget"],
        working_directory=Path(str(entry["working_directory"])),
        log_path=log_path,
        error_log_path=error_log_path,
    )
    plist_text = render_plist(payload)
    warnings = cron_warnings(fields)

    if dry_run:
        if json_mode:
            _emit_json(
                {"dry_run": True, "schedule": entry, "plist": plist_text, "warnings": warnings}
            )
        else:
            console.print(plist_text, markup=False, highlight=False, soft_wrap=True)
        return 0

    _ensure_dir(launch_agents_dir(), 0o755)
    _ensure_dir(logs_dir(), _DIR_MODE)
    if existing is not None:
        _bootout_plist(label, plist_path)
    _write_plist(plist_path, plist_text)
    loaded, detail = _bootstrap_plist(plist_path)

    if existing is not None:
        entries[existing] = entry
    else:
        entries.append(entry)
    save_schedules(entries)

    if json_mode:
        result: dict[str, Any] = {
            "schedule": entry,
            "loaded": loaded,
            "warnings": warnings,
        }
        if not loaded:
            result["warning"] = f"launchctl 装载失败：{detail}"
        _emit_json(result)
        return 0

    _print_launchd_summary(
        console,
        entry,
        plist_path=plist_path,
        log_path=log_path,
        warnings=warnings,
        loaded=loaded,
        detail=detail,
    )
    return 0


def _print_launchd_summary(
    console: Console,
    entry: dict[str, Any],
    *,
    plist_path: Path,
    log_path: Path,
    warnings: list[str],
    loaded: bool,
    detail: str,
) -> None:
    budget_value = entry.get("budget")
    budget = float(budget_value) if isinstance(budget_value, int | float) else None
    console.print(f"已登记定时扫描 {escape(str(entry['name']))}。")
    console.print(f"  触发：{escape(str(entry['cron']))}")
    console.print(f"  目标：{escape(str(entry['target']))}")
    console.print(f"  模式：{escape(str(entry['mode']))}    预算：{_budget_text(budget)}")
    console.print(f"  工作目录：{escape(_display_path(Path(str(entry['working_directory']))))}")
    console.print(f"  plist：{escape(_display_path(plist_path))}")
    console.print(f"  日志：{escape(_display_path(log_path))}")
    for warning in warnings:
        console.print(f"[yellow]注意：{escape(warning)}[/]")
    if loaded:
        console.print("已通过 launchctl 装载；任务在 launchd 中后台运行。")
        return
    console.print(
        f"[yellow]launchctl 装载失败：{escape(detail)}[/]\n"
        f"plist 已写入，可稍后手动执行 launchctl bootstrap gui/{_current_uid()} "
        f"{escape(str(plist_path))}。"
    )


def _add_crontab(
    entry: dict[str, Any],
    fields: list[set[int]],
    entries: list[dict[str, Any]],
    existing: int | None,
    console: Console,
    *,
    json_mode: bool,
    dry_run: bool,
) -> int:
    name = str(entry["name"])
    log_path = logs_dir() / f"{name}.log"
    entry["log_path"] = str(log_path)
    line = _crontab_line(
        cron=str(entry["cron"]),
        target=str(entry["target"]),
        mode=str(entry["mode"]),
        budget=entry["budget"],
        working_directory=Path(str(entry["working_directory"])),
        log_path=log_path,
    )
    warnings = [
        "当前系统不是 macOS，已改为生成 crontab 行，未自动安装。",
        *cron_warnings(fields),
    ]

    if dry_run:
        if json_mode:
            _emit_json(
                {
                    "dry_run": True,
                    "schedule": entry,
                    "crontab_line": line,
                    "warnings": warnings,
                }
            )
        else:
            console.print(line, markup=False, highlight=False, soft_wrap=True)
        return 0

    _ensure_dir(logs_dir(), _DIR_MODE)
    if existing is not None:
        entries[existing] = entry
    else:
        entries.append(entry)
    save_schedules(entries)

    if json_mode:
        _emit_json({"schedule": entry, "crontab_line": line, "warnings": warnings})
        return 0

    console.print(f"已登记定时扫描 {escape(name)}（仅打印 crontab 行，未安装）。")
    console.print("把下面这一行加入 crontab（crontab -e）：")
    console.print(line, markup=False, highlight=False, soft_wrap=True)
    for warning in warnings:
        console.print(f"[yellow]注意：{escape(warning)}[/]")
    return 0


def _budget_text(budget: float | None) -> str:
    return "—" if budget is None else f"${budget:g}"


# --------------------------------------------------------------------------- list / remove


def _cmd_list(args: argparse.Namespace, console: Console) -> int:
    entries = load_schedules()
    if bool(getattr(args, "json", False)):
        _emit_json({"schedules": entries, "count": len(entries)})
        return 0

    if not entries:
        console.print("尚无定时扫描计划。用 strix local schedule add 创建第一条。")
        return 0

    table = Table(title="定时扫描")
    table.add_column("名称", no_wrap=True)
    table.add_column("cron", no_wrap=True)
    table.add_column("目标", overflow="fold")
    table.add_column("模式", no_wrap=True)
    table.add_column("预算", justify="right", no_wrap=True)
    table.add_column("后端", no_wrap=True)
    table.add_column("状态", overflow="fold")
    for entry in entries:
        table.add_row(
            escape(str(entry.get("name", ""))),
            escape(str(entry.get("cron", ""))),
            escape(str(entry.get("target", ""))),
            escape(str(entry.get("mode", ""))),
            _budget_text(_budget_of(entry)),
            escape(str(entry.get("backend") or "launchd")),
            escape(_entry_status(entry)),
        )
    console.print(table)
    return 0


def _budget_of(entry: dict[str, Any]) -> float | None:
    value = entry.get("budget")
    return float(value) if isinstance(value, int | float) else None


def _entry_status(entry: dict[str, Any]) -> str:
    backend = str(entry.get("backend") or "launchd")
    plist_value = entry.get("plist_path")
    if backend != "launchd":
        return "仅打印 crontab 行"
    if not isinstance(plist_value, str) or not plist_value:
        return "未记录 plist 路径"
    return "已写入 plist" if Path(plist_value).exists() else "plist 缺失"


def _cmd_remove(args: argparse.Namespace, console: Console) -> int:
    name = _validate_name(args.name)
    json_mode = bool(getattr(args, "json", False))
    entries = load_schedules()
    index = _index_of(entries, name)
    if index is None:
        message = f"计划不存在：{name}。"
        raise ScheduleError(message)

    entry = entries[index]
    backend = str(entry.get("backend") or "launchd")
    notes: list[str] = []
    unloaded = False
    plist_removed = False

    if backend == "launchd":
        unloaded, plist_removed, plist_notes = _remove_launchd(entry, name)
        notes.extend(plist_notes)
    else:
        notes.extend(_crontab_remove_notes(entry, name))

    del entries[index]
    save_schedules(entries)

    if json_mode:
        _emit_json(
            {
                "removed": entry,
                "unloaded": unloaded,
                "plist_removed": plist_removed,
                "notes": notes,
            }
        )
        return 0

    console.print(f"已删除计划 {escape(name)}。")
    if backend == "launchd":
        console.print("已从 launchd 卸载。" if unloaded else "未确认从 launchd 卸载。")
        console.print("plist 已删除。" if plist_removed else "未找到 plist 文件。")
    for note in notes:
        console.print(note, markup=False, highlight=False, soft_wrap=True)
    return 0


def _remove_launchd(entry: dict[str, Any], name: str) -> tuple[bool, bool, list[str]]:
    """卸载并删除 plist，返回（是否卸载成功，是否删除 plist，提示列表）。"""
    notes: list[str] = []
    plist_value = entry.get("plist_path")
    plist_path = (
        Path(plist_value)
        if isinstance(plist_value, str) and plist_value
        else launch_agents_dir() / f"{_label_for(name)}.plist"
    )
    label = str(entry.get("label") or _label_for(name))
    unloaded = False
    if _is_macos():
        unloaded, detail = _bootout_plist(label, plist_path)
        if not unloaded:
            notes.append(f"launchctl 卸载失败：{detail}；plist 仍会被删除。")

    plist_removed = False
    try:
        if plist_path.exists():
            plist_path.unlink()
            plist_removed = True
    except OSError as exc:
        message = f"无法删除 plist {plist_path}：{exc}"
        raise ScheduleError(message) from exc
    return unloaded, plist_removed, notes


def _crontab_remove_notes(entry: dict[str, Any], name: str) -> list[str]:
    log_value = entry.get("log_path")
    line = _crontab_line(
        cron=str(entry.get("cron", "")),
        target=str(entry.get("target", "")),
        mode=str(entry.get("mode", DEFAULT_MODE)),
        budget=_budget_of(entry),
        working_directory=Path(str(entry.get("working_directory") or _working_directory())),
        log_path=Path(str(log_value)) if log_value else logs_dir() / f"{name}.log",
    )
    return [
        "该计划未安装到 crontab；如需停止，请执行 crontab -e 删除下面这一行：",
        line,
    ]


# --------------------------------------------------------------------------- CLI


def _add_json_flag(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", help="以 JSON 输出")


def register(subparsers: Any) -> None:
    """注册 ``strix local schedule`` 及其子命令。"""
    parser = subparsers.add_parser(
        "schedule",
        help="生成 launchd / crontab 定时扫描",
        description=(
            "管理定时扫描计划。macOS 生成 ~/Library/LaunchAgents 下的 launchd plist，"
            "其他系统只打印 crontab 行。计划登记在 ~/.strix/local/schedules.json。"
        ),
        epilog=(
            "定时任务不继承当前 shell 的环境变量（例如 LLM_API_KEY），"
            "需要让 launchd 任务拿到模型凭据时，把 EnvironmentVariables 补进 plist。"
        ),
    )
    parser.set_defaults(func=run, schedule_command=None)
    actions = parser.add_subparsers(dest="schedule_command", metavar="<子命令>")

    add = actions.add_parser(
        "add",
        help="新增定时扫描",
        description="登记一条定时扫描，并生成 launchd plist（非 macOS 只打印 crontab 行）。",
    )
    add.add_argument("--name", required=True, help="计划名称（字母或数字开头，可含 . _ -）")
    add.add_argument(
        "--cron",
        required=True,
        metavar="CRON",
        help="5 字段 cron 表达式（分 时 日 月 周），也接受 @daily、@hourly 等别名",
    )
    add.add_argument("--target", required=True, help="扫描目标：URL、域名、IP 或本地目录")
    add.add_argument(
        "--mode",
        choices=SCAN_MODES,
        default=DEFAULT_MODE,
        type=str.lower,
        help=f"扫描模式（默认：{DEFAULT_MODE}）",
    )
    add.add_argument(
        "--budget",
        type=float,
        metavar="USD",
        help="单次扫描的 LLM 费用上限，单位为美元（> 0）",
    )
    add.add_argument("--force", action="store_true", help="覆盖同名计划")
    add.add_argument(
        "--dry-run",
        action="store_true",
        help="只打印 plist 内容（非 macOS 打印 crontab 行），不写入磁盘",
    )
    _add_json_flag(add)

    listing = actions.add_parser("list", help="列出定时扫描", description="列出已登记的定时扫描。")
    _add_json_flag(listing)

    remove = actions.add_parser(
        "remove",
        help="删除定时扫描（卸载并删除 plist）",
        description="从 launchd 卸载计划并删除 plist，然后从登记表移除。",
    )
    remove.add_argument("name", metavar="NAME", help="计划名称")
    _add_json_flag(remove)


def _emit_json(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")


def run(args: argparse.Namespace) -> int:
    """执行 ``strix local schedule`` 子命令并返回退出码。"""
    command = getattr(args, "schedule_command", None)
    console = Console()
    if not command:
        console.print(_USAGE, markup=False, highlight=False)
        return 0

    json_mode = bool(getattr(args, "json", False))
    handlers = {"add": _cmd_add, "list": _cmd_list, "remove": _cmd_remove}
    handler = handlers.get(str(command))
    if handler is None:
        message = f"未知的 schedule 子命令：{command}"
        if json_mode:
            _emit_json({"error": message})
        else:
            Console(stderr=True).print(f"[red]{escape(message)}[/]")
        return 2

    try:
        return handler(args, console)
    except ScheduleError as exc:
        if json_mode:
            _emit_json({"error": str(exc)})
        else:
            Console(stderr=True).print(f"[red]{escape(str(exc))}[/]")
        return exc.exit_code

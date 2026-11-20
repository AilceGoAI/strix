"""Local users and roles for ``strix local users``.

Users live in ``~/.strix/local/users.json`` (mode 0600) as::

    {"users": [{"name": "alice", "role": "admin", "token": "...", "created_at": "..."}]}

``STRIX_LOCAL_HOME`` overrides the state root for tests and isolated setups.
Other modules check a token through :func:`verify_token` instead of parsing the
file themselves.
"""

from __future__ import annotations

import hmac
import json
import os
import re
import secrets
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
USERS_FILENAME = "users.json"
ROLES = ("admin", "operator", "viewer")
DEFAULT_ROLE = "viewer"

_DIR_MODE = 0o700
_FILE_MODE = 0o600
_TOKEN_BYTES = 32
_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

_USAGE = """用法：
  strix local users add <用户名> [--role admin|operator|viewer]
  strix local users list
  strix local users remove <用户名> [--force]
  strix local users role <用户名> <角色> [--force]

所有子命令都支持 --json。"""


class UsersError(Exception):
    """A user-management failure with the process exit code to report."""

    def __init__(self, message: str, exit_code: int = 1) -> None:
        super().__init__(message)
        self.exit_code = exit_code


# --------------------------------------------------------------------------- paths


def local_home() -> Path:
    """State root: ``~/.strix/local`` unless ``STRIX_LOCAL_HOME`` is set."""
    override = os.environ.get(LOCAL_HOME_ENV, "").strip()
    if override:
        return Path(override).expanduser()
    return Path.home() / ".strix" / "local"


def default_users_path() -> Path:
    return local_home() / USERS_FILENAME


def _ensure_home_dir(directory: Path) -> None:
    try:
        directory.mkdir(parents=True, exist_ok=True, mode=_DIR_MODE)
        directory.chmod(_DIR_MODE)
    except OSError as exc:
        message = f"无法创建本地状态目录 {directory}：{exc}"
        raise UsersError(message) from exc


# --------------------------------------------------------------------------- storage


def _public(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": record["name"],
        "role": record["role"],
        "created_at": record["created_at"],
    }


def _load_users(path: Path) -> list[dict[str, Any]]:
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    except OSError as exc:
        message = f"无法读取 {path}：{exc}"
        raise UsersError(message) from exc

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        message = f"{path} 不是有效的 JSON：{exc}"
        raise UsersError(message) from exc

    if not isinstance(data, dict):
        message = f"{path} 结构无效：顶层应为对象。"
        raise UsersError(message)
    entries = data.get("users")
    if not isinstance(entries, list):
        message = f"{path} 结构无效：缺少 users 数组。"
        raise UsersError(message)

    users: list[dict[str, Any]] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            message = f"{path} 第 {index + 1} 条用户记录无效：应为对象。"
            raise UsersError(message)
        name = entry.get("name")
        role = entry.get("role")
        token = entry.get("token")
        created_at = entry.get("created_at", "")
        if (
            not isinstance(name, str)
            or not name
            or not isinstance(role, str)
            or not role
            or not isinstance(token, str)
            or not token
        ):
            message = f"{path} 第 {index + 1} 条用户记录无效：需要 name、role、token。"
            raise UsersError(message)
        users.append(
            {
                "name": name,
                "role": role.lower(),
                "token": token,
                "created_at": str(created_at),
            }
        )
    return users


def _save_users(path: Path, users: list[dict[str, Any]]) -> None:
    _ensure_home_dir(path.parent)
    payload = json.dumps({"users": users}, ensure_ascii=False, indent=2) + "\n"
    try:
        write_secret_text(path, payload)
        path.chmod(_FILE_MODE)
    except OSError as exc:
        message = f"无法写入 {path}：{exc}"
        raise UsersError(message) from exc


# --------------------------------------------------------------------------- validation


def _validate_name(name: str) -> str:
    normalized = name.strip()
    if not _NAME_PATTERN.fullmatch(normalized):
        message = "用户名无效：需以字母或数字开头，仅含字母、数字、点、下划线或连字符，长度 1-64。"
        raise UsersError(message, exit_code=2)
    return normalized


def _checked_role(role: str) -> str:
    normalized = role.strip().lower()
    if normalized not in ROLES:
        message = f"角色无效：{role}。可选值：{'、'.join(ROLES)}。"
        raise UsersError(message, exit_code=2)
    return normalized


def _index_of(users: list[dict[str, Any]], name: str) -> int | None:
    for index, user in enumerate(users):
        if user["name"] == name:
            return index
    return None


def _admin_count(users: list[dict[str, Any]]) -> int:
    return sum(1 for user in users if user["role"] == "admin")


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


# --------------------------------------------------------------------------- operations


def list_users(path: Path) -> list[dict[str, Any]]:
    """Return users without their tokens."""
    return [_public(user) for user in _load_users(path)]


def add_user(path: Path, name: str, role: str = DEFAULT_ROLE) -> tuple[dict[str, Any], str]:
    """Add a user, mint a one-time token, and return (public record, token)."""
    clean_name = _validate_name(name)
    clean_role = _checked_role(role)

    users = _load_users(path)
    if _index_of(users, clean_name) is not None:
        message = f"用户已存在：{clean_name}。"
        raise UsersError(message)

    token = secrets.token_urlsafe(_TOKEN_BYTES)
    record = {
        "name": clean_name,
        "role": clean_role,
        "token": token,
        "created_at": _utc_now(),
    }
    users.append(record)
    _save_users(path, users)
    return _public(record), token


def remove_user(path: Path, name: str, *, force: bool = False) -> dict[str, Any]:
    """Delete a user; the last admin needs ``force`` to be removed."""
    clean_name = _validate_name(name)
    users = _load_users(path)
    index = _index_of(users, clean_name)
    if index is None:
        message = f"用户不存在：{clean_name}。"
        raise UsersError(message)

    target = users[index]
    if target["role"] == "admin" and _admin_count(users) == 1 and not force:
        message = "不能删除唯一的 admin 用户；如确需删除，请加 --force。"
        raise UsersError(message)

    del users[index]
    _save_users(path, users)
    return _public(target)


def set_role(path: Path, name: str, role: str, *, force: bool = False) -> dict[str, Any]:
    """Change a role; demoting the last admin needs ``force``."""
    clean_name = _validate_name(name)
    clean_role = _checked_role(role)
    users = _load_users(path)
    index = _index_of(users, clean_name)
    if index is None:
        message = f"用户不存在：{clean_name}。"
        raise UsersError(message)

    target = users[index]
    if (
        target["role"] == "admin"
        and clean_role != "admin"
        and _admin_count(users) == 1
        and not force
    ):
        message = "不能降级唯一的 admin 用户；如确需降级，请加 --force。"
        raise UsersError(message)

    target["role"] = clean_role
    _save_users(path, users)
    return _public(target)


def verify_token(users_path: Path, token: str) -> dict[str, Any] | None:
    """Return the public user matching ``token``, or ``None``.

    The result never carries the token itself. A missing, unreadable, or
    malformed file is treated as "no match" rather than an exception.
    """
    if not token:
        return None
    try:
        users = _load_users(users_path)
    except UsersError:
        return None

    candidate = token.encode("utf-8")
    for user in users:
        stored = str(user["token"]).encode("utf-8")
        if hmac.compare_digest(stored, candidate):
            return _public(user)
    return None


# --------------------------------------------------------------------------- CLI


def _add_json_flag(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", help="以 JSON 输出")


def register(subparsers: Any) -> None:
    """Register the ``strix local users`` subcommands."""
    parser = subparsers.add_parser(
        "users",
        help="管理本地用户与角色（admin/operator/viewer）",
        description="管理本地用户与角色。用户数据保存在 ~/.strix/local/users.json。",
    )
    command_subparsers = parser.add_subparsers(dest="users_command", metavar="<子命令>")

    add = command_subparsers.add_parser(
        "add",
        help="添加用户并生成一次性令牌",
        description="添加本地用户，生成随机令牌并只显示一次。",
    )
    add.add_argument("name", help="用户名（字母或数字开头，可含 . _ -）")
    add.add_argument(
        "--role",
        choices=ROLES,
        default=DEFAULT_ROLE,
        type=str.lower,
        help=f"角色（默认：{DEFAULT_ROLE}）",
    )
    _add_json_flag(add)

    listing = command_subparsers.add_parser(
        "list",
        help="列出用户（不含令牌）",
        description="列出本地用户及其角色，不显示令牌。",
    )
    _add_json_flag(listing)

    remove = command_subparsers.add_parser(
        "remove",
        help="删除用户",
        description="删除本地用户。默认拒绝删除唯一的 admin。",
    )
    remove.add_argument("name", help="用户名")
    remove.add_argument("--force", action="store_true", help="跳过唯一 admin 保护")
    _add_json_flag(remove)

    role = command_subparsers.add_parser(
        "role",
        help="修改用户角色",
        description="修改本地用户角色。默认拒绝降级唯一的 admin。",
    )
    role.add_argument("name", help="用户名")
    role.add_argument("role", choices=ROLES, type=str.lower, help="新角色")
    role.add_argument("--force", action="store_true", help="跳过唯一 admin 保护")
    _add_json_flag(role)


def _emit_json(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")


def _print_usage() -> None:
    Console().print(_USAGE, markup=False, highlight=False)


def _run_add(path: Path, args: argparse.Namespace, json_mode: bool) -> None:
    record, token = add_user(path, args.name, args.role)
    if json_mode:
        _emit_json({"user": record, "token": token})
        return
    console = Console()
    console.print(f"已添加用户 {escape(str(record['name']))}（角色：{record['role']}）。")
    console.print("令牌（仅显示一次，请立即保存）：")
    console.print(token, markup=False, highlight=False)


def _run_list(path: Path, json_mode: bool) -> None:
    users = list_users(path)
    if json_mode:
        _emit_json({"users": users})
        return
    if not users:
        Console().print("暂无本地用户。")
        return
    table = Table(title="本地用户")
    table.add_column("用户名")
    table.add_column("角色")
    table.add_column("创建时间")
    for user in users:
        table.add_row(
            escape(str(user["name"])),
            escape(str(user["role"])),
            escape(str(user["created_at"])),
        )
    Console().print(table)


def _run_remove(path: Path, args: argparse.Namespace, json_mode: bool) -> None:
    record = remove_user(path, args.name, force=args.force)
    if json_mode:
        _emit_json({"removed": record})
        return
    Console().print(f"已删除用户 {escape(str(record['name']))}。")


def _run_role(path: Path, args: argparse.Namespace, json_mode: bool) -> None:
    record = set_role(path, args.name, args.role, force=args.force)
    if json_mode:
        _emit_json({"user": record})
        return
    console = Console()
    console.print(f"用户 {escape(str(record['name']))} 的角色已改为 {record['role']}。")


def run(args: argparse.Namespace) -> int:
    """Execute ``strix local users`` and return the process exit code."""
    command = getattr(args, "users_command", None)
    if not command:
        _print_usage()
        return 0

    json_mode = bool(getattr(args, "json", False))
    path = default_users_path()
    try:
        if command == "add":
            _run_add(path, args, json_mode)
        elif command == "list":
            _run_list(path, json_mode)
        elif command == "remove":
            _run_remove(path, args, json_mode)
        elif command == "role":
            _run_role(path, args, json_mode)
        else:
            message = f"未知的 users 子命令：{command}\n{_USAGE}"
            Console(stderr=True).print(escape(message))
            return 2
    except UsersError as exc:
        Console(stderr=True).print(f"[red]{escape(str(exc))}[/]")
        return exc.exit_code
    return 0

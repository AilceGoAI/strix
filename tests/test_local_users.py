"""Tests for ``strix local users`` — local users, roles, and token checks."""

from __future__ import annotations

import argparse
import json
import stat
from pathlib import Path
from typing import Any

import pytest

from strix.local import users


@pytest.fixture(autouse=True)
def state_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "strix-local"
    monkeypatch.setenv(users.LOCAL_HOME_ENV, str(home))
    return home


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="strix local")
    subparsers = parser.add_subparsers(dest="local_command")
    users.register(subparsers)
    return parser


def _run(*argv: str) -> int:
    return users.run(_parser().parse_args(["users", *argv]))


def _users_file(state_dir: Path) -> Path:
    return state_dir / users.USERS_FILENAME


def _read_users(state_dir: Path) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(_users_file(state_dir).read_text(encoding="utf-8"))
    return data


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_add_creates_private_state_and_prints_token_once(
    state_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _run("add", "alice", "--role", "admin") == 0
    output = capsys.readouterr().out

    data = _read_users(state_dir)
    assert len(data["users"]) == 1
    record = data["users"][0]
    assert record["name"] == "alice"
    assert record["role"] == "admin"
    assert record["created_at"]
    assert record["token"]
    assert record["token"] in output
    assert _mode(state_dir) == 0o700
    assert _mode(_users_file(state_dir)) == 0o600

    assert _run("list") == 0
    listed_text = capsys.readouterr().out
    assert "alice" in listed_text
    assert record["token"] not in listed_text

    assert _run("list", "--json") == 0
    listed = json.loads(capsys.readouterr().out)
    assert listed == {
        "users": [
            {
                "name": "alice",
                "role": "admin",
                "created_at": record["created_at"],
            }
        ]
    }
    assert record["token"] not in json.dumps(listed)


def test_add_json_includes_one_time_token(
    state_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _run("add", "bob", "--json") == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["user"]["name"] == "bob"
    assert payload["user"]["role"] == "viewer"
    assert payload["user"]["created_at"]
    assert payload["token"] == _read_users(state_dir)["users"][0]["token"]


def test_add_rejects_duplicate_name(state_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert _run("add", "alice") == 0
    capsys.readouterr()

    assert _run("add", "alice") == 1
    captured = capsys.readouterr()
    assert "已存在" in captured.err
    assert len(_read_users(state_dir)["users"]) == 1


def test_add_rejects_invalid_name(state_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert _run("add", "bad name!") == 2
    assert "用户名无效" in capsys.readouterr().err
    assert not _users_file(state_dir).exists()


def test_add_rejects_unknown_role(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        _parser().parse_args(["users", "add", "alice", "--role", "root"])
    assert "invalid choice" in capsys.readouterr().err


def test_list_empty(capsys: pytest.CaptureFixture[str]) -> None:
    assert _run("list") == 0
    assert "暂无本地用户" in capsys.readouterr().out

    assert _run("list", "--json") == 0
    assert json.loads(capsys.readouterr().out) == {"users": []}


def test_tokens_are_unique(capsys: pytest.CaptureFixture[str]) -> None:
    assert _run("add", "alice", "--json") == 0
    first = json.loads(capsys.readouterr().out)["token"]
    assert _run("add", "bob", "--json") == 0
    second = json.loads(capsys.readouterr().out)["token"]
    assert first != second


def test_remove_user(state_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert _run("add", "alice") == 0
    capsys.readouterr()

    assert _run("remove", "alice", "--json") == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["removed"]["name"] == "alice"
    assert _read_users(state_dir) == {"users": []}

    assert _run("remove", "alice") == 1
    assert "不存在" in capsys.readouterr().err


def test_role_change(state_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert _run("add", "alice") == 0
    capsys.readouterr()

    assert _run("role", "alice", "operator", "--json") == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["user"] == {
        "name": "alice",
        "role": "operator",
        "created_at": payload["user"]["created_at"],
    }
    assert _read_users(state_dir)["users"][0]["role"] == "operator"

    assert _run("role", "bob", "admin") == 1
    assert "不存在" in capsys.readouterr().err


def test_last_admin_cannot_be_removed_without_force(
    state_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _run("add", "alice", "--role", "admin") == 0
    capsys.readouterr()

    assert _run("remove", "alice") == 1
    assert "唯一的 admin" in capsys.readouterr().err
    assert len(_read_users(state_dir)["users"]) == 1

    assert _run("remove", "alice", "--force") == 0
    assert _read_users(state_dir) == {"users": []}


def test_last_admin_cannot_be_demoted_without_force(
    state_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _run("add", "alice", "--role", "admin") == 0
    capsys.readouterr()

    assert _run("role", "alice", "viewer") == 1
    assert "唯一的 admin" in capsys.readouterr().err
    assert _read_users(state_dir)["users"][0]["role"] == "admin"

    assert _run("role", "alice", "viewer", "--force") == 0
    assert _read_users(state_dir)["users"][0]["role"] == "viewer"


def test_verify_token_returns_public_user(
    state_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _run("add", "alice", "--role", "admin", "--json") == 0
    payload = json.loads(capsys.readouterr().out)
    token = payload["token"]

    record = users.verify_token(_users_file(state_dir), token)
    assert record == payload["user"]
    assert "token" not in record

    assert users.verify_token(_users_file(state_dir), "wrong-token") is None
    assert users.verify_token(state_dir / "missing.json", token) is None
    assert users.verify_token(_users_file(state_dir), "") is None


def test_verify_token_tolerates_malformed_file(state_dir: Path) -> None:
    state_dir.mkdir(mode=0o700, parents=True)
    _users_file(state_dir).write_text("{not json", encoding="utf-8")
    assert users.verify_token(_users_file(state_dir), "anything") is None


def test_malformed_file_blocks_list_and_mutation(
    state_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    state_dir.mkdir(mode=0o700, parents=True)
    _users_file(state_dir).write_text("{not json", encoding="utf-8")

    assert _run("list", "--json") == 1
    assert "不是有效的" in capsys.readouterr().err

    assert _run("add", "alice") == 1
    assert "不是有效的" in capsys.readouterr().err
    assert _users_file(state_dir).read_text(encoding="utf-8") == "{not json"


def test_rewrites_restore_file_permissions(
    state_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _run("add", "alice") == 0
    capsys.readouterr()

    path = _users_file(state_dir)
    path.chmod(0o644)
    assert _run("role", "alice", "operator") == 0
    capsys.readouterr()
    assert _mode(path) == 0o600


def test_default_path_uses_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(users.LOCAL_HOME_ENV, raising=False)
    monkeypatch.setattr(Path, "home", classmethod(lambda _cls: tmp_path))

    assert users.local_home() == tmp_path / ".strix" / "local"
    assert users.default_users_path() == tmp_path / ".strix" / "local" / "users.json"


def test_missing_subcommand_prints_usage(capsys: pytest.CaptureFixture[str]) -> None:
    assert _run() == 0
    output = capsys.readouterr().out
    for command in ("add", "list", "remove", "role"):
        assert command in output


def test_help_lists_subcommands(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        _parser().parse_args(["users", "--help"])
    assert exc_info.value.code == 0
    output = capsys.readouterr().out
    for command in ("add", "list", "remove", "role"):
        assert command in output

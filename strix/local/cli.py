"""`strix local …` — self-hosted edition commands.

Each module under this package exposes ``register(subparsers)`` and ``run(args)``;
this file only composes them so the command tree stays in one place.
"""

from __future__ import annotations

import argparse
from typing import Any

from strix.local import intel, notify, runs, schedule, serve, users


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="strix local",
        description="本地版能力：运行历史、用户与角色、定时扫描、威胁情报、三方通知、只读看板。",
    )
    subparsers = parser.add_subparsers(dest="local_command")
    for module in (runs, users, schedule, intel, notify, serve):
        module.register(subparsers)
    return parser


def run_local(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args: Any = parser.parse_args(argv)
    handler = getattr(args, "func", None)
    if handler is None:
        parser.print_help()
        return 2
    return int(handler(args))

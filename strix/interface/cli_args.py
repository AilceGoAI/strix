"""Command-line argument parsing for the ``strix`` scan entrypoint."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import cast

from strix.config import apply_config_override
from strix.config.settings import DEFAULT_MAX_TURNS
from strix.core.paths import RUNS_DIR_NAME, run_dir_for, runtime_state_dir
from strix.interface.scan_setup import attach_workspace_mount, build_targets_info
from strix.interface.update_check import self_update
from strix.interface.utils import (
    check_mountable_dir,
    collect_local_sources,
    resolve_workspace_files,
    validate_config_file,
)
from strix.report.runs import list_run_summaries
from strix.skills import (
    SKILLS_DIR_ENV,
    env_skill_dirs,
    resolve_methodology,
    validate_requested_skills,
)


# Severities ``--fail-on`` accepts, most severe first.
FAIL_ON_SEVERITIES = ("critical", "high", "medium", "low", "info")


def get_version() -> str:
    try:
        from importlib.metadata import version

        return version("strix-agent")
    except Exception:
        return "unknown"


def _positive_budget(value: str) -> float:
    try:
        budget = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid float value: {value!r}") from exc
    import math

    if not math.isfinite(budget) or budget <= 0:
        raise argparse.ArgumentTypeError("must be a finite number greater than 0")
    return budget


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid int value: {value!r}") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be an integer greater than 0")
    return parsed


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Strix 多智能体网络安全渗透测试工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例：
  # Web 应用渗透测试
  strix --target https://example.com

  # GitHub 仓库分析
  strix --target https://github.com/user/repo
  strix --target git@github.com:user/repo.git

  # 本地代码分析
  strix --target ./my-project

  # API 规范测试（OpenAPI/Swagger 文件或 Postman collection 导出）
  strix --target ./openapi.yaml --target https://api.example.com
  strix --target ./collection.postman_collection.json

  # 按 id 实时拉取 Postman collection（需要 POSTMAN_API_KEY）；可选环境
  strix --target postman://<collection-uuid> --target https://api.example.com
  strix --target "postman://<collection-uuid>?env=<environment-uuid>"

  # 域名渗透测试
  strix --target example.com

  # IP 地址渗透测试
  strix --target 192.168.1.42

  # 多目标（例如：源码与已部署应用一起做白盒测试）
  strix --target https://github.com/user/repo --target https://example.com
  strix --target ./my-project --target https://staging.example.com --target https://prod.example.com

  # 从文件读取目标，每个非空、非注释行一个目标
  strix --target-list ./targets.txt

  # 自定义指令（内联）
  strix --target example.com --instruction "Focus on authentication vulnerabilities"

  # 自定义指令（从文件读取）
  strix --target example.com --instruction-file ./instructions.txt
  strix --target https://app.com --instruction-file /path/to/detailed_instructions.md

  # 放入沙箱工作区的额外文件
  strix --target ./my-project --workspace-file ./wordlist.txt
  strix --target https://app.com --workspace-file ./openapi.yaml:specs/openapi.yaml

Strix Cloud:
  strix cloud login
  strix cloud scans start --source . --yes --wait
  strix cloud                      # 列出全部云资源

  在 Strix Cloud 中运行渗透测试     https://app.strix.ai
  试用 Strix Enterprise             https://strix.ai/demo
        """,
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"strix {get_version()}",
    )

    parser.add_argument(
        "--update",
        action="store_true",
        help="将 strix 更新到最新版本后退出。独立二进制安装会自更新；"
        "pip/pipx/uv 安装则打印对应的升级命令。",
    )

    parser.add_argument(
        "-t",
        "--target",
        type=str,
        action="append",
        help="要测试的目标：URL、仓库、本地目录路径、域名、IP 地址、"
        "API 规范文件（OpenAPI/Swagger .json/.yaml 或 Postman collection 导出），或按 id 指定 "
        "Postman collection（postman://<collection-uuid>[?env=<environment-uuid>]，需要 "
        "POSTMAN_API_KEY）。本地目录会以可写方式挂载到沙箱中。"
        "可重复指定以进行多目标扫描。"
        "全新运行需要 --target 或 --target-list。",
    )
    parser.add_argument(
        "--target-list",
        type=str,
        action="append",
        metavar="PATH",
        help="包含目标的文件路径，每个非空、非注释行一个目标。"
        "可重复指定，也可与 --target 组合使用。",
    )
    parser.add_argument(
        "--instruction",
        type=str,
        help="渗透测试的自定义指令。可以是重点关注的具体漏洞类型"
        "（例如 'Focus on IDOR and XSS'）、"
        "测试方法（例如 'Perform thorough authentication testing'）、"
        "测试凭据（例如 'Use the following credentials to access the app: "
        "admin:password123'），"
        "或关注区域（例如 'Check login API endpoint for security issues'）。",
    )

    parser.add_argument(
        "--instruction-file",
        type=str,
        help="包含渗透测试详细自定义指令的文件路径。"
        "当指令较长或较复杂并已保存在文件中时使用此选项"
        "（例如 '--instruction-file ./detailed_instructions.txt'）。",
    )

    parser.add_argument(
        "--skills",
        type=str,
        metavar="NAMES",
        help="扫描开始前加载到根智能体的技能，以逗号分隔"
        "（例如 '--skills idor,mass_assignment,custom/my_method'）。使用裸名称 "
        "或 '<category>/<name>'。未知名称会中止运行并列出可用技能。",
    )

    parser.add_argument(
        "--skills-dir",
        dest="skills_dir",
        action="append",
        metavar="PATH",
        help="包含额外技能的目录，布局与内置技能集相同，为 '<category>/<name>.md'。"
        "可重复该选项以添加更多目录。路径与内置技能相同的技能会覆盖内置技能。"
        f"也会从 {SKILLS_DIR_ENV} 环境变量读取。",
    )

    parser.add_argument(
        "--methodology",
        action="append",
        metavar="FILE_OR_SKILL",
        help="带有测试方法论的 Markdown 文件或技能名称，作用于整个扫描"
        "（例如 '--methodology ./authz-method.md'）。Strix 会把它放入根智能体及其创建的"
        "每个智能体的系统提示词中。可重复该选项以指定多个。",
    )

    parser.add_argument(
        "--workspace-file",
        type=str,
        action="append",
        metavar="PATH[:DEST]",
        help="扫描开始前，把本机上的文件放入沙箱工作区，例如 wordlist、API 规范或笔记。"
        "可重复该选项以添加更多文件。DEST 是 /workspace 内的路径，默认为文件名"
        "（例如 '--workspace-file ./wordlist.txt:lists/wordlist.txt'）。Strix 会把文件"
        "复制到沙箱中，且位于所有目标目录之外。智能体可以编辑该副本。"
        "本机上的文件不会改变。",
    )

    parser.add_argument(
        "-n",
        "--non-interactive",
        action="store_true",
        help=(
            "以非交互模式运行（不启动 TUI，完成后退出）。"
            "默认为带 TUI 的交互模式。"
        ),
    )

    parser.add_argument(
        "--fail-on",
        dest="fail_on",
        type=str.lower,
        choices=FAIL_ON_SEVERITIES,
        default=None,
        metavar="SEVERITY",
        help=(
            "仅无头模式：只有当发现的严重级别达到或高于该值时才以 2 退出"
            "（critical、high、medium、low、info）。更低的发现仍会写入每个报告产物。"
            "严重级别无法识别的发现始终计入。"
            "默认：任何发现都以 2 退出。"
        ),
    )

    parser.add_argument(
        "-m",
        "--scan-mode",
        type=str,
        choices=["quick", "standard", "deep"],
        default="deep",
        help=(
            "扫描模式："
            "'quick' 用于快速 CI/CD 检查，"
            "'standard' 用于常规测试，"
            "'deep' 用于全面的安全审查（默认）。"
            "默认：deep。"
        ),
    )

    parser.add_argument(
        "--scope-mode",
        type=str,
        choices=["auto", "diff", "full"],
        default="auto",
        help=(
            "代码目标的扫描范围模式："
            "'auto' 在 CI/无头运行中启用 PR diff 范围，"
            "'diff' 强制只测变更文件，"
            "'full' 关闭 diff 范围。"
        ),
    )

    parser.add_argument(
        "--diff-base",
        type=str,
        help=(
            "用于比较的目标分支或提交（例如 origin/main）。"
            "默认为仓库的默认分支。"
        ),
    )

    parser.add_argument(
        "--config",
        type=str,
        help="自定义配置文件（JSON）的路径，用于替代 ~/.strix/cli-config.json",
    )

    parser.add_argument(
        "--mcp-config",
        type=str,
        metavar="PATH",
        help="MCP servers JSON 文件的路径，用于替代 ~/.strix/mcp-servers.json。",
    )

    parser.add_argument(
        "--mcp-server",
        dest="mcp_server",
        action="append",
        metavar="NAME",
        help="本次运行只使用这个 MCP 连接，按配置中的名称指定"
        "（可重复）。其他所有已配置的连接都会被跳过。",
    )

    parser.add_argument(
        "--mcp-exclude",
        dest="mcp_exclude",
        action="append",
        metavar="NAME",
        help="本次运行跳过这个 MCP 连接，按配置中的名称指定（可重复）。",
    )

    parser.add_argument(
        "--max-budget",
        "--max-budget-usd",
        dest="max_budget_usd",
        metavar="USD",
        type=_positive_budget,
        default=None,
        help=(
            "LLM 费用上限，单位为美元（> 0）。达到该上限时扫描会正常停止。"
            "接近上限时会向所有智能体发送分级的收尾警告。"
        ),
    )

    parser.add_argument(
        "--max-turns",
        dest="max_turns",
        metavar="N",
        type=_positive_int,
        default=DEFAULT_MAX_TURNS,
        help=(
            "每个智能体的最大轮次（> 0，默认 %(default)s）。达到该上限时每个智能体都会被"
            "强制停止；接近上限时会发送分级的收尾警告。"
        ),
    )

    parser.add_argument(
        "-r",
        "--resume",
        type=str,
        nargs="?",
        const="",
        metavar="RUN_NAME",
        help=(
            "按运行名称继续此前的扫描（./strix_runs/ 下的目录）。"
            "会恢复根智能体以及每个未终止子智能体的完整 LLM 历史与智能体拓扑。"
            "跳过新运行名的生成。不提供名称时，打开此前运行的选取列表。"
        ),
    )

    args = parser.parse_args()
    # Startup-resolved state lives alongside the parsed flags. The full schema
    # is established here so downstream code reads attributes directly.
    args.needs_setup = False
    args.resume_picker = False
    args.targets_info = []
    args.local_sources = []
    args.diff_scope = {"active": False}
    args.run_name = None

    if args.config:
        apply_config_override(validate_config_file(args.config))

    if args.mcp_config:
        mcp_config_path = Path(args.mcp_config).expanduser()
        if not mcp_config_path.is_file():
            parser.error(f"--mcp-config file not found: {args.mcp_config}")
        # The MCP loader reads this env var as its config-path override, so
        # setting it here makes the flag win over the default location.
        os.environ["STRIX_MCP_CONFIG"] = str(mcp_config_path)

    # The skill registry reads this env var on every lookup, so writing the flag
    # into it (ahead of any entries the user already set) is enough to register.
    if args.skills_dir:
        skill_dirs: list[str] = []
        for raw in args.skills_dir:
            skills_dir = Path(raw).expanduser()
            if not skills_dir.is_dir():
                parser.error(f"--skills-dir directory not found: {raw}")
            skill_dirs.append(str(skills_dir))
        skill_dirs.extend(str(d) for d in env_skill_dirs() if str(d) not in skill_dirs)
        os.environ[SKILLS_DIR_ENV] = os.pathsep.join(skill_dirs)

    args.skills = parse_skill_names(args.skills)
    if args.skills and (skills_error := validate_requested_skills(args.skills, max_skills=None)):
        parser.error(f"--skills: {skills_error}")

    methodology: list[dict[str, str]] = []
    for ref in args.methodology or []:
        try:
            name, content = resolve_methodology(ref)
        except ValueError as e:
            parser.error(f"--methodology: {e}")
        if all(item["name"] != name for item in methodology):
            methodology.append({"name": name, "content": content})
    args.methodology = methodology

    # The MCP loader reads these as its per-run include/exclude selection.
    if args.mcp_server:
        os.environ["STRIX_MCP_ONLY"] = ",".join(args.mcp_server)
    if args.mcp_exclude:
        os.environ["STRIX_MCP_EXCLUDE"] = ",".join(args.mcp_exclude)

    if args.update:
        sys.exit(0 if self_update() else 1)

    if args.fail_on and not args.non_interactive and terminal_attached():
        # Without a terminal main() switches to headless anyway, so the
        # flag is only out of place when the TUI would actually open.
        parser.error("--fail-on only applies to headless runs; add -n/--non-interactive.")

    if args.instruction and args.instruction_file:
        parser.error(
            "Cannot specify both --instruction and --instruction-file. Use one or the other."
        )

    if args.instruction_file:
        instruction_path = Path(args.instruction_file)
        try:
            with instruction_path.open(encoding="utf-8") as f:
                args.instruction = f.read().strip()
                if not args.instruction:
                    parser.error(f"Instruction file '{instruction_path}' is empty")
        except Exception as e:
            parser.error(f"Failed to read instruction file '{instruction_path}': {e}")

    try:
        args.workspace_files = resolve_workspace_files(getattr(args, "workspace_file", None))
    except ValueError as error:
        parser.error(f"--workspace-file: {error}")

    args.user_explicit_instruction = args.instruction if args.resume is not None else None
    # What the user actually asked for, kept apart from args.instruction because
    # prepare_run prepends the diff-scope preamble to that. This is the text the
    # transcript shows as their opening message.
    args.user_instruction = args.instruction or None

    if args.resume is not None:
        if args.target or args.target_list:
            parser.error(
                "Cannot combine --resume with --target/--target-list. "
                "--resume picks up where the prior run left off, including the "
                "original target list."
            )
        if not args.resume.strip():
            # A bare --resume: main() opens the inline picker of prior runs
            # before anything launches; headless has nobody to pick, so it
            # lists them.
            args.resume = None
            args.resume_picker = True
            if args.non_interactive:
                parser.error(resume_run_list_message("--resume needs a run name in headless mode."))
            if not list_run_summaries():
                parser.error(f"--resume: no runs in ./{RUNS_DIR_NAME} to resume")
            return args
        try:
            load_resume_state(args)
        except ResumeError as exc:
            parser.error(str(exc))
    else:
        if not args.target and not args.target_list:
            if args.non_interactive:
                parser.error(
                    "the following arguments are required: -t/--target or --target-list "
                    "(or use --resume <run_name> to continue a prior scan)"
                )
            # Interactive launch with no target: open the normal TUI on its
            # start screen, where the user gives a target or a bare prompt
            # before the scan starts.
            args.needs_setup = True
            return args

        try:
            build_targets_info(args)
        except ValueError as e:
            parser.error(str(e))

    return args


def terminal_attached() -> bool:
    """Whether the TUI can take over the terminal: a tty on both ends, not dumb."""
    if os.environ.get("TERM", "").strip().lower() == "dumb":
        return False
    return all(hasattr(stream, "isatty") and stream.isatty() for stream in (sys.stdin, sys.stdout))


class ResumeError(ValueError):
    """A prior run cannot be resumed as recorded; the message names why."""


def resume_run_list_message(lead: str) -> str:
    """``lead`` followed by the runs that ``--resume <name>`` would accept."""
    runs = list_run_summaries()
    if not runs:
        return f"{lead} There are no runs in ./{RUNS_DIR_NAME}."
    name_width = max(len(run.run_name) for run in runs)
    status_width = max(len(run.status) for run in runs)
    lines = [f"{lead} Runs in ./{RUNS_DIR_NAME}:"]
    lines.extend(
        f"  {run.run_name:<{name_width}}  {run.status:<{status_width}}  "
        f"{run.started_at[:19]:<19}  {run.target}".rstrip()
        for run in runs
    )
    return "\n".join(lines)


def parse_skill_names(raw: str | None) -> list[str]:
    """Split a comma-separated ``--skills`` value, dropping blanks and repeats."""
    names: list[str] = []
    for part in (raw or "").split(","):
        name = part.strip()
        if name and name not in names:
            names.append(name)
    return names


def load_resume_state(args: argparse.Namespace) -> None:
    """Populate ``args.targets_info`` and friends from a prior run's run.json.

    Raises :class:`ResumeError` when the run is missing, unreadable, or its
    recorded workspace is gone.
    """
    from strix.report.writer import read_run_record

    run_dir = run_dir_for(args.resume)
    state_path = run_dir / "run.json"
    if not state_path.exists():
        raise ResumeError(
            f"--resume {args.resume}: no such run "
            f"(missing {state_path}; remove --resume for a fresh start)"
        )
    try:
        state = read_run_record(run_dir)
    except (RuntimeError, TypeError) as exc:
        raise ResumeError(f"--resume {args.resume}: run.json unreadable: {exc}") from exc

    args.targets_info = state.get("targets_info") or []
    # A target-less run has no targets_info at all. It is driven by its
    # instruction, over a mounted working directory or over nothing when the
    # mount was declined, so either of those is enough to resume it.
    workspace_mount = state.get("workspace_mount") or None
    if not args.targets_info and not workspace_mount and not state.get("user_instruction"):
        raise ResumeError(f"--resume {args.resume}: run.json has no targets_info")

    for target in args.targets_info:
        if not isinstance(target, dict):
            continue
        details = target.get("details") or {}
        if target.get("type") == "local_code" and details.get("target_path"):
            try:
                check_mountable_dir(Path(details["target_path"]).expanduser())
            except ValueError as exc:
                raise ResumeError(f"--resume {args.resume}: {exc}") from exc
            continue
        if target.get("type") != "repository":
            continue
        cloned = details.get("cloned_repo_path")
        if not cloned:
            continue
        if not Path(cloned).expanduser().exists():
            raise ResumeError(
                f"--resume {args.resume}: cloned repo at {cloned} is missing. "
                f"It was deleted between runs. Pick a fresh --run-name to "
                f"re-clone, or restore the directory before resuming."
            )

    if args.instruction is None:
        args.instruction = state.get("instruction")
    if not args.skills:
        stored_skills = cast("list[str]", state.get("skills") or [])
        args.skills = [str(name) for name in stored_skills if str(name).strip()]
    if not args.methodology:
        stored_methodology = cast("list[dict[str, str]]", state.get("methodology") or [])
        args.methodology = [m for m in stored_methodology if isinstance(m, dict)]
    if not getattr(args, "user_instruction", None):
        args.user_instruction = state.get("user_instruction") or None
    args.local_sources = collect_local_sources(args.targets_info)
    # Remount the workspace the run was started with. The user already confirmed
    # this directory, so the target mount guard does not apply to it; it only has
    # to still be there.
    args.workspace_mount = workspace_mount

    # Replace the workspace files the run started with, unless this resume names
    # its own. The persisted record is revalidated like a fresh flag, so an
    # edited run.json cannot widen what a resume places. A file deleted between
    # runs is dropped rather than fatal: it is context for the agent, not scope.
    if not getattr(args, "workspace_files", None):
        restored = [
            f"{source_path}:{workspace_path}"
            for workspace_file in state.get("workspace_files") or []
            if isinstance(workspace_file, dict)
            and (source_path := Path(str(workspace_file.get("source_path") or ""))).is_file()
            and (workspace_path := str(workspace_file.get("workspace_path") or ""))
        ]
        try:
            args.workspace_files = resolve_workspace_files(restored)
        except ValueError as error:
            raise ResumeError(f"--resume {args.resume}: invalid workspace file: {error}") from error
    if workspace_mount:
        if not Path(workspace_mount).expanduser().is_dir():
            raise ResumeError(
                f"--resume {args.resume}: the working directory {workspace_mount} "
                f"is missing. Restore it before resuming, or start a fresh run."
            )
        attach_workspace_mount(args)
    if state.get("diff_scope"):
        args.diff_scope = state.get("diff_scope")
    persisted_scan_mode = state.get("scan_mode")
    if persisted_scan_mode and args.scan_mode == "deep":
        args.scan_mode = persisted_scan_mode
    agents_path = runtime_state_dir(run_dir) / "agents.json"
    if not agents_path.exists():
        raise ResumeError(
            f"--resume {args.resume}: missing {agents_path}. The run was "
            f"persisted but never reached its first agent snapshot — "
            f"there's nothing to resume from. Pick a fresh --run-name "
            f"or remove --resume to start over with the same targets."
        )

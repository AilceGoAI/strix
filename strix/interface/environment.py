"""Startup environment validation and Docker image management."""

import logging
import shutil
import sys

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from strix.config import IntegrationSettings, codex, load_settings
from strix.interface.utils import (
    check_docker_connection,
    image_exists,
    process_pull_line,
)
from strix.telemetry import report_error


logger = logging.getLogger(__name__)


def _missing_web_search_vars(integrations: IntegrationSettings) -> list[str]:
    """Mirror the web_search provider rules: which key(s) the selected provider needs."""
    if integrations.web_search_provider == "exa":
        return [] if integrations.exa_api_key else ["EXA_API_KEY"]
    if integrations.web_search_provider == "perplexity":
        return [] if integrations.perplexity_api_key else ["PERPLEXITY_API_KEY"]
    if integrations.exa_api_key or integrations.perplexity_api_key:
        return []
    return ["EXA_API_KEY", "PERPLEXITY_API_KEY"]


def validate_environment() -> None:
    logger.info("Validating environment")
    console = Console()
    missing_required_vars = []
    missing_optional_vars = []

    settings = load_settings()

    if codex.subscription_model(settings.llm.model):
        if not codex.is_authenticated():
            console.print(
                f"[red]STRIX_LLM={settings.llm.model} 使用你的 ChatGPT 订阅，"
                "但你尚未登录。[/] 请先运行 [cyan]strix auth login chatgpt[/]。"
            )
            report_error("subscription_not_signed_in")
            sys.exit(1)
        logger.info("Environment OK (ChatGPT subscription)")
        return

    if not settings.llm.model:
        missing_required_vars.append("STRIX_LLM")

    if not settings.llm.api_key:
        missing_optional_vars.append("LLM_API_KEY")

    if not settings.llm.api_base:
        missing_optional_vars.append("LLM_API_BASE")

    missing_optional_vars.extend(_missing_web_search_vars(settings.integrations))

    if missing_required_vars:
        error_text = Text()
        error_text.append("缺少必需的环境变量", style="bold red")
        error_text.append("\n\n", style="white")

        for var in missing_required_vars:
            error_text.append(f"• {var}", style="bold yellow")
            error_text.append(" 未设置\n", style="white")

        if missing_optional_vars:
            error_text.append("\n可选环境变量：\n", style="dim white")
            for var in missing_optional_vars:
                error_text.append(f"• {var}", style="dim yellow")
                error_text.append(" 未设置\n", style="dim white")

        error_text.append("\n必需环境变量：\n", style="white")
        for var in missing_required_vars:
            if var == "STRIX_LLM":
                error_text.append("• ", style="white")
                error_text.append("STRIX_LLM", style="bold cyan")
                error_text.append(
                    " - 使用的模型名称（例如 'openrouter/z-ai/glm-5.3' 或 "
                    "'anthropic/claude-opus-4-7'）\n",
                    style="white",
                )

        if missing_optional_vars:
            error_text.append("\n可选环境变量：\n", style="white")
            for var in missing_optional_vars:
                if var == "LLM_API_BASE":
                    error_text.append("• ", style="white")
                    error_text.append("LLM_API_BASE", style="bold cyan")
                    error_text.append(
                        " - 使用本地模型时的自定义 API 基础 URL（例如 Ollama、LMStudio）\n",
                        style="white",
                    )
                elif var == "PERPLEXITY_API_KEY":
                    error_text.append("• ", style="white")
                    error_text.append("PERPLEXITY_API_KEY", style="bold cyan")
                    error_text.append(
                        " - Perplexity AI 网页搜索的 API key（Exa 的替代方案）\n",
                        style="white",
                    )
                elif var == "EXA_API_KEY":
                    error_text.append("• ", style="white")
                    error_text.append("EXA_API_KEY", style="bold cyan")
                    error_text.append(
                        " - Exa 网页搜索的 API key（启用实时调研）\n",
                        style="white",
                    )
                elif var == "STRIX_REASONING_EFFORT":
                    error_text.append("• ", style="white")
                    error_text.append("STRIX_REASONING_EFFORT", style="bold cyan")
                    error_text.append(
                        " - 推理强度等级：none、minimal、low、medium、high、xhigh、"
                        "max（默认：high）\n",
                        style="white",
                    )

        error_text.append("\n配置示例：\n", style="white")
        error_text.append("export STRIX_LLM='openrouter/z-ai/glm-5.3'\n", style="dim white")

        if missing_optional_vars:
            for var in missing_optional_vars:
                if var == "LLM_API_BASE":
                    error_text.append(
                        "export LLM_API_BASE='http://localhost:11434'  "
                        "# 仅使用本地模型时需要\n",
                        style="dim white",
                    )
                elif var == "PERPLEXITY_API_KEY":
                    error_text.append(
                        "export PERPLEXITY_API_KEY='your-perplexity-key-here'\n", style="dim white"
                    )
                elif var == "EXA_API_KEY":
                    error_text.append("export EXA_API_KEY='your-exa-key-here'\n", style="dim white")
                elif var == "STRIX_REASONING_EFFORT":
                    error_text.append(
                        "export STRIX_REASONING_EFFORT='high'\n",
                        style="dim white",
                    )

        panel = Panel(
            error_text,
            title="[bold white]STRIX",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )

        logger.debug("Missing required env vars: %s", missing_required_vars)
        console.print("\n")
        console.print(panel)
        console.print()
        report_error("missing_required_config")
        sys.exit(1)
    logger.info(
        "Environment OK (optional missing: %s)",
        missing_optional_vars or "none",
    )


def check_docker_installed() -> None:
    if shutil.which("docker") is None:
        logger.debug("Docker CLI not found in PATH")
        console = Console()
        error_text = Text()
        error_text.append("未安装 Docker", style="bold red")
        error_text.append("\n\n", style="white")
        error_text.append("在 PATH 中未找到 'docker' CLI。\n", style="white")
        error_text.append(
            "请安装 Docker，并确保 'docker' 命令可用。\n\n", style="white"
        )

        panel = Panel(
            error_text,
            title="[bold white]STRIX",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )
        console.print("\n", panel, "\n")
        report_error("docker_not_installed")
        sys.exit(1)
    logger.debug("Docker CLI present")


def pull_docker_image() -> None:
    from docker.errors import DockerException

    console = Console()
    client = check_docker_connection()

    image = load_settings().runtime.image

    if image_exists(client, image):
        logger.debug("Docker image already present locally: %s", image)
        return

    logger.info("Pulling docker image: %s", image)
    console.print()
    console.print(f"[dim]正在拉取镜像[/] {image}")
    console.print("[dim yellow]仅在首次运行时发生，可能需要几分钟……[/]")
    console.print()

    with console.status("[bold cyan]正在下载镜像层……", spinner="dots") as status:
        try:
            layers_info: dict[str, str] = {}
            last_update = ""

            for line in client.api.pull(image, stream=True, decode=True):
                last_update = process_pull_line(line, layers_info, status, last_update)

        except DockerException as e:
            logger.debug("Failed to pull docker image %s", image, exc_info=True)
            console.print()
            error_text = Text()
            error_text.append("拉取镜像失败", style="bold red")
            error_text.append("\n\n", style="white")
            error_text.append(f"无法下载：{image}\n", style="white")
            error_text.append(str(e), style="dim red")

            panel = Panel(
                error_text,
                title="[bold white]STRIX",
                title_align="left",
                border_style="red",
                padding=(1, 2),
            )
            console.print(panel, "\n")
            report_error("image_pull_failed", e)
            sys.exit(1)

    logger.info("Docker image %s ready", image)
    success_text = Text()
    success_text.append("Docker 镜像已就绪", style="#22c55e")
    console.print(success_text)
    console.print()

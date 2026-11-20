# ruff: noqa: RUF002
"""本地威胁情报缓存（strix/local/intel.py）的测试。

全部用 ``tmp_path`` + ``STRIX_LOCAL_HOME`` 隔离，网络走本地 ``http.server``。
"""

from __future__ import annotations

import argparse
import json
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlparse

import pytest

from strix.local import intel


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


KEV_PAYLOAD: dict[str, Any] = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "catalogVersion": "2026.11.18",
    "dateReleased": "2026-11-18T00:00:00.000Z",
    "count": 2,
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j2",
            "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
            "dateAdded": "2021-12-10",
            "shortDescription": "Apache Log4j2 contains a remotely exploitable JNDI flaw.",
            "requiredAction": "Apply updates per vendor instructions.",
            "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": "Known",
            "notes": "",
            "cwes": ["CWE-502"],
        },
        {
            "cveID": "CVE-2023-0001",
            "vendorProject": "Example",
            "product": "Widget",
            "vulnerabilityName": "Example Widget Bug",
            "dateAdded": "2023-01-10",
            "shortDescription": "Example widget issue.",
            "requiredAction": "Patch.",
            "dueDate": "2023-01-31",
            "knownRansomwareCampaignUse": "Unknown",
            "notes": "",
            "cwes": [],
        },
    ],
}


def nvd_payload(cve_id: str) -> dict[str, Any]:
    return {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "published": "2021-12-10T10:15:09.143",
                    "lastModified": "2025-10-28T12:00:00.000",
                    "vulnStatus": "Analyzed",
                    "descriptions": [
                        {"lang": "en", "value": "Apache Log4j2 JNDI remote code execution."},
                        {"lang": "es", "value": "Ejecucion remota de codigo."},
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "source": "nvd@nist.gov",
                                "type": "Primary",
                                "cvssData": {
                                    "version": "3.1",
                                    "baseScore": 10.0,
                                    "baseSeverity": "CRITICAL",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                },
                            }
                        ]
                    },
                    "weaknesses": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "description": [{"lang": "en", "value": "CWE-502"}],
                        }
                    ],
                    "references": [
                        {"url": "https://logging.apache.org/log4j/2.x/security.html"},
                        {"url": "https://example.test/advisory"},
                    ],
                }
            }
        ],
    }


EMPTY_NVD_PAYLOAD: dict[str, Any] = {
    "resultsPerPage": 0,
    "startIndex": 0,
    "totalResults": 0,
    "vulnerabilities": [],
}


class FakeIntelServer:
    """可变路由表：每个路径一个响应队列，队列只有一个元素时重复使用。"""

    def __init__(self) -> None:
        self.kev_queue: list[tuple[int, Any]] = []
        self.nvd_queues: dict[str, list[tuple[int, Any]]] = {}
        self.kev_hits = 0
        self.nvd_hits: list[str] = []

    def set_kev(self, payload: Any, status: int = 200) -> None:
        self.kev_queue = [(status, payload)]

    def set_kev_responses(self, responses: list[tuple[int, Any]]) -> None:
        self.kev_queue = list(responses)

    def set_nvd(self, cve_id: str, payload: Any, status: int = 200) -> None:
        self.nvd_queues[cve_id] = [(status, payload)]

    def set_nvd_responses(self, cve_id: str, responses: list[tuple[int, Any]]) -> None:
        self.nvd_queues[cve_id] = list(responses)

    def _next(self, queue: list[tuple[int, Any]]) -> tuple[int, Any]:
        if not queue:
            return 404, {"error": "not configured"}
        if len(queue) == 1:
            return queue[0]
        return queue.pop(0)

    def handle_kev(self) -> tuple[int, Any]:
        self.kev_hits += 1
        return self._next(self.kev_queue)

    def handle_nvd(self, cve_id: str) -> tuple[int, Any]:
        self.nvd_hits.append(cve_id)
        return self._next(self.nvd_queues.get(cve_id, []))


def _make_handler(server: FakeIntelServer) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path == "/kev":
                status, payload = server.handle_kev()
            elif parsed.path == "/nvd":
                query = parse_qs(parsed.query)
                cve_id = (query.get("cveId") or [""])[0]
                status, payload = server.handle_nvd(cve_id)
            else:
                status, payload = 404, {"error": "unknown route"}
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _fmt: str, *_args: Any) -> None:
            return

    return Handler


@dataclass
class IntelEnv:
    home: Path
    server: FakeIntelServer
    httpd: ThreadingHTTPServer
    thread: threading.Thread = field(repr=False)


@pytest.fixture()
def intel_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[IntelEnv]:
    home = tmp_path / "local-home"
    monkeypatch.setenv("STRIX_LOCAL_HOME", str(home))
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    server = FakeIntelServer()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(server))
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    monkeypatch.setenv("STRIX_INTEL_KEV_URL", f"{base}/kev")
    monkeypatch.setenv("STRIX_INTEL_NVD_URL", f"{base}/nvd")
    try:
        yield IntelEnv(home=home, server=server, httpd=httpd, thread=thread)
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="strix local")
    subparsers = parser.add_subparsers(dest="command")
    intel.register(subparsers)
    return parser


def _run(argv: list[str]) -> int:
    args = _build_parser().parse_args(["intel", *argv])
    return intel.run(args)


def _json_output(capsys: pytest.CaptureFixture[str]) -> dict[str, Any]:
    return json.loads(capsys.readouterr().out)


# ---------------------------------------------------------------------------
# 命令注册
# ---------------------------------------------------------------------------


def test_register_exposes_update_and_lookup(capsys: pytest.CaptureFixture[str]) -> None:
    parser = _build_parser()
    with pytest.raises(SystemExit) as excinfo:
        parser.parse_args(["intel", "--help"])
    assert excinfo.value.code == 0
    help_text = capsys.readouterr().out
    assert "intel" in help_text
    assert "update" in help_text
    assert "lookup" in help_text


def test_intel_without_subcommand_prints_usage(capsys: pytest.CaptureFixture[str]) -> None:
    assert _run([]) == intel.EXIT_USAGE
    assert "strix local intel" in capsys.readouterr().out


def test_help_lists_chinese_descriptions(capsys: pytest.CaptureFixture[str]) -> None:
    parser = _build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["intel", "update", "--help"])
    assert "CISA KEV" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# update
# ---------------------------------------------------------------------------


def test_update_caches_kev_with_private_permissions(
    intel_env: IntelEnv, capsys: pytest.CaptureFixture[str]
) -> None:
    intel_env.server.set_kev(KEV_PAYLOAD)

    assert _run(["update", "--json", "--min-interval", "0"]) == intel.EXIT_OK
    output = _json_output(capsys)

    assert output["ok"] is True
    assert output["degraded"] is False
    assert output["kev"]["status"] == "updated"
    assert output["kev"]["count"] == 2
    assert output["kev"]["catalog_version"] == "2026.11.18"

    cache_file = intel_env.home / "intel" / "kev.json"
    cached = json.loads(cache_file.read_text(encoding="utf-8"))
    assert [item["cveID"] for item in cached["vulnerabilities"]] == [
        "CVE-2021-44228",
        "CVE-2023-0001",
    ]

    assert intel_env.home.stat().st_mode & 0o777 == 0o700
    assert (intel_env.home / "intel").stat().st_mode & 0o777 == 0o700
    assert cache_file.stat().st_mode & 0o777 == 0o600
    assert (intel_env.home / "intel" / "state.json").stat().st_mode & 0o777 == 0o600


def test_update_sends_nvd_request_for_requested_cve(intel_env: IntelEnv) -> None:
    intel_env.server.set_kev(KEV_PAYLOAD)
    intel_env.server.set_nvd("CVE-2021-44228", nvd_payload("CVE-2021-44228"))

    _run(["update", "--cve", "cve-2021-44228", "--json", "--min-interval", "0"])

    assert intel_env.server.nvd_hits == ["CVE-2021-44228"]
    record_file = intel_env.home / "intel" / "nvd" / "CVE-2021-44228.json"
    record = json.loads(record_file.read_text(encoding="utf-8"))
    assert record["record"]["id"] == "CVE-2021-44228"
    assert record_file.stat().st_mode & 0o777 == 0o600


def test_update_is_incremental_for_fresh_nvd_records(
    intel_env: IntelEnv, capsys: pytest.CaptureFixture[str]
) -> None:
    intel_env.server.set_kev(KEV_PAYLOAD)
    intel_env.server.set_nvd("CVE-2021-44228", nvd_payload("CVE-2021-44228"))

    _run(["update", "--cve", "CVE-2021-44228", "--json", "--min-interval", "0"])
    capsys.readouterr()

    assert _run(["update", "--cve", "CVE-2021-44228", "--json", "--min-interval", "0"]) == 0
    second = _json_output(capsys)
    assert second["nvd"]["skipped_fresh"] == 1
    assert second["nvd"]["updated"] == 0
    assert len(intel_env.server.nvd_hits) == 1

    assert (
        _run(
            [
                "update",
                "--cve",
                "CVE-2021-44228",
                "--max-age-days",
                "0",
                "--json",
                "--min-interval",
                "0",
            ]
        )
        == 0
    )
    third = _json_output(capsys)
    assert third["nvd"]["updated"] == 1
    assert len(intel_env.server.nvd_hits) == 2


def test_update_respects_nvd_limit_when_following_kev(intel_env: IntelEnv) -> None:
    intel_env.server.set_kev(KEV_PAYLOAD)
    for cve_id in ("CVE-2021-44228", "CVE-2023-0001"):
        intel_env.server.set_nvd(cve_id, nvd_payload(cve_id))

    _run(["update", "--limit", "1", "--json", "--min-interval", "0"])

    assert intel_env.server.nvd_hits == ["CVE-2021-44228"]


def test_update_ignores_limit_for_explicit_cves(intel_env: IntelEnv) -> None:
    intel_env.server.set_kev(KEV_PAYLOAD)
    cve_ids = ["CVE-2020-0001", "CVE-2020-0002"]
    for cve_id in cve_ids:
        intel_env.server.set_nvd(cve_id, nvd_payload(cve_id))

    argv = ["update", "--limit", "1", "--json", "--min-interval", "0"]
    for cve_id in cve_ids:
        argv.extend(["--cve", cve_id])
    _run(argv)

    assert intel_env.server.nvd_hits == cve_ids


def test_update_reports_cve_missing_from_nvd(
    intel_env: IntelEnv, capsys: pytest.CaptureFixture[str]
) -> None:
    intel_env.server.set_kev(KEV_PAYLOAD)
    intel_env.server.set_nvd("CVE-2020-9999", EMPTY_NVD_PAYLOAD)

    assert _run(["update", "--cve", "CVE-2020-9999", "--json", "--min-interval", "0"]) == 0
    output = _json_output(capsys)
    assert output["nvd"]["not_found"] == 1
    assert not (intel_env.home / "intel" / "nvd" / "CVE-2020-9999.json").exists()


def test_update_retries_transient_failures(
    intel_env: IntelEnv, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(intel, "_RETRY_DELAYS_S", (0.0, 0.0))
    intel_env.server.set_kev_responses([(500, {"error": "boom"}), (200, KEV_PAYLOAD)])

    assert _run(["update", "--retries", "1", "--json", "--min-interval", "0"]) == intel.EXIT_OK
    output = _json_output(capsys)
    assert output["kev"]["status"] == "updated"
    assert intel_env.server.kev_hits == 2


def test_update_falls_back_to_cache_when_network_fails(
    intel_env: IntelEnv, capsys: pytest.CaptureFixture[str]
) -> None:
    intel_env.server.set_kev(KEV_PAYLOAD)
    _run(["update", "--json", "--min-interval", "0"])
    capsys.readouterr()

    intel_env.server.set_kev_responses([(503, {"error": "down"})])
    code = _run(["update", "--retries", "0", "--json", "--min-interval", "0"])
    output = _json_output(capsys)

    assert code == intel.EXIT_OK
    assert output["degraded"] is True
    assert output["kev"]["status"] == "cached"
    assert output["kev"]["count"] == 2
    assert any("数据可能过期" in warning for warning in output["warnings"])


def test_update_without_cache_and_offline_exits_nonzero(
    intel_env: IntelEnv, capsys: pytest.CaptureFixture[str]
) -> None:
    intel_env.server.set_kev_responses([(503, {"error": "down"})])

    code = _run(["update", "--retries", "0", "--json", "--min-interval", "0"])
    output = _json_output(capsys)

    assert code == intel.EXIT_ERROR
    assert output["ok"] is False
    assert output["kev"]["status"] == "unavailable"
    assert any("本地也没有缓存" in warning for warning in output["warnings"])


def test_update_stops_after_consecutive_nvd_failures(intel_env: IntelEnv) -> None:
    intel_env.server.set_kev(KEV_PAYLOAD)
    cve_ids = ["CVE-2020-0001", "CVE-2020-0002", "CVE-2020-0003", "CVE-2020-0004"]
    for cve_id in cve_ids:
        intel_env.server.set_nvd_responses(cve_id, [(500, {"error": "boom"})])

    argv = ["update", "--retries", "0", "--json", "--min-interval", "0"]
    for cve_id in cve_ids:
        argv.extend(["--cve", cve_id])
    _run(argv)

    assert intel_env.server.nvd_hits == cve_ids[:3]


def test_update_rejects_invalid_cve_argument(
    intel_env: IntelEnv, capsys: pytest.CaptureFixture[str]
) -> None:
    intel_env.server.set_kev(KEV_PAYLOAD)

    assert _run(["update", "--cve", "not-a-cve", "--json"]) == intel.EXIT_USAGE
    output = _json_output(capsys)
    assert output["ok"] is False
    assert "CVE" in output["error"]


# ---------------------------------------------------------------------------
# lookup
# ---------------------------------------------------------------------------


def test_lookup_reads_cache_without_network(
    intel_env: IntelEnv, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    intel_env.server.set_kev(KEV_PAYLOAD)
    intel_env.server.set_nvd("CVE-2021-44228", nvd_payload("CVE-2021-44228"))
    _run(["update", "--cve", "CVE-2021-44228", "--json", "--min-interval", "0"])
    capsys.readouterr()

    def _fail(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("lookup 不应发起网络请求")

    monkeypatch.setattr(intel.requests, "get", _fail)

    assert _run(["lookup", "CVE-2021-44228", "--json"]) == intel.EXIT_OK
    output = _json_output(capsys)

    assert output["cve_id"] == "CVE-2021-44228"
    assert output["found"] is True
    assert output["kev"]["listed"] is True
    assert output["kev"]["vendor_project"] == "Apache"
    assert output["kev"]["due_date"] == "2021-12-24"
    assert output["nvd"]["severity"] == "CRITICAL"
    assert output["nvd"]["cvss"][0]["score"] == 10.0
    assert output["nvd"]["weaknesses"] == ["CWE-502"]
    assert output["warnings"] == []


def test_lookup_human_output_mentions_kev_and_cvss(
    intel_env: IntelEnv, capsys: pytest.CaptureFixture[str]
) -> None:
    intel_env.server.set_kev(KEV_PAYLOAD)
    intel_env.server.set_nvd("CVE-2021-44228", nvd_payload("CVE-2021-44228"))
    _run(["update", "--cve", "CVE-2021-44228", "--json", "--min-interval", "0"])
    capsys.readouterr()

    assert _run(["lookup", "cve-2021-44228"]) == intel.EXIT_OK
    text = capsys.readouterr().out
    assert "CVE-2021-44228" in text
    assert "CISA KEV：已收录" in text
    assert "CVSS v3.1：10.0" in text
    assert "CRITICAL" in text
    assert "Apache" in text


def test_lookup_unknown_cve_reports_hint(
    intel_env: IntelEnv, capsys: pytest.CaptureFixture[str]
) -> None:
    intel_env.server.set_kev(KEV_PAYLOAD)
    _run(["update", "--json", "--min-interval", "0"])
    capsys.readouterr()

    assert _run(["lookup", "CVE-2020-9999", "--json"]) == intel.EXIT_ERROR
    output = _json_output(capsys)
    assert output["found"] is False
    assert output["kev"] == {"listed": False}
    assert output["nvd"] is None
    assert any("CVE-2020-9999" in warning for warning in output["warnings"])

    assert _run(["lookup", "CVE-2020-9999"]) == intel.EXIT_ERROR
    text = capsys.readouterr().out
    assert "本地缓存中没有该 CVE 的记录" in text
    assert "strix local intel update --cve CVE-2020-9999" in text


def test_lookup_without_kev_cache_warns_unknown_kev_status(
    intel_env: IntelEnv, capsys: pytest.CaptureFixture[str]
) -> None:
    assert not (intel_env.home / "intel" / "kev.json").exists()

    assert _run(["lookup", "CVE-2021-44228", "--json"]) == intel.EXIT_ERROR
    output = _json_output(capsys)
    assert output["kev"] is None
    assert any("CISA KEV 缓存" in warning for warning in output["warnings"])


def test_lookup_flags_stale_cache(intel_env: IntelEnv, capsys: pytest.CaptureFixture[str]) -> None:
    stale_kev = dict(KEV_PAYLOAD)
    cache = {
        "schema_version": 1,
        "source": "cisa-kev",
        "source_url": "https://example.test/kev",
        "fetched_at": "2020-01-01T00:00:00Z",
        "catalog_version": "2020.01.01",
        "date_released": "2020-01-01T00:00:00.000Z",
        "count": len(stale_kev["vulnerabilities"]),
        "vulnerabilities": stale_kev["vulnerabilities"],
    }
    intel._write_json(intel.kev_cache_path(), cache)
    assert (intel_env.home / "intel" / "kev.json").exists()

    record = {
        "schema_version": 1,
        "source": "nvd-2.0",
        "source_url": "https://example.test/nvd",
        "cve_id": "CVE-2021-44228",
        "fetched_at": "2020-01-01T00:00:00Z",
        "record": nvd_payload("CVE-2021-44228")["vulnerabilities"][0]["cve"],
    }
    intel._write_json(intel.nvd_cache_path("CVE-2021-44228"), record)

    assert _run(["lookup", "CVE-2021-44228", "--json"]) == intel.EXIT_OK
    output = _json_output(capsys)
    assert output["found"] is True
    assert any("KEV 缓存" in warning and "可能过期" in warning for warning in output["warnings"])
    assert any("NVD 缓存" in warning and "可能过期" in warning for warning in output["warnings"])


def test_lookup_rejects_invalid_cve(
    intel_env: IntelEnv, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _run(["lookup", "CVE-21-x", "--json"]) == intel.EXIT_USAGE
    assert not (intel_env.home / "intel").exists()
    output = _json_output(capsys)
    assert output["ok"] is False


# ---------------------------------------------------------------------------
# 限速
# ---------------------------------------------------------------------------


def test_rate_limiter_spaces_requests() -> None:
    now = [100.0]
    sleeps: list[float] = []

    def clock() -> float:
        return now[0]

    def sleep(seconds: float) -> None:
        sleeps.append(seconds)
        now[0] += seconds

    limiter = intel.RateLimiter(2.0, clock=clock, sleep=sleep)
    limiter.wait()
    now[0] += 0.5
    limiter.wait()

    assert sleeps == [1.5]

    now[0] += 5.0
    limiter.wait()
    assert sleeps == [1.5]


def test_rate_limiter_disabled_by_zero_interval() -> None:
    sleeps: list[float] = []
    limiter = intel.RateLimiter(0.0, clock=lambda: 0.0, sleep=sleeps.append)
    limiter.wait()
    limiter.wait()
    assert sleeps == []

# ruff: noqa: RUF002, RUF003
"""本地威胁情报缓存：CISA KEV 目录与 NVD 2.0 单 CVE 记录。

缓存落在 ``~/.strix/local/intel/``（可用 ``STRIX_LOCAL_HOME`` 覆盖根目录）：

- ``kev.json``            CISA KEV 全量目录快照
- ``nvd/<CVE-ID>.json``   每个 CVE 一条 NVD 2.0 记录
- ``state.json``          最近一次更新摘要

``update`` 需要联网，``lookup`` 完全离线；网络失败时降级读缓存并在输出里说明数据可能过期。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import requests


if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Sequence


KEV_SOURCE_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
NVD_SOURCE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2

_SCHEMA_VERSION = 1
_CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

_KEV_STALE_DAYS = 7.0
_NVD_STALE_DAYS = 30.0
_NVD_DEFAULT_LIMIT = 10
_NVD_DEFAULT_MAX_AGE_DAYS = 7.0
_NVD_MAX_CONSECUTIVE_FAILURES = 3
_RETRY_DELAYS_S = (1.0, 2.0, 4.0, 8.0)
_MAX_RETRY_AFTER_S = 60.0
_RETRYABLE_STATUS = frozenset({403, 408, 425, 429, 500, 502, 503, 504})

_CVSS_METRIC_KEYS = (
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
)


class IntelError(Exception):
    """情报命令的失败，携带进程退出码。"""

    def __init__(self, message: str, *, exit_code: int = EXIT_ERROR) -> None:
        super().__init__(message)
        self.exit_code = exit_code


class IntelUsageError(IntelError):
    def __init__(self, message: str) -> None:
        super().__init__(message, exit_code=EXIT_USAGE)


class IntelNetworkError(IntelError):
    pass


# ---------------------------------------------------------------------------
# 状态目录与文件
# ---------------------------------------------------------------------------


def local_root() -> Path:
    """本地状态根目录：``STRIX_LOCAL_HOME`` 优先，否则 ``~/.strix/local``。"""
    override = os.environ.get("STRIX_LOCAL_HOME", "").strip()
    if override:
        return Path(override).expanduser()
    return Path.home() / ".strix" / "local"


def intel_dir() -> Path:
    return local_root() / "intel"


def nvd_dir() -> Path:
    return intel_dir() / "nvd"


def kev_cache_path() -> Path:
    return intel_dir() / "kev.json"


def state_cache_path() -> Path:
    return intel_dir() / "state.json"


def nvd_cache_path(cve_id: str) -> Path:
    return nvd_dir() / f"{cve_id}.json"


def _ensure_private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def _write_json(path: Path, payload: object) -> None:
    _ensure_private_dir(path.parent)
    text = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    temp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temp.write_text(text, encoding="utf-8")
    temp.chmod(stat.S_IRUSR | stat.S_IWUSR)
    temp.replace(path)
    path.chmod(0o600)


def _read_json(path: Path) -> object | None:
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    try:
        value: object = json.loads(raw)
    except ValueError:
        return None
    return value


def _as_dict(value: object) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return cast("dict[str, Any]", value)
    return None


def _text(value: object) -> str | None:
    if isinstance(value, str):
        cleaned = value.strip()
        return cleaned or None
    return None


def _clean(value: object) -> str | None:
    text = _text(value)
    if text is None:
        return None
    return _CONTROL_CHARS.sub("", text)


# ---------------------------------------------------------------------------
# 时间
# ---------------------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(moment: datetime) -> str:
    return moment.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_iso(value: object) -> datetime | None:
    text = _text(value)
    if text is None:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _age_days(value: object) -> float | None:
    moment = _parse_iso(value)
    if moment is None:
        return None
    return max(0.0, (_now() - moment).total_seconds() / 86400.0)


def _round_age(value: object) -> float | None:
    age = _age_days(value)
    return round(age, 2) if age is not None else None


def _age_text(value: object) -> str:
    age = _age_days(value)
    if age is None:
        return "未知"
    if age < 1:
        return "不足 1 天"
    return f"{age:.0f} 天"


def _time_text(value: object) -> str:
    moment = _parse_iso(value)
    if moment is None:
        return _text(value) or "未知"
    return moment.strftime("%Y-%m-%d %H:%M UTC")


# ---------------------------------------------------------------------------
# 环境配置
# ---------------------------------------------------------------------------


def _kev_url() -> str:
    return os.environ.get("STRIX_INTEL_KEV_URL", "").strip() or KEV_SOURCE_URL


def _nvd_url() -> str:
    return os.environ.get("STRIX_INTEL_NVD_URL", "").strip() or NVD_SOURCE_URL


def _nvd_api_key() -> str | None:
    return os.environ.get("NVD_API_KEY", "").strip() or None


def _default_min_interval() -> float:
    # NVD 公共配额约为每 30 秒 5 次，带 apiKey 时约为每 30 秒 50 次。
    return 0.6 if _nvd_api_key() else 6.0


def _normalize_cve(raw: str) -> str:
    candidate = raw.strip().upper()
    if not _CVE_ID_PATTERN.match(candidate):
        raise IntelUsageError(f"无效的 CVE 编号：{raw}（应形如 CVE-2024-1234）")
    return candidate


# ---------------------------------------------------------------------------
# HTTP：限速与重试
# ---------------------------------------------------------------------------


class RateLimiter:
    """保证相邻请求至少间隔 ``min_interval`` 秒，时钟与睡眠可注入以便测试。"""

    def __init__(
        self,
        min_interval: float,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._min_interval = max(0.0, min_interval)
        self._clock = clock
        self._sleep = sleep
        self._last: float | None = None

    def wait(self) -> None:
        now = self._clock()
        if self._min_interval > 0 and self._last is not None:
            remaining = self._min_interval - (now - self._last)
            if remaining > 0:
                self._sleep(remaining)
                now = self._clock()
        self._last = now


@dataclass
class HttpPolicy:
    timeout: float
    retries: int
    limiter: RateLimiter


def _retry_delay(attempt: int, retry_after: str | None) -> float:
    if retry_after:
        try:
            parsed = float(retry_after)
        except ValueError:
            parsed = 0.0
        if parsed > 0:
            return min(parsed, _MAX_RETRY_AFTER_S)
    return _RETRY_DELAYS_S[min(attempt, len(_RETRY_DELAYS_S) - 1)]


def _http_get_json(
    url: str,
    *,
    params: dict[str, str],
    headers: dict[str, str],
    policy: HttpPolicy,
    label: str,
) -> object | None:
    """GET 一个 JSON 资源；404 返回 ``None``，其余失败抛 :class:`IntelNetworkError`。"""
    attempts = policy.retries + 1
    last_error = "未知错误"
    for attempt in range(attempts):
        policy.limiter.wait()
        try:
            response = requests.get(
                url,
                params=params or None,
                headers=headers,
                timeout=policy.timeout,
            )
        except requests.RequestException as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            if attempt + 1 < attempts:
                time.sleep(_retry_delay(attempt, None))
            continue
        if response.status_code == 200:
            try:
                payload: object = response.json()
            except ValueError as exc:
                raise IntelNetworkError(f"{label} 返回了无法解析的 JSON") from exc
            return payload
        if response.status_code == 404:
            return None
        last_error = f"HTTP {response.status_code}"
        if response.status_code not in _RETRYABLE_STATUS:
            raise IntelNetworkError(f"{label} 请求失败：HTTP {response.status_code}")
        if attempt + 1 < attempts:
            time.sleep(_retry_delay(attempt, response.headers.get("Retry-After")))
    raise IntelNetworkError(f"{label} 请求失败：{last_error}")


# ---------------------------------------------------------------------------
# 数据获取
# ---------------------------------------------------------------------------


def fetch_kev(policy: HttpPolicy) -> dict[str, Any]:
    payload = _http_get_json(
        _kev_url(),
        params={},
        headers={"Accept": "application/json"},
        policy=policy,
        label="CISA KEV",
    )
    record = _as_dict(payload)
    entries = record.get("vulnerabilities") if record is not None else None
    if not isinstance(entries, list):
        raise IntelNetworkError("CISA KEV 数据结构不符合预期（缺少 vulnerabilities 字段）")
    normalized = [item for item in entries if isinstance(item, dict)]
    return {
        "schema_version": _SCHEMA_VERSION,
        "source": "cisa-kev",
        "source_url": _kev_url(),
        "fetched_at": _iso(_now()),
        "catalog_version": _text(record.get("catalogVersion")) if record else None,
        "date_released": _text(record.get("dateReleased")) if record else None,
        "count": len(normalized),
        "vulnerabilities": normalized,
    }


def fetch_nvd_record(cve_id: str, policy: HttpPolicy) -> dict[str, Any] | None:
    """拉取单个 CVE 的 NVD 2.0 记录；NVD 未收录时返回 ``None``。"""
    headers = {"Accept": "application/json"}
    api_key = _nvd_api_key()
    if api_key:
        headers["apiKey"] = api_key
    payload = _http_get_json(
        _nvd_url(),
        params={"cveId": cve_id},
        headers=headers,
        policy=policy,
        label=f"NVD {cve_id}",
    )
    record = _as_dict(payload)
    entries = record.get("vulnerabilities") if record is not None else None
    if not isinstance(entries, list):
        raise IntelNetworkError("NVD 数据结构不符合预期（缺少 vulnerabilities 字段）")
    if not entries:
        return None
    first = _as_dict(entries[0])
    cve = _as_dict(first.get("cve")) if first is not None else None
    if cve is None:
        return None
    return {
        "schema_version": _SCHEMA_VERSION,
        "source": "nvd-2.0",
        "source_url": _nvd_url(),
        "cve_id": cve_id,
        "fetched_at": _iso(_now()),
        "record": cve,
    }


# ---------------------------------------------------------------------------
# 缓存读取与解析
# ---------------------------------------------------------------------------


def load_kev_cache() -> dict[str, Any] | None:
    cache = _as_dict(_read_json(kev_cache_path()))
    if cache is None:
        return None
    if not isinstance(cache.get("vulnerabilities"), list):
        return None
    return cache


def _kev_index(cache: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if cache is None:
        return {}
    entries = cache.get("vulnerabilities")
    if not isinstance(entries, list):
        return {}
    index: dict[str, dict[str, Any]] = {}
    for item in entries:
        entry = _as_dict(item)
        if entry is None:
            continue
        cve_id = _text(entry.get("cveID"))
        if cve_id:
            index[cve_id.upper()] = entry
    return index


def load_nvd_cache(cve_id: str) -> dict[str, Any] | None:
    cache = _as_dict(_read_json(nvd_cache_path(cve_id)))
    if cache is None or _as_dict(cache.get("record")) is None:
        return None
    return cache


def _count_nvd_cache() -> int:
    try:
        return sum(1 for path in nvd_dir().glob("CVE-*.json") if path.is_file())
    except OSError:
        return 0


def _nvd_description(record: dict[str, Any]) -> str | None:
    descriptions = record.get("descriptions")
    if not isinstance(descriptions, list):
        return None
    fallback: str | None = None
    for item in descriptions:
        entry = _as_dict(item)
        if entry is None:
            continue
        value = _text(entry.get("value"))
        if value is None:
            continue
        if entry.get("lang") == "en":
            return value
        if fallback is None:
            fallback = value
    return fallback


def _nvd_metrics(record: dict[str, Any]) -> list[dict[str, Any]]:
    metrics = _as_dict(record.get("metrics"))
    if metrics is None:
        return []
    collected: list[dict[str, Any]] = []
    for key, default_version in _CVSS_METRIC_KEYS:
        items = metrics.get(key)
        if not isinstance(items, list):
            continue
        for item in items:
            entry = _as_dict(item)
            if entry is None:
                continue
            data = _as_dict(entry.get("cvssData"))
            if data is None:
                continue
            raw_score = data.get("baseScore")
            score = float(raw_score) if isinstance(raw_score, (int, float)) else None
            collected.append(
                {
                    "version": _text(data.get("version")) or default_version,
                    "source": _text(entry.get("source")),
                    "type": _text(entry.get("type")),
                    "score": score,
                    "severity": _text(data.get("baseSeverity")) or _text(entry.get("baseSeverity")),
                    "vector": _text(data.get("vectorString")),
                }
            )
    return collected


def _nvd_weaknesses(record: dict[str, Any]) -> list[str]:
    weaknesses = record.get("weaknesses")
    if not isinstance(weaknesses, list):
        return []
    found: list[str] = []
    for item in weaknesses:
        entry = _as_dict(item)
        if entry is None:
            continue
        descriptions = entry.get("description")
        if not isinstance(descriptions, list):
            continue
        for description in descriptions:
            desc = _as_dict(description)
            value = _text(desc.get("value")) if desc is not None else None
            if value is not None and value not in found:
                found.append(value)
    return found


def _nvd_reference_urls(record: dict[str, Any]) -> list[str]:
    references = record.get("references")
    if not isinstance(references, list):
        return []
    urls: list[str] = []
    for item in references:
        entry = _as_dict(item)
        url = _text(entry.get("url")) if entry is not None else None
        if url is not None:
            urls.append(url)
    return urls


# ---------------------------------------------------------------------------
# 更新
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class UpdateOptions:
    cve_ids: tuple[str, ...]
    limit: int
    max_age_days: float
    skip_kev: bool
    skip_nvd: bool
    policy: HttpPolicy


def _kev_section_fields(cache: dict[str, Any]) -> dict[str, Any]:
    return {
        "count": cache.get("count"),
        "catalog_version": cache.get("catalog_version"),
        "date_released": cache.get("date_released"),
        "fetched_at": cache.get("fetched_at"),
        "age_days": _round_age(cache.get("fetched_at")),
    }


def _sync_kev(options: UpdateOptions) -> tuple[dict[str, Any], dict[str, Any] | None, bool]:
    cached = load_kev_cache()
    section: dict[str, Any] = {"status": "skipped", "error": None}
    degraded = False
    if options.skip_kev:
        if cached is not None:
            section.update(_kev_section_fields(cached))
        return section, cached, degraded
    try:
        fresh = fetch_kev(options.policy)
    except IntelNetworkError as exc:
        section["error"] = str(exc)
        if cached is None:
            section["status"] = "unavailable"
        else:
            section["status"] = "cached"
            section.update(_kev_section_fields(cached))
            degraded = True
        return section, cached, degraded
    _write_json(kev_cache_path(), fresh)
    section["status"] = "updated"
    section.update(_kev_section_fields(fresh))
    return section, fresh, degraded


def _nvd_candidates(
    options: UpdateOptions,
    kev_cache: dict[str, Any] | None,
    previous_index: dict[str, dict[str, Any]],
) -> list[str]:
    if options.cve_ids:
        return list(dict.fromkeys(options.cve_ids))
    current = list(_kev_index(kev_cache))
    new_ids = [cve_id for cve_id in current if cve_id not in previous_index]
    old_ids = [cve_id for cve_id in current if cve_id in previous_index]
    return new_ids + old_ids


def _sync_nvd(
    options: UpdateOptions,
    kev_cache: dict[str, Any] | None,
    previous_index: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    section: dict[str, Any] = {
        "status": "skipped",
        "requested": 0,
        "updated": 0,
        "skipped_fresh": 0,
        "not_found": 0,
        "failed": 0,
        "errors": [],
        "total_cached": _count_nvd_cache(),
    }
    if options.skip_nvd:
        return section

    candidates = _nvd_candidates(options, kev_cache, previous_index)
    section["requested"] = len(candidates)
    fetched = 0
    consecutive_failures = 0
    for cve_id in candidates:
        if options.limit > 0 and fetched >= options.limit:
            break
        cached = load_nvd_cache(cve_id)
        cached_at = cached.get("fetched_at") if cached is not None else None
        age = _age_days(cached_at)
        if cached is not None and age is not None and age <= options.max_age_days:
            section["skipped_fresh"] += 1
            continue
        fetched += 1
        try:
            record = fetch_nvd_record(cve_id, options.policy)
        except IntelNetworkError as exc:
            section["failed"] += 1
            section["errors"].append(f"{cve_id}: {exc}")
            consecutive_failures += 1
            if consecutive_failures >= _NVD_MAX_CONSECUTIVE_FAILURES:
                section["errors"].append("连续多次失败，已中止本次 NVD 更新")
                break
            continue
        consecutive_failures = 0
        if record is None:
            section["not_found"] += 1
            continue
        _write_json(nvd_cache_path(cve_id), record)
        section["updated"] += 1

    section["total_cached"] = _count_nvd_cache()
    if fetched == 0:
        section["status"] = "cached" if section["skipped_fresh"] else "empty"
    elif section["failed"] == 0:
        section["status"] = "updated"
    elif section["updated"] == 0:
        section["status"] = "failed"
    else:
        section["status"] = "partial"
    return section


def _policy_from_args(args: argparse.Namespace) -> HttpPolicy:
    raw_interval = getattr(args, "min_interval", None)
    interval = _default_min_interval() if raw_interval is None else float(raw_interval)
    timeout = float(getattr(args, "timeout", 30.0) or 30.0)
    retries = int(getattr(args, "retries", 2) or 0)
    return HttpPolicy(
        timeout=max(0.1, timeout),
        retries=max(0, retries),
        limiter=RateLimiter(interval),
    )


def _update(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    raw_cves: Sequence[str] = getattr(args, "cve", None) or ()
    cve_ids = tuple(dict.fromkeys(_normalize_cve(str(item)) for item in raw_cves))
    raw_limit = getattr(args, "limit", _NVD_DEFAULT_LIMIT)
    limit = max(0, int(raw_limit if raw_limit is not None else _NVD_DEFAULT_LIMIT))
    if cve_ids:
        # 显式点名要查的 CVE 不应被 --limit 截断，limit 只用于跟随 KEV 的批量增量。
        limit = 0
    options = UpdateOptions(
        cve_ids=cve_ids,
        limit=limit,
        max_age_days=max(0.0, float(getattr(args, "max_age_days", _NVD_DEFAULT_MAX_AGE_DAYS))),
        skip_kev=bool(getattr(args, "no_kev", False)),
        skip_nvd=bool(getattr(args, "no_nvd", False)),
        policy=_policy_from_args(args),
    )

    _ensure_private_dir(local_root())
    _ensure_private_dir(intel_dir())

    previous_index = _kev_index(load_kev_cache())
    kev_section, kev_cache, kev_degraded = _sync_kev(options)
    nvd_section = _sync_nvd(options, kev_cache, previous_index)

    warnings: list[str] = []
    if kev_section["status"] == "cached":
        warnings.append(
            "CISA KEV 更新失败，沿用本地缓存"
            f"（缓存时间 {_time_text(kev_section.get('fetched_at'))}），数据可能过期："
            f"{kev_section.get('error')}"
        )
    elif kev_section["status"] == "unavailable":
        warnings.append(f"CISA KEV 更新失败，本地也没有缓存：{kev_section.get('error')}")
    if options.cve_ids and options.skip_nvd:
        warnings.append("已指定 --cve，但同时使用了 --no-nvd，未拉取 NVD 记录。")
    nvd_errors = list(nvd_section["errors"])
    warnings.extend(f"NVD：{message}" for message in nvd_errors[:3])
    if len(nvd_errors) > 3:
        warnings.append(f"NVD：另有 {len(nvd_errors) - 3} 条失败记录未逐条列出。")
    if nvd_section["status"] == "failed":
        warnings.append("本次没有刷新任何 NVD 记录，已保留原有缓存（如果存在）。")

    usable = kev_cache is not None or nvd_section["total_cached"] > 0
    exit_code = EXIT_OK if usable else EXIT_ERROR
    report: dict[str, Any] = {
        "ok": exit_code == EXIT_OK,
        "degraded": kev_degraded,
        "cache_dir": str(intel_dir()),
        "kev": kev_section,
        "nvd": nvd_section,
        "warnings": warnings,
    }
    try:
        _write_json(
            state_cache_path(),
            {
                "schema_version": _SCHEMA_VERSION,
                "last_update": _iso(_now()),
                "exit_code": exit_code,
                "kev": kev_section,
                "nvd": {
                    key: nvd_section[key]
                    for key in ("status", "updated", "skipped_fresh", "not_found", "failed")
                },
            },
        )
    except OSError:
        warnings.append("更新摘要未能写入 state.json，缓存数据本身不受影响。")
    return report, exit_code


# ---------------------------------------------------------------------------
# 离线查询
# ---------------------------------------------------------------------------


def _kev_entry_section(entry: dict[str, Any], cache: dict[str, Any]) -> dict[str, Any]:
    cwes = entry.get("cwes")
    cwe_values = (
        [value for value in cwes if isinstance(value, str)] if isinstance(cwes, list) else []
    )
    return {
        "listed": True,
        "vulnerability_name": _clean(entry.get("vulnerabilityName")),
        "vendor_project": _clean(entry.get("vendorProject")),
        "product": _clean(entry.get("product")),
        "short_description": _clean(entry.get("shortDescription")),
        "required_action": _clean(entry.get("requiredAction")),
        "date_added": _clean(entry.get("dateAdded")),
        "due_date": _clean(entry.get("dueDate")),
        "ransomware": _clean(entry.get("knownRansomwareCampaignUse")),
        "notes": _clean(entry.get("notes")),
        "cwes": cwe_values,
        "fetched_at": cache.get("fetched_at"),
        "age_days": _round_age(cache.get("fetched_at")),
    }


def _nvd_section(cache: dict[str, Any]) -> dict[str, Any] | None:
    record = _as_dict(cache.get("record"))
    if record is None:
        return None
    metrics = _nvd_metrics(record)
    severity = next((item["severity"] for item in metrics if item["severity"]), None)
    return {
        "published": _clean(record.get("published")),
        "last_modified": _clean(record.get("lastModified")),
        "status": _clean(record.get("vulnStatus")),
        "description": _clean(_nvd_description(record)),
        "severity": severity,
        "cvss": metrics,
        "weaknesses": _nvd_weaknesses(record),
        "reference_count": len(_nvd_reference_urls(record)),
        "references": _nvd_reference_urls(record)[:5],
        "fetched_at": cache.get("fetched_at"),
        "age_days": _round_age(cache.get("fetched_at")),
    }


def _lookup(cve_id: str) -> dict[str, Any]:
    warnings: list[str] = []
    kev_cache = load_kev_cache()
    kev_entry = _kev_index(kev_cache).get(cve_id)
    kev_section: dict[str, Any] | None = None
    if kev_cache is None:
        warnings.append(
            "本地没有 CISA KEV 缓存，无法判断该 CVE 是否已被在野利用；"
            "运行 `strix local intel update` 拉取。"
        )
    else:
        kev_age = _age_days(kev_cache.get("fetched_at"))
        if kev_age is None or kev_age > _KEV_STALE_DAYS:
            warnings.append(
                f"CISA KEV 缓存已有 {_age_text(kev_cache.get('fetched_at'))}未更新，"
                "数据可能过期；运行 `strix local intel update` 刷新。"
            )
        kev_section = (
            _kev_entry_section(kev_entry, kev_cache) if kev_entry is not None else {"listed": False}
        )

    nvd_cache = load_nvd_cache(cve_id)
    nvd_section = _nvd_section(nvd_cache) if nvd_cache is not None else None
    if nvd_section is None:
        warnings.append(
            f"本地没有 {cve_id} 的 NVD 记录；运行 `strix local intel update --cve {cve_id}` 拉取。"
        )
    else:
        nvd_age = _age_days(nvd_section.get("fetched_at"))
        if nvd_age is None or nvd_age > _NVD_STALE_DAYS:
            warnings.append(
                f"NVD 缓存已有 {_age_text(nvd_section.get('fetched_at'))}未更新，"
                "数据可能过期；可重新运行 update 刷新。"
            )

    found = kev_entry is not None or nvd_section is not None
    return {
        "cve_id": cve_id,
        "found": found,
        "cache_dir": str(intel_dir()),
        "kev": kev_section,
        "nvd": nvd_section,
        "warnings": warnings,
    }


# ---------------------------------------------------------------------------
# 输出
# ---------------------------------------------------------------------------


def _emit(text: str) -> None:
    sys.stdout.write(text if text.endswith("\n") else f"{text}\n")
    sys.stdout.flush()


def _emit_json(payload: object) -> None:
    _emit(json.dumps(payload, ensure_ascii=False, indent=2))


def _emit_error(message: str, *, json_mode: bool) -> None:
    if json_mode:
        _emit_json({"ok": False, "error": message})
        return
    sys.stderr.write(f"错误：{message}\n")
    sys.stderr.flush()


def _warning_lines(warnings: Sequence[str]) -> list[str]:
    if not warnings:
        return []
    return ["", "提示：", *(f"  - {warning}" for warning in warnings)]


def _describe_kev(section: dict[str, Any]) -> str:
    status = section.get("status")
    if status == "skipped":
        return "  CISA KEV：已跳过（--no-kev）"
    if status == "unavailable":
        return "  CISA KEV：更新失败，本地无缓存，KEV 状态未知"
    if status == "cached":
        return (
            f"  CISA KEV：更新失败，沿用本地缓存 {section.get('count')} 条"
            f"（缓存时间 {_time_text(section.get('fetched_at'))}），数据可能过期"
        )
    return (
        f"  CISA KEV：已更新，收录 {section.get('count')} 条"
        f"（目录版本 {section.get('catalog_version') or '未知'}）"
    )


def _describe_nvd(section: dict[str, Any]) -> str:
    status = section.get("status")
    head = "  NVD："
    if status == "skipped":
        return f"{head}已跳过（--no-nvd）"
    if status == "empty":
        return f"{head}没有需要拉取的 CVE（本地共 {section.get('total_cached')} 条）"
    if status == "cached":
        return (
            f"{head}本地记录仍然新鲜，跳过 {section.get('skipped_fresh')} 条"
            f"（本地共 {section.get('total_cached')} 条）"
        )
    if status == "failed":
        return (
            f"{head}本次 {section.get('requested')} 条全部失败"
            f"（本地共 {section.get('total_cached')} 条）"
        )
    return (
        f"{head}新增或更新 {section.get('updated')} 条，"
        f"跳过新鲜缓存 {section.get('skipped_fresh')} 条，"
        f"未收录 {section.get('not_found')} 条，失败 {section.get('failed')} 条"
        f"（本地共 {section.get('total_cached')} 条）"
    )


def _print_update(report: dict[str, Any]) -> None:
    if report["degraded"]:
        headline = (
            "威胁情报缓存更新完成，但部分来源回退到本地缓存，数据可能过期"
            f"（缓存目录：{report['cache_dir']}）"
        )
    elif report["ok"]:
        headline = f"威胁情报缓存已更新（缓存目录：{report['cache_dir']}）"
    else:
        headline = f"未能取得可用的威胁情报数据（缓存目录：{report['cache_dir']}）"
    lines = [
        headline,
        _describe_kev(report["kev"]),
        _describe_nvd(report["nvd"]),
        *_warning_lines(report["warnings"]),
    ]
    if not report["ok"]:
        lines.append("")
        lines.append("  请检查网络或代理设置后重试；已有的本地缓存不受影响。")
    _emit("\n".join(lines))


def _lookup_path_hint(cve_id: str) -> str:
    return (
        f"运行 `strix local intel update --cve {cve_id}` 拉取 NVD 记录，"
        "或运行 `strix local intel update` 更新 CISA KEV 目录后重试。"
    )


def _nvd_output_lines(nvd: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    severity = nvd.get("severity")
    if severity:
        lines.append(f"  严重性：{severity}")
    for metric in nvd.get("cvss", []):
        score = metric.get("score")
        parts = [
            f"CVSS v{metric.get('version')}：{'未知' if score is None else score}",
            metric.get("severity") or "",
            metric.get("type") or "",
            metric.get("source") or "",
        ]
        lines.append(f"  {' '.join(part for part in parts if part)}")
        if metric.get("vector"):
            lines.append(f"         {metric['vector']}")
    if nvd.get("published"):
        lines.append(f"  发布：{nvd['published']}")
    if nvd.get("last_modified"):
        lines.append(f"  最后修改：{nvd['last_modified']}")
    if nvd.get("weaknesses"):
        lines.append(f"  CWE：{', '.join(nvd['weaknesses'])}")
    if nvd.get("reference_count"):
        lines.append(f"  参考链接：{nvd['reference_count']} 条")
        lines.extend(f"    {url}" for url in nvd.get("references", [])[:3])
    return lines


def _kev_output_lines(kev: dict[str, Any]) -> list[str]:
    if not kev.get("listed"):
        return ["CISA KEV：本地目录中未收录"]
    detail = [f"加入 {kev.get('date_added') or '未知'}"]
    if kev.get("due_date"):
        detail.append(f"修复截止 {kev['due_date']}")
    if kev.get("ransomware"):
        detail.append(f"勒索软件利用 {kev['ransomware']}")
    lines = [f"CISA KEV：已收录（{'；'.join(detail)}）"]
    if kev.get("vulnerability_name"):
        lines.append(f"  名称：{kev['vulnerability_name']}")
    vendor = kev.get("vendor_project") or "未知"
    product = kev.get("product") or "未知"
    lines.append(f"  厂商/产品：{vendor} / {product}")
    if kev.get("required_action"):
        lines.append(f"  必需操作：{kev['required_action']}")
    return lines


def _cache_output_lines(nvd: object, kev: object) -> list[str]:
    cache_lines: list[str] = []
    if isinstance(nvd, dict) and nvd.get("fetched_at"):
        cache_lines.append(
            f"  NVD：{_time_text(nvd['fetched_at'])}（{_age_text(nvd['fetched_at'])}前）"
        )
    if isinstance(kev, dict) and kev.get("fetched_at"):
        cache_lines.append(
            f"  CISA KEV：{_time_text(kev['fetched_at'])}（{_age_text(kev['fetched_at'])}前）"
        )
    return cache_lines


def _print_lookup(result: dict[str, Any]) -> None:
    cve_id = result["cve_id"]
    if not result["found"]:
        lines = [f"{cve_id}：本地缓存中没有该 CVE 的记录。", f"  {_lookup_path_hint(cve_id)}"]
        lines.extend(_warning_lines(result["warnings"]))
        _emit("\n".join(lines))
        return

    nvd = result.get("nvd")
    kev = result.get("kev")
    lines = [cve_id]

    description = nvd.get("description") if isinstance(nvd, dict) else None
    if description is None and isinstance(kev, dict):
        description = kev.get("short_description")
    if description:
        lines.append(f"  描述：{description}")

    if isinstance(nvd, dict):
        lines.extend(_nvd_output_lines(nvd))
    if isinstance(kev, dict):
        lines.extend(_kev_output_lines(kev))

    cache_lines = _cache_output_lines(nvd, kev)
    if cache_lines:
        lines.append("本地缓存：")
        lines.extend(cache_lines)

    lines.extend(_warning_lines(result["warnings"]))
    _emit("\n".join(lines))


def _print_usage() -> None:
    _emit(
        "用法：strix local intel {update,lookup}\n"
        "  strix local intel update [--cve CVE-ID ...]   拉取 CISA KEV 与 NVD 记录到本地缓存\n"
        "  strix local intel lookup <CVE-ID>             离线查询本地缓存\n"
        "两个子命令都支持 --json。"
    )


# ---------------------------------------------------------------------------
# 命令注册与入口
# ---------------------------------------------------------------------------


_EPILOG = (
    "环境变量：STRIX_LOCAL_HOME 覆盖本地状态根目录；NVD_API_KEY 提高 NVD 限速；"
    "STRIX_INTEL_KEV_URL / STRIX_INTEL_NVD_URL 覆盖数据源（离线镜像或测试用）。"
)


class _LocalHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """把 argparse 的 ``usage:`` 前缀换成中文，其余排版保持原样。"""

    def add_usage(
        self,
        usage: str | None,
        actions: Iterable[Any],
        groups: Iterable[Any],
        prefix: str | None = None,
    ) -> None:
        super().add_usage(usage, actions, groups, prefix="用法：" if prefix is None else prefix)


def _localized_parser(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    parser._positionals.title = "位置参数"
    parser._optionals.title = "选项"
    parser.add_argument("-h", "--help", action="help", help="显示帮助信息并退出")
    return parser


def register(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """在 ``strix local`` 的子命令表里挂载 ``intel``。"""
    parser = _localized_parser(
        subparsers.add_parser(
            "intel",
            help="本地威胁情报缓存（CISA KEV 与 NVD 2.0）",
            description="维护并离线查询本地 CVE 威胁情报缓存。",
            epilog=_EPILOG,
            formatter_class=_LocalHelpFormatter,
            add_help=False,
        )
    )
    parser.set_defaults(func=run)
    commands = parser.add_subparsers(dest="intel_command", metavar="{update,lookup}")

    update = _localized_parser(
        commands.add_parser(
            "update",
            help="联网更新本地缓存（KEV 全量，NVD 按 CVE 增量）",
            description="拉取 CISA KEV 目录，并按 CVE 增量拉取 NVD 2.0 记录；失败时保留旧缓存。",
            formatter_class=_LocalHelpFormatter,
            add_help=False,
        )
    )
    update.add_argument(
        "--cve",
        action="append",
        default=[],
        metavar="CVE-ID",
        help="只拉取指定 CVE 的 NVD 记录，可重复指定",
    )
    update.add_argument(
        "--limit",
        type=int,
        default=_NVD_DEFAULT_LIMIT,
        metavar="N",
        help="跟随 KEV 增量时本次最多拉取多少条 NVD 记录"
        f"（默认 {_NVD_DEFAULT_LIMIT}，0 表示不限；显式 --cve 不受此限制）",
    )
    update.add_argument(
        "--max-age-days",
        type=float,
        default=_NVD_DEFAULT_MAX_AGE_DAYS,
        metavar="DAYS",
        help=f"NVD 记录超过该天数才重新拉取（默认 {_NVD_DEFAULT_MAX_AGE_DAYS:g}）",
    )
    update.add_argument("--no-kev", action="store_true", help="跳过 CISA KEV 更新")
    update.add_argument("--no-nvd", action="store_true", help="跳过 NVD 更新")
    update.add_argument(
        "--min-interval",
        type=float,
        default=None,
        metavar="SECONDS",
        help="两次 NVD 请求的最小间隔（默认无 NVD_API_KEY 时 6 秒，有时 0.6 秒）",
    )
    update.add_argument(
        "--retries",
        type=int,
        default=2,
        metavar="N",
        help="单个请求失败后的重试次数（默认 2）",
    )
    update.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        metavar="SECONDS",
        help="单次请求超时（默认 30 秒）",
    )
    update.add_argument("--json", action="store_true", help="以 JSON 输出结果")
    update.set_defaults(func=run)

    lookup = _localized_parser(
        commands.add_parser(
            "lookup",
            help="离线查询本地缓存中的 CVE 记录",
            description="完全离线地查询本地缓存的 CISA KEV 收录状态与 NVD 记录。",
            formatter_class=_LocalHelpFormatter,
            add_help=False,
        )
    )
    lookup.add_argument("cve_id", metavar="CVE-ID", help="CVE 编号，例如 CVE-2021-44228")
    lookup.add_argument("--json", action="store_true", help="以 JSON 输出结果")
    lookup.set_defaults(func=run)


def _command_update(args: argparse.Namespace, json_mode: bool) -> int:
    report, exit_code = _update(args)
    if json_mode:
        _emit_json(report)
    else:
        _print_update(report)
    return exit_code


def _command_lookup(args: argparse.Namespace, json_mode: bool) -> int:
    raw = getattr(args, "cve_id", "") or ""
    result = _lookup(_normalize_cve(str(raw)))
    if json_mode:
        _emit_json(result)
    else:
        _print_lookup(result)
    return EXIT_OK if result["found"] else EXIT_ERROR


def run(args: argparse.Namespace) -> int:
    """执行 ``strix local intel`` 的某个子命令，返回进程退出码。"""
    command = getattr(args, "intel_command", None)
    json_mode = bool(getattr(args, "json", False))
    try:
        if command == "update":
            return _command_update(args, json_mode)
        if command == "lookup":
            return _command_lookup(args, json_mode)
        _print_usage()
    except IntelError as exc:
        _emit_error(str(exc), json_mode=json_mode)
        return exc.exit_code
    except KeyboardInterrupt:
        _emit_error("已中断", json_mode=json_mode)
        return 130
    except OSError as exc:
        _emit_error(f"本地缓存读写失败：{exc}", json_mode=json_mode)
        return EXIT_ERROR
    return EXIT_USAGE

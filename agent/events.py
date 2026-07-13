from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


# ---------------------------------------------------------------------------
# 正则模式（编译一次，复用）
# ---------------------------------------------------------------------------

# 常见顶级域名，用于区分域名和包名
_KNOWN_TLDS: set[str] = {
    "com", "net", "org", "io", "dev", "app", "info", "biz", "co", "me", "tv",
    "ai", "gg", "sh", "xyz", "tech", "online", "site", "cloud", "digital",
    "eu", "uk", "de", "cn", "ru", "jp", "br", "fr", "in",
    "invalid", "test", "example", "local", "lan",
}

_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)

_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

_HASH_RE = {
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
}

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# 包名：至少三段，首段以小写字母开头（排除 java/Android 关键字开头的路径）
_PACKAGE_RE = re.compile(
    r"\b([a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){2,})\b"
)

_PERMISSION_RE = re.compile(
    r"\bandroid\.permission\.\w+(?:\.\w+)*\b",
    re.IGNORECASE,
)

_ERROR_CODE_RE = re.compile(
    r"\b(?:error\s*code|errno|exit\s*code|status\s*code)[:\s]*(\d+)",
    re.IGNORECASE,
)

# 行为标签关键词 → TTP 映射
_TTP_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bsu\b"), "PRIVILEGE_ESCALATION"),
    (re.compile(r"\broot\b", re.IGNORECASE), "ROOT_ACCESS"),
    (re.compile(r"\b(inject|hook|ptrace)\b", re.IGNORECASE), "HOOK_INJECTION"),
    (re.compile(r"\bchmod\s+[0-7]*7[0-7]*\b"), "PERMISSION_CHANGE"),
    (re.compile(r"\b(chown|setuid|setgid)\b", re.IGNORECASE), "PRIVILEGE_CHANGE"),
    (re.compile(r"\b(exec|popen|system|Runtime\.exec)\b"), "COMMAND_EXECUTION"),
    (re.compile(r"\b(https?://|ftp://|socks?://)\S+"), "NETWORK_CONNECTION"),
    (re.compile(r"\b(bind|reverse)\s*shell\b", re.IGNORECASE), "BIND_REVERSE_SHELL"),
    (re.compile(r"\bdex(class)?loader\b", re.IGNORECASE), "DEX_LOADING"),
    (re.compile(r"\bnative\s*(library|load|hook)\b", re.IGNORECASE), "NATIVE_HOOK"),
    (re.compile(r"\b(sandbox|escape|breakout)\b", re.IGNORECASE), "SANDBOX_ESCAPE"),
    (re.compile(r"\b(persistence|boot\s*receiver|autostart)\b", re.IGNORECASE), "PERSISTENCE"),
    (re.compile(r"\b(data\s*exfil|leak|steal)\b", re.IGNORECASE), "DATA_EXFILTRATION"),
    (re.compile(r"\b(obfuscat|encrypt|base64)\b", re.IGNORECASE), "OBFUSCATION"),
    (re.compile(r"\b(sms|contact|call\s*log|camera|mic)\b", re.IGNORECASE), "SENSITIVE_DATA_ACCESS"),
]

# 排除域名误报：常见技术术语
_DOMAIN_EXCLUDE = {
    "android.com",
    "google.com",
    "source.android.com",
    "developer.android.com",
}


# ---------------------------------------------------------------------------
# 提取函数
# ---------------------------------------------------------------------------

def _looks_like_package(name: str) -> bool:
    """启发式：常见 Java/Android 包名前缀。"""
    return name.split(".", 1)[0] in {"com", "org", "net", "io", "java", "javax", "android", "androidx"}


def extract_domains(text: str) -> list[str]:
    """提取 FQDN 域名，排除包名、权限和平台域名。"""
    domains = _DOMAIN_RE.findall(text)
    results: set[str] = set()
    for d in domains:
        lower = d.lower().rstrip(".")
        tld = lower.rsplit(".", 1)[-1]
        if tld not in _KNOWN_TLDS:
            continue
        if lower in _DOMAIN_EXCLUDE:
            continue
        if _looks_like_package(lower):
            continue
        if "permission" in lower:
            continue
        if len(lower) <= 253:
            results.add(lower)
    return sorted(results)


def extract_ips(text: str) -> list[str]:
    """提取 IPv4 地址，排除 0.x.x.x 和 127.x.x.x。"""
    ips = _IPV4_RE.findall(text)
    return sorted(set(
        ip for ip in ips
        if not ip.startswith("0.") and not ip.startswith("127.")
    ))


def extract_hashes(text: str) -> list[str]:
    """提取 MD5(32)/SHA1(40)/SHA256(64) hex 哈希，排除全零和全F。"""
    found: set[str] = set()
    for algo, pattern in _HASH_RE.items():
        for match in pattern.finditer(text):
            h = match.group(0)
            if h.lower() not in {"0" * len(h), "f" * len(h)}:
                found.add(f"{algo}:{h.lower()}")
    return sorted(found)


def extract_cve_ids(text: str) -> list[str]:
    """提取 CVE-YYYY-NNNN 标识符。"""
    return sorted(set(c.upper() for c in _CVE_RE.findall(text)))


def extract_package_names(text: str) -> list[str]:
    """提取 com.xxx.xxx 风格的包名，排除域名和权限字符串。"""
    candidates = _PACKAGE_RE.findall(text)
    results: set[str] = set()
    for c in candidates:
        if c.count(".") < 2 or len(c) > 128:
            continue
        if re.search(r"\.\.", c):
            continue
        # 末段是 TLD → 大概率是域名
        tld = c.rsplit(".", 1)[-1]
        if tld in _KNOWN_TLDS:
            continue
        # 排除权限字符串
        if c.startswith("android.permission"):
            continue
        results.add(c)
    return sorted(results)


def extract_permissions(text: str) -> list[str]:
    """提取 android.permission.XXX 或 com.android.XXX 权限字符串。"""
    return sorted(set(p for p in _PERMISSION_RE.findall(text)))


def extract_error_codes(text: str) -> list[str]:
    """提取日志中的错误码。"""
    return sorted(set(f"error_code:{m}" for m in _ERROR_CODE_RE.findall(text)))


def extract_ttp_tags(text: str) -> list[str]:
    """基于行为关键词匹配 TTP 标签。"""
    tags: set[str] = set()
    for pattern, tag in _TTP_PATTERNS:
        if pattern.search(text):
            tags.add(tag)
    return sorted(tags)


# ---------------------------------------------------------------------------
# Pydantic 模型
# ---------------------------------------------------------------------------

class DeviceContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    os_version: str | None = None
    security_patch_level: str | None = None
    is_rooted: bool = False
    edr_agent_version: str | None = None
    network_type: Literal["WIFI", "CELLULAR", "VPN", "UNKNOWN"] | None = None


class AppContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    package_name: str | None = None
    apk_hash: str | None = None
    permissions: list[str] = Field(default_factory=list)
    install_source: Literal["official_store", "sideload", "unknown"] | None = None


class VulnerabilityContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cve_ids: list[str] = Field(default_factory=list)
    patch_status: Literal["PATCHED", "UNPATCHED", "UNKNOWN"] | None = None


class SecurityEventInput(BaseModel):
    """基于 Agent.md 第 5 节的统一事件输入 Schema。"""

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1, max_length=128)
    device_id: str = Field(min_length=1, max_length=128)
    timestamp: str = Field(min_length=1)
    source: Literal["EDR", "MDM", "SIEM", "MANUAL", "TEST"] = "EDR"

    device_context: DeviceContext = Field(default_factory=DeviceContext)
    raw_logs: list[str] = Field(default_factory=list)
    alerts: list[dict[str, Any]] = Field(default_factory=list)
    app_context: AppContext | None = None
    vulnerability_context: VulnerabilityContext | None = None

    @model_validator(mode="after")
    def _check_minimum_fields(self) -> SecurityEventInput:
        if not self.raw_logs and not self.alerts:
            raise ValueError("raw_logs 或 alerts 至少需要一个")
        return self


# ---------------------------------------------------------------------------
# 汇总提取
# ---------------------------------------------------------------------------

def _flatten_alerts(alerts: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for alert in alerts:
        for key in ("signature", "raw_message", "description", "category"):
            v = alert.get(key)
            if isinstance(v, str):
                parts.append(v)
    return " ".join(parts)


def extract_signals(event: SecurityEventInput) -> dict[str, Any]:
    """从 SecurityEventInput 中提取所有结构化信号。"""
    # 收集所有文本源
    text_sources: list[str] = []

    # raw_logs
    text_sources.extend(event.raw_logs)

    # alerts
    text_sources.append(_flatten_alerts(event.alerts))

    # app_context
    if event.app_context:
        ac = event.app_context
        if ac.package_name:
            text_sources.append(ac.package_name)
        if ac.apk_hash:
            text_sources.append(ac.apk_hash)
        text_sources.extend(ac.permissions)

    # vulnerability_context
    if event.vulnerability_context:
        text_sources.extend(event.vulnerability_context.cve_ids)

    combined = " ".join(text_sources)

    # 从 combined 文本提取，同时吞掉结构字段
    domains = extract_domains(combined)
    ips = extract_ips(combined)
    hashes = extract_hashes(combined)
    cve_ids = extract_cve_ids(combined)
    package_names = extract_package_names(combined)
    permissions = extract_permissions(combined)
    error_codes = extract_error_codes(combined)
    ttp_tags = extract_ttp_tags(combined)

    # 补充结构字段里已有的
    if event.vulnerability_context:
        for cve in event.vulnerability_context.cve_ids:
            cve_ids = sorted(set(cve_ids) | {cve.upper()})
    if event.app_context:
        if event.app_context.package_name:
            package_names = sorted(set(package_names) | {event.app_context.package_name})
        for perm in event.app_context.permissions:
            permissions = sorted(set(permissions) | {perm})
        if event.app_context.apk_hash:
            h = event.app_context.apk_hash.strip().lower()
            length_to_algo = {32: "md5", 40: "sha1", 64: "sha256"}
            algo = length_to_algo.get(len(h), "unknown")
            hashes = sorted(set(hashes) | {f"{algo}:{h}"})

    return {
        "domains": domains,
        "ips": ips,
        "hashes": hashes,
        "cve_ids": cve_ids,
        "package_names": package_names,
        "permissions": permissions,
        "error_codes": error_codes,
        "ttp_tags": ttp_tags,
    }


def validate_event_input(data: dict[str, Any]) -> SecurityEventInput:
    """校验 JSON 输入并返回 SecurityEventInput 实例。"""
    return SecurityEventInput.model_validate(data)

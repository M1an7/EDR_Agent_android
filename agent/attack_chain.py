from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import httpx
from dotenv import load_dotenv

load_dotenv()

PROJECT_ROOT = Path(__file__).resolve().parents[1]
AUDIT_DIR = PROJECT_ROOT / "logs" / "audit"

# Kill Chain 阶段排序（后续阶段优先展示在前）
KILL_CHAIN_ORDER = [
    "INITIAL_ACCESS",
    "EXECUTION",
    "PERSISTENCE",
    "PRIVILEGE_ESCALATION",
    "DEFENSE_EVASION",
    "CREDENTIAL_ACCESS",
    "C2_COMMUNICATION",
    "EXFILTRATION",
]


def map_to_kill_chain(category: str, ttp_tags: list[str]) -> str:
    """将攻击类别 + TTP 标签映射到 Kill Chain 阶段。"""
    c = category.upper()
    tags_upper = [t.upper() for t in ttp_tags]

    if any(t in tags_upper for t in ["MALICIOUS_APK", "PHISHING_APP"]) or c in {"MALICIOUS_APK", "PHISHING_APP"}:
        return "INITIAL_ACCESS"
    if any(t in tags_upper for t in ["COMMAND_EXECUTION", "DEX_LOADING"]) or c in {"COMMAND_EXECUTION", "DEX_LOADING"}:
        return "EXECUTION"
    if any(t in tags_upper for t in ["PERSISTENCE", "BOOT_RECEIVER", "AUTOSTART"]) or c in {"PERSISTENCE"}:
        return "PERSISTENCE"
    if any(t in tags_upper for t in ["PRIVILEGE_ESCALATION", "ROOT_ACCESS", "PERMISSION_CHANGE", "PRIVILEGE_CHANGE"]) or c in {"PRIVILEGE_ESCALATION", "ROOT_ACCESS"}:
        return "PRIVILEGE_ESCALATION"
    if any(t in tags_upper for t in ["DEFENSE_EVASION", "OBFUSCATION", "SANDBOX_ESCAPE"]) or "OVERLAY" in c or "OBFUSCATION" in c:
        return "DEFENSE_EVASION"
    if any(t in tags_upper for t in ["KEYLOGGING", "CREDENTIAL", "SCREEN_CAPTURE", "SENSITIVE_DATA_ACCESS"]) or "KEYLOGGING" in c or "CREDENTIAL" in c:
        return "CREDENTIAL_ACCESS"
    if any(t in tags_upper for t in ["C2_COMMUNICATION", "NETWORK_CONNECTION", "BIND_REVERSE_SHELL"]) or c in {"C2_COMMUNICATION"}:
        return "C2_COMMUNICATION"
    if any(t in tags_upper for t in ["DATA_EXFILTRATION"]) or c in {"DATA_EXFILTRATION"}:
        return "EXFILTRATION"
    if c in set(KILL_CHAIN_ORDER):
        return c
    return "UNKNOWN"


class AttackChainTracer:
    """确定性引擎：跨事件 IOC 关联 + Kill Chain 映射。"""

    def __init__(self) -> None:
        self._events: dict[str, dict[str, Any]] = {}
        self._ioc_index: dict[str, dict[str, set[str]]] = {
            "domain": {}, "ip": {}, "hash": {}, "cve": {}, "package": {},
        }
        self._load_audit_logs()

    def _load_audit_logs(self) -> None:
        if not AUDIT_DIR.exists():
            return
        for f in sorted(AUDIT_DIR.glob("*.jsonl")):
            with f.open(encoding="utf-8") as fh:
                for line in fh:
                    entry = json.loads(line)
                    eid = entry["event_id"]
                    stage = entry["stage"]
                    data = entry["data"]

                    if eid not in self._events:
                        self._events[eid] = {"event_id": eid, "signals": {}, "classification": {}}

                    if stage == "signals_extracted":
                        self._events[eid]["signals"] = data
                        if "timestamp" not in self._events[eid]:
                            self._events[eid]["timestamp"] = entry.get("timestamp", "")
                        self._index_iocs(eid, data)
                    elif stage in ("rule_engine_hit", "llm_assessment"):
                        self._events[eid]["classification"] = data
                    elif stage == "event_parsed":
                        self._events[eid]["device_id"] = data.get("device_id", "")
                        if "timestamp" not in self._events[eid]:
                            self._events[eid]["timestamp"] = entry.get("timestamp", "")

    def _index_iocs(self, eid: str, signals: dict) -> None:
        for domain in signals.get("domains", []):
            self._ioc_index["domain"].setdefault(domain.lower(), set()).add(eid)
        for ip in signals.get("ips", []):
            self._ioc_index["ip"].setdefault(ip, set()).add(eid)
        for h in signals.get("hashes", []):
            self._ioc_index["hash"].setdefault(h.lower(), set()).add(eid)
        for cve in signals.get("cve_ids", []):
            self._ioc_index["cve"].setdefault(cve.upper(), set()).add(eid)
        for pkg in signals.get("package_names", []):
            self._ioc_index["package"].setdefault(pkg, set()).add(eid)

    def trace_by_ioc(self, value: str, ioc_type: str = "domain") -> list[str]:
        """找到所有包含该 IOC 的事件。"""
        index = self._ioc_index.get(ioc_type, {})
        return sorted(index.get(value.lower(), set()))

    def trace_by_device(self, device_id: str) -> list[str]:
        """找到该设备的所有历史事件。"""
        return sorted(
            eid for eid, evt in self._events.items()
            if evt.get("device_id") == device_id
        )

    def build_chain(self, event_ids: list[str]) -> dict[str, Any]:
        """输入事件 ID 列表，构建结构化攻击链。"""
        events = [self._events[eid] for eid in event_ids if eid in self._events]
        if not events:
            return {"chain_id": "empty", "correlated_events": 0, "timeline": []}

        events.sort(key=lambda e: e.get("timestamp", ""))

        timeline = []
        phases = set()
        for i, evt in enumerate(events, 1):
            cls = evt.get("classification", {})
            sigs = evt.get("signals", {})
            category = cls.get("category", "UNKNOWN")
            ttp_tags = sigs.get("ttp_tags", [])
            phase = map_to_kill_chain(category, ttp_tags)
            phases.add(phase)

            timeline.append({
                "order": i,
                "event_id": evt["event_id"],
                "timestamp": evt.get("timestamp", ""),
                "device_id": evt.get("device_id", ""),
                "kill_chain_phase": phase,
                "category": category,
                "detection_type": cls.get("detection_type", "UNKNOWN"),
                "key_signals": {
                    "domains": sigs.get("domains", [])[:3],
                    "ips": sigs.get("ips", [])[:3],
                    "hashes": sigs.get("hashes", [])[:3],
                    "cve_ids": sigs.get("cve_ids", [])[:3],
                    "ttp_tags": sigs.get("ttp_tags", [])[:5],
                },
            })

        coverage = [p for p in KILL_CHAIN_ORDER if p in phases]
        missing = [p for p in KILL_CHAIN_ORDER if p not in phases]

        return {
            "chain_id": f"chain-{events[0]['event_id']}",
            "correlated_events": len(events),
            "devices_involved": sorted(set(e.get("device_id", "") for e in events)),
            "timeline": timeline,
            "coverage": coverage,
            "missing_phases": missing,
            "completeness": f"{len(coverage)}/{len(KILL_CHAIN_ORDER)}",
        }


class AttackChainAnalyzer:
    """LLM 分析层：输入事实链 → 推理攻击意图、画像、扩散模式。"""

    def __init__(self) -> None:
        base_url = os.environ.get("LLM_BASE_URL", "").rstrip("/")
        self._endpoint = f"{base_url}/chat/completions"
        self._api_key = os.environ.get("LLM_API_KEY", "")
        self._model = os.environ.get("LLM_MODEL", "sec-agent-base")
        self._client = httpx.Client(timeout=httpx.Timeout(connect=10, read=180, write=30, pool=10))

    def analyze(self, chain: dict[str, Any]) -> dict[str, Any]:
        """输入确定性链 → LLM 推理攻击意图。"""
        if not chain.get("timeline"):
            return {"campaign_assessment": "无足够事件进行攻击意图分析", "confidence": "low"}

        prompt = f"""你是 Android 安全攻击链分析专家。请分析以下攻击链，推理攻击意图和活动模式。

攻击链事实:
{json.dumps(chain, ensure_ascii=False, indent=2)}

请从以下维度分析并输出 JSON：
- campaign_assessment: 攻击活动的整体评估（攻击目标、可能动机、组织化程度）
- attacker_profile: 攻击者画像（技能水平、使用的攻击手法特征）
- spread_pattern: 扩散模式（单设备还是多设备？横向移动迹象？）
- missing_phase_risk: 缺失环节的风险评估（未观察到不代表没发生）
- recommended_investigation: 下一步调查建议
- confidence: low/medium/high（对以上分析的置信度）

输出 JSON 格式，不要其他文字。"""

        response = self._client.post(
            self._endpoint,
            headers={"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json"},
            json={
                "model": self._model,
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
                "temperature": 0,
                "max_tokens": 1500,
                "chat_template_kwargs": {"enable_thinking": False},
            },
        )

        if response.is_error:
            return {"error": f"LLM API 错误: {response.status_code}", "confidence": "low"}

        choices = response.json().get("choices", [])
        if not choices:
            return {"error": "LLM 无响应", "confidence": "low"}

        content = choices[0].get("message", {}).get("content", "")
        try:
            return json.loads(_extract_json(content))
        except (json.JSONDecodeError, ValueError):
            return {"raw_output": content[:1000], "confidence": "low", "note": "LLM 输出解析失败"}

    def close(self) -> None:
        self._client.close()


def _extract_json(text: str) -> str:
    text = text.strip()
    if text.startswith("{"):
        return text
    import re
    match = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
    if match:
        return match.group(1).strip()
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        return text[start:end + 1]
    raise ValueError("无法提取 JSON")

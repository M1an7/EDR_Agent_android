from __future__ import annotations

import json
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RULES_PATH = PROJECT_ROOT / "data" / "rules" / "rules.json"


class RuleEngine:
    """确定性规则引擎：匹配信号 → 输出分类，未命中返回 None。"""

    def __init__(self, rules_path: Path | None = None) -> None:
        path = rules_path or DEFAULT_RULES_PATH
        raw = json.loads(path.read_text(encoding="utf-8"))
        self._rules: dict[str, list[dict[str, Any]]] = raw["rules"]

        # 构建索引：value → rule
        self._cve_index: dict[str, dict[str, Any]] = {}
        for r in self._rules.get("cve", []):
            self._cve_index[r["value"].upper()] = r

        self._ioc_index: dict[str, list[dict[str, Any]]] = {
            "domain": [],
            "ip": [],
            "hash": [],
        }
        for r in self._rules.get("ioc", []):
            t = r["type"]
            if t in self._ioc_index:
                self._ioc_index[t].append(r)

        self._error_index: dict[str, dict[str, Any]] = {}
        for r in self._rules.get("error_code", []):
            self._error_index[r["value"]] = r

    def match(self, signals: dict[str, Any]) -> dict[str, Any] | None:
        """按优先级匹配信号：CVE > IOC > 错误码。命中返回分类+证据，未命中返回 None。"""
        matched: list[dict[str, Any]] = []

        # CVE 优先
        for cve_id in signals.get("cve_ids", []):
            rule = self._cve_index.get(cve_id.upper())
            if rule:
                matched.append({
                    "rule": rule,
                    "signal": cve_id,
                    "signal_type": "cve",
                })

        # IOC（domain/ip/hash）
        for domain in signals.get("domains", []):
            for r in self._ioc_index["domain"]:
                if r["value"] == domain:
                    matched.append({"rule": r, "signal": domain, "signal_type": "domain"})

        for ip in signals.get("ips", []):
            for r in self._ioc_index["ip"]:
                if r["value"] == ip:
                    matched.append({"rule": r, "signal": ip, "signal_type": "ip"})

        for h in signals.get("hashes", []):
            for r in self._ioc_index["hash"]:
                if r["value"] == h:
                    matched.append({"rule": r, "signal": h, "signal_type": "hash"})

        # 错误码
        for ec in signals.get("error_codes", []):
            rule = self._error_index.get(ec)
            if rule:
                matched.append({"rule": rule, "signal": ec, "signal_type": "error_code"})

        if not matched:
            return None

        # 多规则命中时取第一个（CVE 优先已在顺序中体现）
        best = matched[0]
        rule = best["rule"]
        classification = rule["classification"]

        evidence = []
        for m in matched:
            evidence.append({
                "type": "RULE_MATCH",
                "rule_id": m["rule"]["rule_id"],
                "signal_type": m["signal_type"],
                "matched_value": m["signal"],
                "source": m["rule"].get("data", {}).get("source", "rule_database"),
            })

        return {
            "path": "rule_direct",
            "detection_type": classification["detection_type"],
            "category": classification["category"],
            "evidence": evidence,
            "matched_rules": [m["rule"]["rule_id"] for m in matched],
        }

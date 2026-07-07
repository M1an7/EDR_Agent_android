from __future__ import annotations

import json
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RULES_PATH = PROJECT_ROOT / "data" / "rules" / "rules.json"
KEV_PATH = PROJECT_ROOT / "data" / "processed" / "cisa_kev.jsonl"


class RAGClient:
    """RAG 统一接口，支持 mock/local/remote。"""

    def search(self, signals: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError


class MockRAGClient(RAGClient):
    """基于本地规则库 + KEV 做匹配，不调外部服务。"""

    def __init__(self) -> None:
        self._ioc_rules: dict[str, list[dict[str, Any]]] = {
            "domain": [], "ip": [], "hash": [],
        }
        self._kev_entries: dict[str, dict[str, Any]] = {}
        self._load_data()

    def _load_data(self) -> None:
        if RULES_PATH.exists():
            rules = json.loads(RULES_PATH.read_text(encoding="utf-8"))
            for r in rules.get("rules", {}).get("ioc", []):
                t = r.get("type")
                if t in self._ioc_rules:
                    self._ioc_rules[t].append(r)

        if KEV_PATH.exists():
            with KEV_PATH.open(encoding="utf-8") as f:
                for line in f:
                    entry = json.loads(line)
                    cve = entry.get("cve_id", "").upper()
                    if cve:
                        self._kev_entries[cve] = entry

    def search(self, signals: dict[str, Any]) -> dict[str, Any]:
        results: list[dict[str, Any]] = []

        for cve_id in signals.get("cve_ids", []):
            entry = self._kev_entries.get(cve_id.upper())
            if entry:
                results.append({
                    "doc_id": f"kev-{cve_id.lower()}",
                    "title": entry.get("vulnerability_name", cve_id),
                    "source_type": "CVE",
                    "confidence": 0.95,
                    "similarity_score": 1.0,
                    "freshness": "VALID",
                    "content_summary": entry.get("short_description", "")[:500],
                    "matched_entities": {"cve_ids": [cve_id]},
                    "recommended_actions": ["TRIGGER_SCAN", "CREATE_TICKET"],
                })

        for domain in signals.get("domains", []):
            for rule in self._ioc_rules["domain"]:
                if rule["value"] == domain:
                    results.append({
                        "doc_id": rule["rule_id"],
                        "title": f"恶意域名: {domain}",
                        "source_type": "IOC",
                        "confidence": 0.90,
                        "similarity_score": 1.0,
                        "freshness": "VALID",
                        "content_summary": rule.get("data", {}).get("note", "已知恶意域名"),
                        "matched_entities": {"domains": [domain]},
                        "recommended_actions": ["BLOCK_DOMAIN", "COLLECT_FORENSIC_DATA"],
                    })

        for ip in signals.get("ips", []):
            for rule in self._ioc_rules["ip"]:
                if rule["value"] == ip:
                    results.append({
                        "doc_id": rule["rule_id"],
                        "title": f"恶意 IP: {ip}",
                        "source_type": "IOC",
                        "confidence": 0.90,
                        "similarity_score": 1.0,
                        "freshness": "VALID",
                        "content_summary": rule.get("data", {}).get("note", "已知恶意 IP"),
                        "matched_entities": {"ips": [ip]},
                        "recommended_actions": ["BLOCK_IP", "COLLECT_FORENSIC_DATA"],
                    })

        for h in signals.get("hashes", []):
            for rule in self._ioc_rules["hash"]:
                if rule["value"] == h:
                    results.append({
                        "doc_id": rule["rule_id"],
                        "title": f"恶意 APK Hash: {h}",
                        "source_type": "IOC",
                        "confidence": 0.90,
                        "similarity_score": 1.0,
                        "freshness": "VALID",
                        "content_summary": rule.get("data", {}).get("note", "已知恶意 Hash"),
                        "matched_entities": {"hashes": [h]},
                        "recommended_actions": ["ISOLATE_APP", "TRIGGER_SCAN"],
                    })

        return {"ok": True, "results": results, "rag_mode": "mock"}

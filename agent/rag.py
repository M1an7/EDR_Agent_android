from __future__ import annotations

import json
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RULES_PATH = PROJECT_ROOT / "data" / "rules" / "rules.json"
KEV_PATH = PROJECT_ROOT / "data" / "processed" / "cisa_kev.jsonl"
RAG_SAMPLES = PROJECT_ROOT / "rag" / "samples" / "rag_evidence_packs"


class RAGClient:
    """RAG 统一接口，支持 mock/local。"""

    def search(self, signals: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError


class MockRAGClient(RAGClient):
    """基于本地规则库 + KEV 做匹配，不调外部服务。"""

    def __init__(self) -> None:
        self._ioc_rules: dict[str, list[dict[str, Any]]] = {"domain": [], "ip": [], "hash": []}
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
                    "doc_id": f"kev-{cve_id.lower()}", "title": entry.get("vulnerability_name", cve_id),
                    "source_type": "CVE", "confidence": 0.95, "similarity_score": 1.0,
                    "freshness": "VALID", "content_summary": entry.get("short_description", "")[:500],
                    "matched_entities": {"cve_ids": [cve_id]},
                    "recommended_actions": ["TRIGGER_SCAN", "CREATE_TICKET"],
                })
        for domain in signals.get("domains", []):
            for rule in self._ioc_rules["domain"]:
                if rule["value"] == domain:
                    results.append({
                        "doc_id": rule["rule_id"], "title": f"恶意域名: {domain}",
                        "source_type": "IOC", "confidence": 0.90, "similarity_score": 1.0,
                        "freshness": "VALID", "content_summary": rule.get("data", {}).get("note", "已知恶意域名"),
                        "matched_entities": {"domains": [domain]},
                        "recommended_actions": ["BLOCK_DOMAIN", "COLLECT_FORENSIC_DATA"],
                    })
        for ip in signals.get("ips", []):
            for rule in self._ioc_rules["ip"]:
                if rule["value"] == ip:
                    results.append({
                        "doc_id": rule["rule_id"], "title": f"恶意 IP: {ip}",
                        "source_type": "IOC", "confidence": 0.90, "similarity_score": 1.0,
                        "freshness": "VALID", "content_summary": rule.get("data", {}).get("note", "已知恶意 IP"),
                        "matched_entities": {"ips": [ip]},
                        "recommended_actions": ["BLOCK_IP", "COLLECT_FORENSIC_DATA"],
                    })
        for h in signals.get("hashes", []):
            for rule in self._ioc_rules["hash"]:
                if rule["value"] == h:
                    results.append({
                        "doc_id": rule["rule_id"], "title": f"恶意 APK Hash: {h}",
                        "source_type": "IOC", "confidence": 0.90, "similarity_score": 1.0,
                        "freshness": "VALID", "content_summary": rule.get("data", {}).get("note", "已知恶意 Hash"),
                        "matched_entities": {"hashes": [h]},
                        "recommended_actions": ["ISOLATE_APP", "TRIGGER_SCAN"],
                    })
        return {"ok": True, "results": results, "rag_mode": "mock"}


class LocalRAGClient(RAGClient):
    """对接 RAG 团队预生成的 evidence pack 文件。按 event_id 匹配。"""

    def __init__(self) -> None:
        self._packs: dict[str, dict[str, Any]] = {}
        self._load_packs()

    def _load_packs(self) -> None:
        if not RAG_SAMPLES.exists():
            return
        for f in RAG_SAMPLES.glob("*.rag_evidence_pack.json"):
            try:
                pack = json.loads(f.read_text(encoding="utf-8"))
                eid = pack.get("input_event_id", "")
                if eid:
                    self._packs[eid] = pack
            except Exception:
                pass

    def search(self, signals: dict[str, Any], event_id: str = "") -> dict[str, Any]:
        """查找匹配的 evidence pack。匹配优先级：event_id > IOC 模糊匹配。"""
        pack = None

        if event_id and event_id in self._packs:
            pack = self._packs[event_id]

        # 按 IOC 模糊匹配
        if not pack:
            for eid, p in self._packs.items():
                score = 0
                for domain in signals.get("domains", []):
                    if domain in p.get("query_text", ""):
                        score += 3
                for ip in signals.get("ips", []):
                    if ip in p.get("query_text", ""):
                        score += 3
                for cve in signals.get("cve_ids", []):
                    if cve.upper() in p.get("query_text", "").upper():
                        score += 3
                for pkg in signals.get("package_names", []):
                    if pkg in p.get("query_text", ""):
                        score += 2
                if score >= 3:
                    pack = p
                    break

        if not pack:
            return {"ok": True, "results": [], "rag_mode": "local"}

        return {
            "ok": True,
            "rag_mode": "local",
            "rag_judgement": pack.get("judgement", ""),
            "rag_severity": pack.get("severity", ""),
            "rag_confidence": pack.get("confidence", 0.0),
            "results": self._pack_to_results(pack),
        }

    def _pack_to_results(self, pack: dict) -> list[dict[str, Any]]:
        """将 evidence pack 转为内部 results 格式。"""
        results: list[dict[str, Any]] = []

        for ioc in pack.get("matched_iocs", []):
            results.append({
                "doc_id": ioc.get("entity_id", ""),
                "title": ioc.get("name", ""),
                "source_type": "IOC",
                "confidence": pack.get("confidence", 0.0),
                "similarity_score": ioc.get("score", 0.0),
                "freshness": "VALID" if ioc.get("status") == "active" else "EXPIRED",
                "content_summary": ioc.get("source", ""),
                "matched_entities": {"iocs": [ioc.get("entity_id")]},
            })

        for tech in pack.get("matched_techniques", []):
            results.append({
                "doc_id": tech.get("entity_id", ""),
                "title": tech.get("name", ""),
                "source_type": "TTP",
                "confidence": pack.get("confidence", 0.0),
                "similarity_score": tech.get("score", 0.0),
                "freshness": "VALID" if tech.get("status") == "active" else "EXPIRED",
                "content_summary": tech.get("source", ""),
                "matched_entities": {"technique_ids": [tech.get("entity_id")]},
            })

        for mapping in pack.get("matched_behavior_mappings", []):
            results.append({
                "doc_id": mapping.get("entity_id", ""),
                "title": mapping.get("name", ""),
                "source_type": "TTP",
                "confidence": pack.get("confidence", 0.0),
                "similarity_score": mapping.get("score", 0.0),
                "freshness": "VALID",
                "content_summary": mapping.get("source", ""),
                "matched_entities": {},
            })

        return results

from __future__ import annotations

from typing import Any


def compute_confidence(
    signals: dict[str, Any],
    rule_result: dict[str, Any] | None = None,
    analysis_result: dict[str, Any] | None = None,
    rag_result: dict[str, Any] | None = None,
) -> float:
    """确定性加权公式，计算置信度 0.00-1.00。"""

    score = 0.0

    # 1. 明确 IOC 命中 (0.30)
    ioc_confirmed = False
    if rule_result:
        evidence = rule_result.get("evidence", [])
        ioc_signals = {"domain", "ip", "hash"}
        for e in evidence:
            if e.get("signal_type") in ioc_signals:
                ioc_confirmed = True
                break
    if not ioc_confirmed and rag_result:
        for r in rag_result.get("results", []):
            if r.get("source_type") == "IOC" and r.get("similarity_score", 0) >= 0.65:
                ioc_confirmed = True
                break
    if not ioc_confirmed:
        has_ioc = bool(signals.get("domains") or signals.get("ips") or signals.get("hashes"))
        has_ttp = bool(signals.get("ttp_tags"))
        if has_ioc and has_ttp:
            ioc_confirmed = True
    if ioc_confirmed:
        score += 0.30

    # 2. 行为规则命中 (0.25)
    behavior_hit = False
    if signals.get("ttp_tags"):
        behavior_hit = True
    if not behavior_hit and rule_result:
        for e in rule_result.get("evidence", []):
            if e.get("signal_type") in {"domain", "ip", "hash"}:
                behavior_hit = True
                break
    if behavior_hit:
        score += 0.25

    # 3. RAG 高相似度命中 (0.20)
    rag_hit = False
    if rag_result:
        for r in rag_result.get("results", []):
            if r.get("similarity_score", 0) >= 0.65:
                rag_hit = True
                break
    if rag_hit:
        score += 0.20

    # 4. CVE / 补丁上下文匹配 (0.10)
    cve_hit = bool(signals.get("cve_ids"))
    if not cve_hit and analysis_result:
        raw_evidence = analysis_result.get("evidence", []) or []
        cve_evidence = [
            e for e in raw_evidence
            if isinstance(e, dict) and e.get("type") == "VULN"
        ]
        if cve_evidence:
            cve_hit = True
    if cve_hit:
        score += 0.10

    # 5. 历史相似案例 (0.10) — 暂不可用
    # 阶段 7 反馈机制启用后，从积累区查询相似历史事件

    # 6. 上下文完整性 (0.05)
    context_complete = (
        signals.get("package_names")
        or signals.get("permissions")
        or signals.get("ttp_tags")
    )
    if context_complete:
        score += 0.05

    return round(min(score, 1.0), 2)

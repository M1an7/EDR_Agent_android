from __future__ import annotations

from typing import Any

# Agent.md 第 11.1 节：自动处置白名单
AUTO_REMEDIATION_WHITELIST: set[str] = {
    "BLOCK_DOMAIN",
    "BLOCK_IP",
    "ISOLATE_APP",
    "DISABLE_PERMISSION",
    "TRIGGER_SCAN",
    "COLLECT_FORENSIC_DATA",
    "CREATE_TICKET",
    "SEND_ALERT",
}

# 禁止自动执行的破坏性动作
BLOCKED_ACTIONS: set[str] = {
    "WIPE_DEVICE",
    "UNINSTALL_APP",
    "RESET_POLICY",
    "MODIFY_SYSTEM_CONFIG",
}


def _check_evidence_conflict(evidence: list[dict[str, Any]]) -> bool:
    """检查证据链中是否有明显矛盾。"""
    # 简单启发式：如果证据同时标记了正常行为和恶意行为，可能有错判
    has_malicious = False
    has_benign = False
    for e in evidence:
        if not isinstance(e, dict):
            continue
        detail = e.get("detail", "")
        source = e.get("source", "")
        if any(kw in detail for kw in ["malicious", "恶意", "攻击", "ATTACK", "VULNERABILITY"]):
            has_malicious = True
        if any(kw in detail.lower() for kw in ["normal", "benign", "正常", "system service", "系统"]):
            has_benign = True
        if source == "rule_database" and "MOCK" in str(e.get("rule_id", "")):
            has_benign = True
    return has_malicious and has_benign


def _infer_actions(detection_type: str, category: str) -> list[str]:
    """当分析结果没有推荐动作时，根据分类推断默认动作。"""
    mapping: dict[str, list[str]] = {
        "C2_COMMUNICATION": ["BLOCK_DOMAIN", "BLOCK_IP", "COLLECT_FORENSIC_DATA", "ISOLATE_APP", "CREATE_TICKET", "SEND_ALERT"],
        "MALICIOUS_APK": ["ISOLATE_APP", "COLLECT_FORENSIC_DATA", "DISABLE_PERMISSION", "CREATE_TICKET", "SEND_ALERT"],
        "PRIVILEGE_ESCALATION": ["ISOLATE_APP", "DISABLE_PERMISSION", "COLLECT_FORENSIC_DATA", "TRIGGER_SCAN", "CREATE_TICKET"],
        "DATA_EXFILTRATION": ["BLOCK_IP", "BLOCK_DOMAIN", "ISOLATE_APP", "COLLECT_FORENSIC_DATA", "CREATE_TICKET"],
        "HOOK_INJECTION": ["ISOLATE_APP", "COLLECT_FORENSIC_DATA", "TRIGGER_SCAN", "CREATE_TICKET"],
        "PHISHING_APP": ["ISOLATE_APP", "DISABLE_PERMISSION", "BLOCK_DOMAIN", "COLLECT_FORENSIC_DATA", "CREATE_TICKET"],
        "PERSISTENCE": ["ISOLATE_APP", "DISABLE_PERMISSION", "COLLECT_FORENSIC_DATA", "TRIGGER_SCAN", "CREATE_TICKET"],
        "ANDROID_SYSTEM_CVE": ["TRIGGER_SCAN", "COLLECT_FORENSIC_DATA", "CREATE_TICKET", "SEND_ALERT"],
    }
    if detection_type == "ATTACK":
        return mapping.get(category, mapping.get("MALICIOUS_APK", []))  # type: ignore[arg-type]
    if detection_type == "VULNERABILITY":
        return mapping.get(category, mapping.get("ANDROID_SYSTEM_CVE", []))  # type: ignore[arg-type]
    if detection_type == "FAULT":
        return ["CREATE_TICKET", "SEND_ALERT"]
    return []


def decide(
    confidence: float,
    severity: str,
    rag_status: str,
    recommended_actions: list[str] | None = None,
    evidence: list[dict[str, Any]] | None = None,
    rag_used: bool = True,
    detection_type: str = "",
    category: str = "",
) -> dict[str, Any]:
    """决策引擎：根据置信度/严重度/RAG 状态决定自动处置还是人工复核。"""

    evidence = evidence or []
    recommended_actions = recommended_actions or []

    reasons: list[str] = []
    auto_allowed = True

    # 条件 1：置信度
    if confidence < 0.90:
        auto_allowed = False
        reasons.append(f"置信度 {confidence} < 0.90")

    # 条件 2：严重度
    if severity not in {"HIGH", "CRITICAL"}:
        auto_allowed = False
        reasons.append(f"严重度 {severity} 不足，需要 HIGH 或 CRITICAL")

    # 条件 3：RAG 状态
    rag_blocked = rag_status not in {"SUCCESS"}
    if not rag_used:
        rag_blocked = False  # RAG 禁用时不阻塞
    if rag_blocked:
        auto_allowed = False
        reasons.append(f"RAG 状态 {rag_status}，不足以支撑自动处置")

    # 条件 4：证据无冲突
    if _check_evidence_conflict(evidence):
        auto_allowed = False
        reasons.append("证据链存在矛盾")

    # 条件 5：处置动作在白名单
    if not recommended_actions and detection_type and category:
        recommended_actions = _infer_actions(detection_type, category)
    allowed = [a for a in recommended_actions if a in AUTO_REMEDIATION_WHITELIST]
    blocked = [a for a in recommended_actions if a in BLOCKED_ACTIONS]

    if not allowed:
        auto_allowed = False
        reasons.append("推荐动作不在白名单内")

    if blocked:
        auto_allowed = False
        reasons.append(f"包含被禁止的破坏性动作: {blocked}")

    need_human = not auto_allowed
    reason_text = "; ".join(reasons) if reasons else None

    return {
        "auto_remediation_allowed": auto_allowed,
        "need_human_review": need_human,
        "human_review_reason": reason_text,
        "allowed_actions": allowed,
        "blocked_actions": blocked,
    }

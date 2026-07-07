from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from dotenv import load_dotenv

load_dotenv()

PROJECT_ROOT = Path(__file__).resolve().parents[1]
FEEDBACK_PATH = PROJECT_ROOT / "data" / "knowledge" / "feedback.json"

# 已知规则库里的值，不需要重复记录
_KNOWN_RULE_VALUES: set[str] = set()


def _load_known_values() -> None:
    rules_path = PROJECT_ROOT / "data" / "rules" / "rules.json"
    if not rules_path.exists():
        return
    rules = json.loads(rules_path.read_text(encoding="utf-8"))
    for cve in rules.get("rules", {}).get("cve", []):
        _KNOWN_RULE_VALUES.add(cve["value"].upper())
    for ioc in rules.get("rules", {}).get("ioc", []):
        _KNOWN_RULE_VALUES.add(ioc["value"].lower())
    for ec in rules.get("rules", {}).get("error_code", []):
        _KNOWN_RULE_VALUES.add(ec["value"].lower())


_load_known_values()


class FeedbackManager:
    """管理反馈积累区和待审核知识区。"""

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or FEEDBACK_PATH
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._entries: list[dict[str, Any]] = self._load()

    def _load(self) -> list[dict[str, Any]]:
        if self._path.exists():
            data = json.loads(self._path.read_text(encoding="utf-8"))
            return data.get("entries", [])
        return []

    def _save(self) -> None:
        self._path.write_text(
            json.dumps({"entries": self._entries}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def write_observation(
        self,
        event_id: str,
        signals: dict[str, Any],
        result: dict[str, Any],
        path: str,
    ) -> list[str]:
        """写入值得记录的观察，返回写入的条目 ID 列表。"""
        ids: list[str] = []
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        source = "RULE_DIRECT" if path == "rule_direct" else "AGENT_ANALYSIS"

        # 记录未知域名
        for d in signals.get("domains", []):
            if d.lower() not in _KNOWN_RULE_VALUES:
                ids.append(self._add(now, event_id, source, "NEW_IOC", {"domain": d}, f"发现新域名: {d}"))

        # 记录未知 IP
        for ip in signals.get("ips", []):
            if ip.lower() not in _KNOWN_RULE_VALUES:
                ids.append(self._add(now, event_id, source, "NEW_IOC", {"ip": ip}, f"发现新 IP: {ip}"))

        # 记录未知 Hash
        for h in signals.get("hashes", []):
            if h.lower() not in _KNOWN_RULE_VALUES:
                ids.append(self._add(now, event_id, source, "NEW_IOC", {"hash": h}, f"发现新 Hash: {h}"))

        # 记录新 TTP 标签
        for tag in signals.get("ttp_tags", []):
            if tag.lower() not in _KNOWN_RULE_VALUES:
                ids.append(self._add(now, event_id, source, "NEW_TTP", {"ttp_tag": tag}, f"观察到行为模式: {tag}"))

        # 置信度异常（过高或过低都值得记录）
        confidence = result.get("confidence", 0)
        if confidence >= 0.90:
            ids.append(self._add(now, event_id, source, "HIGH_CONFIDENCE",
                {"confidence": confidence, "detection_type": result.get("detection_type")},
                f"高置信度事件: {result.get('detection_type')}/{result.get('category')}"))
        elif confidence < 0.30 and result.get("detection_type") != "UNKNOWN":
            ids.append(self._add(now, event_id, source, "LOW_CONFIDENCE",
                {"confidence": confidence, "detection_type": result.get("detection_type")},
                f"低置信度事件: 仅有 {confidence}"))

        if ids:
            self._save()
        return ids

    def _add(self, timestamp: str, event_id: str, source: str,
             suggestion_type: str, signals: dict, summary: str) -> str:
        obs_id = f"obs-{len(self._entries)+1:04d}"
        self._entries.append({
            "id": obs_id,
            "event_id": event_id,
            "timestamp": timestamp,
            "status": "accumulated",
            "suggestion_type": suggestion_type,
            "source": source,
            "signals": signals,
            "summary": summary,
        })
        return obs_id

    def get_accumulated(self) -> list[dict[str, Any]]:
        return [e for e in self._entries if e["status"] == "accumulated"]

    def get_pending(self) -> list[dict[str, Any]]:
        return [e for e in self._entries if e["status"] == "pending_review"]

    def mark_approved(self, obs_id: str) -> None:
        self._update_status(obs_id, "approved")

    def mark_rejected(self, obs_id: str) -> None:
        self._update_status(obs_id, "rejected")

    def mark_pending(self, obs_ids: list[str]) -> None:
        for e in self._entries:
            if e["id"] in obs_ids:
                e["status"] = "pending_review"
        self._save()

    def _update_status(self, obs_id: str, status: str) -> None:
        for e in self._entries:
            if e["id"] == obs_id:
                e["status"] = status
                self._save()
                return


class FeedbackStep:
    """LLM 审视积累区，判定是否沉淀为待审核知识。"""

    def __init__(self, manager: FeedbackManager) -> None:
        self._manager = manager
        base_url = os.environ.get("LLM_BASE_URL", "").rstrip("/")
        self._endpoint = f"{base_url}/chat/completions"
        self._api_key = os.environ.get("LLM_API_KEY", "")
        self._model = os.environ.get("LLM_MODEL", "sec-agent-base")
        self._client = httpx.Client(timeout=httpx.Timeout(connect=10, read=120, write=30, pool=10))

    def review_and_precipitate(self) -> dict[str, Any]:
        """审视积累区，发现重复模式则沉淀。"""
        accumulated = self._manager.get_accumulated()
        if not accumulated:
            return {"precipitated": 0, "message": "积累区为空，无需审视"}

        prompt = f"""你是 EDR 安全知识管理员。请审视以下积累的观察记录，判断是否有值得沉淀为正式知识的模式。

积累记录 ({len(accumulated)} 条):
{json.dumps(accumulated, ensure_ascii=False, indent=2)}

沉淀标准：
- 同一类型的新 IOC/TTP 出现 3 次以上 → 建议沉淀
- 同类高置信度事件模式反复出现 → 建议沉淀
- 低置信度事件反复出现 → 可能是误报模式，标记 FALSE_POSITIVE
- 单次出现的异常 → 暂不沉淀，继续观察

请输出 JSON：
{{
  "precipitated_ids": ["obs-0001", "obs-0003"],
  "suggestions": [
    {{
      "suggestion_type": "NEW_IOC | NEW_TTP | FALSE_POSITIVE | SOP_UPDATE | EXPIRED_INTEL",
      "entities": {{"domains":[], "ips":[], "hashes":[], "package_names":[], "cve_ids":[], "ttp_tags":[]}},
      "summary": "沉淀建议描述",
      "evidence": ["引用的观察 ID 列表"],
      "review_required": true
    }}
  ],
  "keep_observing": ["obs-0002"],
  "note": "审视总结"
}}"""

        response = self._client.post(
            self._endpoint,
            headers={"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json"},
            json={
                "model": self._model,
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
                "temperature": 0,
                "max_tokens": 2000,
                "chat_template_kwargs": {"enable_thinking": False},
            },
        )

        if response.is_error:
            return {"precipitated": 0, "error": f"LLM API 错误: {response.status_code}"}

        choices = response.json().get("choices", [])
        if not choices:
            return {"precipitated": 0, "error": "LLM 无响应"}

        content = choices[0].get("message", {}).get("content", "")
        try:
            result = json.loads(_extract_json(content))
        except (json.JSONDecodeError, ValueError):
            return {"precipitated": 0, "error": f"LLM 输出无法解析: {content[:500]}"}

        # 标记沉淀条目
        precipitated = result.get("precipitated_ids", [])
        if precipitated:
            self._manager.mark_pending(precipitated)

        return result

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

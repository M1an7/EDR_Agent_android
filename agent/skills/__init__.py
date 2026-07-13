from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..runtime import AgentRuntime
from ..tools import ToolRegistration

SKILLS_DIR = Path(__file__).resolve().parent


class SkillTrigger:
    """技能触发条件：匹配 detection_type / category / ttp_tags / has_signals 的组合。"""

    def __init__(self, config: dict[str, Any]) -> None:
        self.detection_types: list[str] = config.get("detection_types", [])
        self.categories: list[str] = config.get("categories", [])
        self.ttp_tags: list[str] = config.get("ttp_tags", [])
        self.has_signals: list[str] = config.get("has_signals", [])

    def match(self, context: dict[str, Any]) -> int:
        """返回匹配分数（0 = 不匹配，越高越优先）。"""
        score = 0
        signals = context.get("signals", {})
        category = context.get("category", "")
        detection_type = context.get("detection_type", "")
        ttp = [t.upper() for t in signals.get("ttp_tags", [])]

        if self.detection_types and detection_type.upper() in [d.upper() for d in self.detection_types]:
            score += 3
        if self.categories and category.upper() in [c.upper() for c in self.categories]:
            score += 4
        if self.ttp_tags and any(t in ttp for t in self.ttp_tags):
            score += 2
        for sig_type in self.has_signals:
            if signals.get(sig_type):
                score += 1

        return score


class Skill:
    """封装一个分析技能：触发条件 + 提示词 + 工具集。"""

    def __init__(self, config: dict[str, Any], tool_registry: dict[str, ToolRegistration]) -> None:
        self.name: str = config["name"]
        self.description: str = config.get("description", "")
        self.trigger = SkillTrigger(config.get("trigger", {}))
        self.system_prompt: str = config.get("system_prompt", "")
        self.tool_registry = tool_registry

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description}


class SkillRegistry:
    """管理所有已注册技能。"""

    def __init__(self) -> None:
        self._skills: dict[str, Skill] = {}

    def register(self, skill: Skill) -> None:
        self._skills[skill.name] = skill

    def match(self, context: dict[str, Any]) -> list[tuple[Skill, int]]:
        """返回所有匹配的技能及分数，按分数降序排列。"""
        scored = []
        for skill in self._skills.values():
            s = skill.trigger.match(context)
            if s > 0:
                scored.append((skill, s))
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored

    def get_default(self) -> Skill:
        return self._skills.get("general_analysis") or list(self._skills.values())[0]

    def list_skills(self) -> list[dict[str, Any]]:
        return [s.to_dict() for s in self._skills.values()]


class SkillRouter:
    """根据事件上下文选择并调用技能。支持 fast（最优匹配）和 deep（并行+汇总）两种模式。"""

    def __init__(
        self,
        registry: SkillRegistry,
        base_tools: dict[str, ToolRegistration],
        mode: str = "fast",
    ) -> None:
        self.registry = registry
        self.base_tools = base_tools
        self.mode = mode

    def execute(
        self,
        event_id: str,
        signals: dict[str, Any],
        rule_result: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """执行技能分析，返回 skill_results 列表。"""
        context = {
            "signals": signals,
            "detection_type": rule_result.get("detection_type", "") if rule_result else "",
            "category": rule_result.get("category", "") if rule_result else "",
        }

        matches = self.registry.match(context)

        if not matches:
            default = self.registry.get_default()
            return [self._run_skill(default, signals, event_id)]

        if self.mode == "fast":
            best_skill, score = matches[0]
            print(f"\n[Skill] fast 模式: 选择 {best_skill.name} (分数={score})")
            return [self._run_skill(best_skill, signals, event_id)]

        # deep 模式：所有匹配技能并行
        print(f"\n[Skill] deep 模式: {len(matches)} 个技能并行")
        results = []
        for skill, score in matches:
            print(f"  - {skill.name} (分数={score})")
            results.append(self._run_skill(skill, signals, event_id))

        # 汇总
        print(f"\n[Skill] 汇总 {len(results)} 份结果...")
        summary = self._summarize(results, signals, event_id)
        results.append({"skill": "summary", "result": summary})
        return results

    def _run_skill(
        self, skill: Skill, signals: dict[str, Any], event_id: str
    ) -> dict[str, Any]:
        """预取数据注入 prompt → 单次 LLM 直出 JSON，不走工具调用。"""
        import os
        import httpx
        from dotenv import load_dotenv
        load_dotenv()

        # 预取上下文：优先用 event_id 精确匹配 RAG evidence pack
        rag_data, log_data = {}, {}
        for name, reg in self.base_tools.items():
            try:
                if name == "rag_search":
                    kws = " ".join(
                        (signals.get("domains") or []) + (signals.get("ips") or []) +
                        (signals.get("hashes") or []) + (signals.get("cve_ids") or []) +
                        (signals.get("package_names") or [])
                    )[:256]
                    rag_data = reg.handler(reg.args_model(query_keywords=kws))
                    # 如果 handler 返回的 RAG 结果是空的（没有 IOC 匹配），用 event_id 再试
                    if not rag_data.get("results") and event_id:
                        from ..rag import LocalRAGClient
                        local = LocalRAGClient()
                        rag_data = local.search(signals, event_id=event_id)
                elif name == "query_android_logs" and not log_data:
                    for kw in (signals.get("package_names") or [])[:2] + (signals.get("ttp_tags") or [])[:2]:
                        if kw:
                            log_data = reg.handler(reg.args_model(keyword=kw, limit=10))
                            if log_data.get("result", {}).get("returned_count", 0) > 0:
                                break
            except Exception:
                pass

        base_url = os.environ.get("LLM_BASE_URL", "").rstrip("/")
        client = httpx.Client(timeout=httpx.Timeout(connect=10, read=180, write=30, pool=10))

        prompt = f"""{skill.system_prompt}

事件 ID: {event_id}

已提取信号: {json.dumps(signals, ensure_ascii=False, indent=2)}

预查询 RAG 情报: {json.dumps(rag_data, ensure_ascii=False)[:2000]}
预查询日志数据: {json.dumps(log_data, ensure_ascii=False)[:2000]}

请立即输出 JSON 分类结果。"""

        try:
            response = client.post(
                f"{base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {os.environ.get('LLM_API_KEY', '')}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": os.environ.get("LLM_MODEL", ""),
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False, "temperature": 0, "max_tokens": 1200,
                    "chat_template_kwargs": {"enable_thinking": False},
                },
            )
            if response.is_error:
                return {"skill": skill.name, "result": {"detection_type": "UNKNOWN"}, "error": f"API {response.status_code}"}

            content = response.json()["choices"][0]["message"]["content"]
            from ..analysis_agent import _extract_json
            try:
                result = json.loads(_extract_json(content))
            except (json.JSONDecodeError, ValueError):
                result = {
                    "detection_type": "UNKNOWN", "category": "UNKNOWN", "severity": "LOW",
                    "evidence": [], "reasoning_summary": content[:300], "recommended_actions": [],
                }
            return {"skill": skill.name, "result": result}
        except Exception as e:
            return {"skill": skill.name, "result": {"detection_type": "UNKNOWN"}, "error": str(e)}
        finally:
            client.close()

    def _summarize(
        self, results: list[dict[str, Any]], signals: dict[str, Any], event_id: str
    ) -> dict[str, Any]:
        """LLM 汇总多技能结果。"""
        # 用最简单的单次 LLM 调用做汇总
        import os
        import httpx
        from dotenv import load_dotenv
        load_dotenv()

        summaries = []
        for r in results:
            if "result" in r:
                summaries.append({
                    "skill": r["skill"],
                    "detection_type": r["result"].get("detection_type"),
                    "category": r["result"].get("category"),
                    "severity": r["result"].get("severity"),
                    "reasoning": r["result"].get("reasoning_summary", "")[:200],
                })

        base_url = os.environ.get("LLM_BASE_URL", "").rstrip("/")
        client = httpx.Client(timeout=httpx.Timeout(connect=10, read=120, write=30, pool=10))

        try:
            response = client.post(
                f"{base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {os.environ.get('LLM_API_KEY', '')}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": os.environ.get("LLM_MODEL", ""),
                    "messages": [{
                        "role": "user",
                        "content": f"""请汇总裁决 {len(summaries)} 个专家技能对同一事件的分析结果。

各技能结果:
{json.dumps(summaries, ensure_ascii=False, indent=2)}

请输出最终共识 JSON：
{{"detection_type": "...", "category": "...", "severity": "...", "evidence": [], "reasoning_summary": "合并推理...", "skill_consensus": "agree|partial|disagree", "recommended_actions": []}}""",
                    }],
                    "stream": False,
                    "temperature": 0,
                    "max_tokens": 1200,
                    "chat_template_kwargs": {"enable_thinking": False},
                },
            )
            if response.is_error:
                return {"error": f"汇总 API 错误: {response.status_code}"}
            content = response.json()["choices"][0]["message"]["content"]
            from ..analysis_agent import _extract_json
            return json.loads(_extract_json(content))
        except Exception as e:
            return {"error": str(e)}
        finally:
            client.close()


def load_skills_from_dir() -> SkillRegistry:
    """从 agent/skills/ 目录加载 JSON 配置，注册到 SkillRegistry。"""
    registry = SkillRegistry()
    for f in sorted(SKILLS_DIR.glob("*.json")):
        config = json.loads(f.read_text(encoding="utf-8"))
        # 技能专属工具（初版为空，后续可追加）
        skill = Skill(config, {})
        registry.register(skill)
    return registry

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import httpx
from dotenv import load_dotenv

load_dotenv()

PROJECT_ROOT = Path(__file__).resolve().parents[1]
GRAPH_DIR = PROJECT_ROOT / "data" / "attack_graph"
AUDIT_DIR = PROJECT_ROOT / "logs" / "audit"

from .attack_chain import map_to_kill_chain, KILL_CHAIN_ORDER

# Kill Chain 阶段 → 能填补它的技能
PHASE_TO_SKILLS: dict[str, list[str]] = {
    "INITIAL_ACCESS": ["malware_analysis", "c2_investigation", "general_analysis"],
    "EXECUTION": ["malware_analysis", "privilege_escalation", "general_analysis"],
    "PERSISTENCE": ["malware_analysis", "general_analysis"],
    "PRIVILEGE_ESCALATION": ["privilege_escalation", "general_analysis"],
    "DEFENSE_EVASION": ["malware_analysis", "privilege_escalation", "general_analysis"],
    "CREDENTIAL_ACCESS": ["malware_analysis", "general_analysis"],
    "C2_COMMUNICATION": ["c2_investigation", "general_analysis"],
    "EXFILTRATION": ["c2_investigation", "general_analysis"],
}


class AttackGraph:
    """持久化攻击图：节点（事件）、边（关联）、Kill Chain 覆盖。"""

    def __init__(self, graph_id: str = "default") -> None:
        self.graph_id = graph_id
        GRAPH_DIR.mkdir(parents=True, exist_ok=True)
        self._path = GRAPH_DIR / f"{graph_id}.json"
        self.nodes: dict[str, dict] = {}   # event_id → {signals, classification, device_id, timestamp}
        self.edges: list[dict] = []         # {from, to, type, value}
        self._load()

    def _load(self) -> None:
        if self._path.exists():
            data = json.loads(self._path.read_text(encoding="utf-8"))
            self.nodes = data.get("nodes", {})
            self.edges = data.get("edges", [])

    def _save(self) -> None:
        self._path.write_text(json.dumps({
            "graph_id": self.graph_id, "nodes": self.nodes, "edges": self.edges,
        }, ensure_ascii=False, indent=2), encoding="utf-8")

    def add_event(self, event_id: str, signals: dict, classification: dict,
                  device_id: str = "", timestamp: str = "") -> None:
        if event_id in self.nodes:
            return
        self.nodes[event_id] = {
            "signals": signals, "classification": classification,
            "device_id": device_id, "timestamp": timestamp,
        }
        # 自动建 IOC 边
        for other_id, other in self.nodes.items():
            if other_id == event_id:
                continue
            for ioc_type in ["domains", "ips", "hashes", "cve_ids", "package_names"]:
                shared = set(signals.get(ioc_type, [])) & set(other["signals"].get(ioc_type, []))
                for val in shared:
                    self.edges.append({"from": other_id, "to": event_id, "type": ioc_type, "value": val})
        self._save()

    def coverage(self) -> dict:
        """返回 {phase: [event_ids]} 和 missing_phases。"""
        phase_events: dict[str, list[str]] = {p: [] for p in KILL_CHAIN_ORDER}
        for eid, node in self.nodes.items():
            category = node["classification"].get("category", "UNKNOWN")
            ttp = node["signals"].get("ttp_tags", [])
            phase = map_to_kill_chain(category, ttp)
            if phase != "UNKNOWN":
                phase_events[phase].append(eid)

        covered = [p for p in KILL_CHAIN_ORDER if phase_events[p]]
        missing = [p for p in KILL_CHAIN_ORDER if not phase_events[p]]
        return {"phase_events": phase_events, "covered": covered, "missing": missing}

    def get_clues_for_phase(self, phase: str) -> dict:
        """获取与缺失阶段相邻的已有线索。"""
        idx = KILL_CHAIN_ORDER.index(phase) if phase in KILL_CHAIN_ORDER else -1
        clues: dict[str, Any] = {"nearby_events": [], "iocs": [], "devices": []}
        # 向前后各看两个阶段
        for offset in [-2, -1, 1, 2]:
            neighbor_idx = idx + offset
            if 0 <= neighbor_idx < len(KILL_CHAIN_ORDER):
                neighbor = KILL_CHAIN_ORDER[neighbor_idx]
                cov = self.coverage()
                for eid in cov["phase_events"].get(neighbor, []):
                    node = self.nodes.get(eid, {})
                    clues["nearby_events"].append(eid)
                    for ioc_type in ["domains", "ips", "hashes"]:
                        clues["iocs"].extend(node.get("signals", {}).get(ioc_type, []))
                    if node.get("device_id"):
                        clues["devices"].append(node["device_id"])
        clues["devices"] = list(set(clues["devices"]))
        clues["iocs"] = list(set(clues["iocs"]))[:10]
        return clues


class Gap:
    """一个 Kill Chain 缺口。"""
    def __init__(self, phase: str, clues: dict, skills: list[str]) -> None:
        self.phase = phase
        self.clues = clues
        self.skills = skills


class EvidenceGapEvaluator:
    """评估攻击图缺口，按 Kill Chain 顺序排列。"""

    def evaluate(self, graph: AttackGraph) -> list[Gap]:
        cov = graph.coverage()
        gaps = []
        for phase in cov["missing"]:
            clues = graph.get_clues_for_phase(phase)
            skills = PHASE_TO_SKILLS.get(phase, ["general_analysis"])
            gaps.append(Gap(phase, clues, skills))
        return gaps


class AgentSelector:
    """对缺口选最优 Agent。冷启动 LLM 估算概率，运行时贝叶斯更新。"""

    def __init__(self) -> None:
        self._history: list[dict] = []  # {skill, phase, success, probability}

    def select(self, gap: Gap) -> tuple[str, float]:
        """返回 (skill_name, probability)。"""
        if not gap.skills:
            return ("general_analysis", 0.5)

        # 查历史概率
        best_skill, best_prob = gap.skills[0], 0.0
        for skill in gap.skills:
            past = [h for h in self._history if h["skill"] == skill and h["phase"] == gap.phase]
            if past:
                avg = sum(h["probability"] for h in past[-5:]) / min(len(past), 5)
            else:
                avg = self._llm_estimate(skill, gap)
                self._history.append({"skill": skill, "phase": gap.phase, "success": None, "probability": avg})
            if avg > best_prob:
                best_prob, best_skill = avg, skill

        return best_skill, round(best_prob, 2)

    def update(self, skill: str, phase: str, success: bool) -> None:
        """贝叶斯更新概率。"""
        for h in self._history:
            if h["skill"] == skill and h["phase"] == phase:
                old = h["probability"]
                if success:
                    h["probability"] = min(old + 0.15, 0.95)
                else:
                    h["probability"] = max(old - 0.20, 0.05)
                h["success"] = success
                return

    def _llm_estimate(self, skill: str, gap: Gap) -> float:
        """冷启动：LLM 估算该技能对缺口的填补概率。"""
        try:
            base_url = os.environ.get("LLM_BASE_URL", "").rstrip("/")
            client = httpx.Client(timeout=httpx.Timeout(connect=10, read=60, write=30, pool=10))
            response = client.post(
                f"{base_url}/chat/completions",
                headers={"Authorization": f"Bearer {os.environ.get('LLM_API_KEY', '')}", "Content-Type": "application/json"},
                json={
                    "model": os.environ.get("LLM_MODEL", ""),
                    "messages": [{"role": "user", "content": f"技能 '{skill}' 填补 Kill Chain 阶段 '{gap.phase}' 的概率是多少？线索: {json.dumps(gap.clues, ensure_ascii=False)[:500]}。只输出 0 到 1 之间的数字。"}],
                    "stream": False, "temperature": 0, "max_tokens": 10,
                    "chat_template_kwargs": {"enable_thinking": False},
                },
            )
            if response.is_error:
                return 0.5
            text = response.json()["choices"][0]["message"]["content"].strip()
            client.close()
            try:
                val = float(text)
                return max(0.1, min(0.9, val))
            except ValueError:
                return 0.5
        except Exception:
            return 0.5


class OrchestrationEngine:
    """编排引擎主循环：加载 → 评估 → 选择 → 派遣 → 更新 → 停止。"""

    def __init__(self) -> None:
        self.graph = AttackGraph()
        self.evaluator = EvidenceGapEvaluator()
        self.selector = AgentSelector()

    def run(self, max_rounds: int = 10, coverage_threshold: float = 0.5,
            min_marginal_gain: float = 0.1) -> dict:
        """运行编排循环。"""
        self._load_events_from_audit()
        rounds = []
        round_num = 0

        for round_num in range(1, max_rounds + 1):
            gaps = self.evaluator.evaluate(self.graph)
            if not gaps:
                print("[编排] 攻击图无缺口，停止")
                break

            # 取最早缺失阶段
            gap = gaps[0]
            cov = self.graph.coverage()
            completeness = len(cov["covered"]) / len(KILL_CHAIN_ORDER)

            # 停止条件：覆盖达标
            if completeness >= coverage_threshold:
                print(f"[编排] 覆盖 {completeness:.0%} ≥ {coverage_threshold:.0%}，停止")
                break

            # 选择 Agent
            skill, prob = self.selector.select(gap)
            if prob < min_marginal_gain:
                print(f"[编排] 最优 Agent '{skill}' 概率 {prob} < {min_marginal_gain}，停止")
                break

            print(f"\n[编排 轮次 {round_num}] 缺口={gap.phase} | 技能={skill} | 概率={prob} | 覆盖={completeness:.0%}")

            # 派遣：调用技能（预取数据 + LLM 直出）
            result = self._dispatch(skill, gap)
            success = result.get("hit", False)
            self.selector.update(skill, gap.phase, success)

            rounds.append({"round": round_num, "phase": gap.phase, "skill": skill,
                           "probability": prob, "success": success, "result": result})

            if success:
                result["phase"] = gap.phase
                self._add_result_to_graph(result, skill)

        cov = self.graph.coverage()
        completeness = len(cov["covered"]) / len(KILL_CHAIN_ORDER)
        return {"rounds": rounds, "total_rounds": round_num, "final_coverage": cov,
                "completeness": completeness, "graph_id": self.graph.graph_id}

    def _load_events_from_audit(self) -> None:
        if not AUDIT_DIR.exists():
            return
        for f in sorted(AUDIT_DIR.glob("*.jsonl")):
            events: dict[str, dict] = {}
            with f.open(encoding="utf-8") as fh:
                for line in fh:
                    entry = json.loads(line)
                    eid = entry["event_id"]
                    if eid not in events:
                        events[eid] = {}
                    if entry["stage"] == "signals_extracted":
                        events[eid]["signals"] = entry["data"]
                        events[eid]["timestamp"] = entry.get("timestamp", "")
                    elif entry["stage"] in ("rule_engine_hit", "llm_assessment"):
                        events[eid]["classification"] = entry["data"]
                    elif entry["stage"] == "event_parsed":
                        events[eid]["device_id"] = entry["data"].get("device_id", "")
            for eid, evt in events.items():
                if "signals" in evt and "classification" in evt:
                    self.graph.add_event(eid, evt.get("signals", {}), evt.get("classification", {}),
                                         evt.get("device_id", ""), evt.get("timestamp", ""))

    def _dispatch(self, skill_name: str, gap: Gap) -> dict:
        """用技能系统真实预取数据 + LLM 判定是否补上缺口。"""
        try:
            # 用线索中的 IOC 做真实查询
            from .rag import MockRAGClient
            from .analysis_agent import build_analysis_tools
            from .main import query_android_logs, query_android_vulnerabilities

            rag = MockRAGClient()
            base_tools = build_analysis_tools(rag, query_android_logs, query_android_vulnerabilities)

            # 预取：RAG 查线索中的 IOC
            clues = gap.clues
            rag_result = {}
            log_result = {}
            for name, reg in base_tools.items():
                try:
                    if name == "rag_search":
                        kws = " ".join(clues.get("iocs", []) + clues.get("devices", []))[:256]
                        if kws:
                            rag_result = reg.handler(reg.args_model(query_keywords=kws))
                    elif name == "query_android_logs" and not log_result:
                        for kw in clues.get("iocs", [])[:3]:
                            if kw:
                                log_result = reg.handler(reg.args_model(keyword=kw, limit=10))
                                if log_result.get("returned_count", 0) > 0:
                                    break
                except Exception:
                    pass

            base_url = os.environ.get("LLM_BASE_URL", "").rstrip("/")
            client = httpx.Client(timeout=httpx.Timeout(connect=10, read=180, write=30, pool=10))

            prompt = f"""你是安全调查 Agent。当前攻击链缺失阶段: {gap.phase}。
技能: {skill_name}

已有线索: {json.dumps(clues, ensure_ascii=False)[:1000]}

RAG 查询结果: {json.dumps(rag_result, ensure_ascii=False)[:1500]}
日志查询结果: {json.dumps(log_result, ensure_ascii=False)[:1500]}

请根据以上真实数据判定 {gap.phase} 阶段是否存在攻击证据。
输出 JSON: {{"hit": true/false, "confidence": 0.0-1.0, "evidence": "...", "detection_type": "ATTACK", "category": "根据数据推断的分类"}}"""

            response = client.post(
                f"{base_url}/chat/completions",
                headers={"Authorization": f"Bearer {os.environ.get('LLM_API_KEY', '')}", "Content-Type": "application/json"},
                json={"model": os.environ.get("LLM_MODEL", ""), "messages": [{"role": "user", "content": prompt}],
                      "stream": False, "temperature": 0, "max_tokens": 800,
                      "chat_template_kwargs": {"enable_thinking": False}},
            )
            client.close()
            if response.is_error:
                return {"hit": False, "error": f"API {response.status_code}"}
            content = response.json()["choices"][0]["message"]["content"]
            try:
                result = json.loads(content)
            except json.JSONDecodeError:
                from .analysis_agent import _extract_json
                result = json.loads(_extract_json(content))

            result["rag_data"] = rag_result
            result["log_data"] = log_result
            return result
        except Exception as e:
            return {"hit": False, "error": str(e)}

    def _add_result_to_graph(self, result: dict, skill: str) -> None:
        """把 LLM 判定结果作为新节点加入攻击图。"""
        # 直接用缺口阶段名，不依赖 LLM 自由文本分类
        category = result.get("phase", "UNKNOWN")

        eid = f"orch-{len(self.graph.nodes)+1:04d}"
        self.graph.add_event(
            eid,
            signals={"ttp_tags": result.get("ttp_tags", [])},
            classification={
                "detection_type": result.get("detection_type", "ATTACK"),
                "category": category,
            },
            device_id="orchestrator",
            timestamp="",
        )

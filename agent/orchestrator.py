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


def _kill_chain_phase_distance(phase_a: str, phase_b: str) -> int:
    """计算两个 Kill Chain 阶段之间的距离。"""
    try:
        return abs(KILL_CHAIN_ORDER.index(phase_a) - KILL_CHAIN_ORDER.index(phase_b))
    except ValueError:
        return 3


def _phase_distance_weight(distance: int) -> float:
    """阶段距离 → 权重衰减。"""
    if distance <= 1:
        return 0.8
    elif distance == 2:
        return 0.5
    return 0.2


class AttackGraph:
    """EAG = (V, E, W, C)：证据攻击图。"""

    def __init__(self, graph_id: str = "default") -> None:
        self.graph_id = graph_id
        GRAPH_DIR.mkdir(parents=True, exist_ok=True)
        self._path = GRAPH_DIR / f"{graph_id}.json"
        self.nodes: dict[str, dict] = {}    # id → {node_type, signals, classification, device_id, timestamp}
        self.edges: list[dict] = []          # {from, to, edge_type, weight, evidence}
        self.conflicts: list[dict] = []      # [{node, conflicting_edges, severity}]
        self._load()

    def _load(self) -> None:
        if self._path.exists():
            data = json.loads(self._path.read_text(encoding="utf-8"))
            self.nodes = data.get("nodes", {})
            self.edges = data.get("edges", [])
            self.conflicts = data.get("conflicts", [])

    def _save(self) -> None:
        self._path.write_text(json.dumps({
            "graph_id": self.graph_id, "nodes": self.nodes, "edges": self.edges,
            "conflicts": self.conflicts,
        }, ensure_ascii=False, indent=2), encoding="utf-8")

    # ------------------------------------------------------------------
    # V: 节点
    # ------------------------------------------------------------------

    def add_device_node(self, device_id: str) -> str:
        nid = f"device:{device_id}"
        if nid not in self.nodes:
            self.nodes[nid] = {"node_type": "entity", "device_id": device_id}
            self._save()
        return nid

    def add_event_node(self, event_id: str, signals: dict, classification: dict,
                       device_id: str = "", timestamp: str = "") -> str:
        if event_id in self.nodes:
            return event_id
        phase = map_to_kill_chain(
            classification.get("category", "UNKNOWN"),
            signals.get("ttp_tags", []),
        )
        self.nodes[event_id] = {
            "node_type": "event",
            "signals": signals, "classification": classification,
            "device_id": device_id, "timestamp": timestamp, "kill_chain_phase": phase,
        }
        if device_id:
            self.add_device_node(device_id)
        self._save()
        return event_id

    def add_technique_node(self, cve_or_ttp: str, tech_type: str = "cve") -> str:
        nid = f"technique:{cve_or_ttp}"
        if nid not in self.nodes:
            self.nodes[nid] = {"node_type": "attack_technique", "value": cve_or_ttp, "tech_type": tech_type}
            self._save()
        return nid

    # ------------------------------------------------------------------
    # E + W: 边 + 权重
    # ------------------------------------------------------------------

    def _add_edge(self, source: str, target: str, edge_type: str, weight: float,
                   value: str = "", evidence: str = "") -> None:
        """去重添加边。"""
        for e in self.edges:
            e_target = e.get("to", e.get("target", ""))
            if e["from"] == source and e_target == target and e["edge_type"] == edge_type and e.get("value") == value:
                return
        self.edges.append({
            "from": source, "target": target, "edge_type": edge_type,
            "weight": round(weight, 2), "value": value, "evidence": evidence,
        })

    def build_ioc_edges(self) -> int:
        """IOC 精确匹配边，权重 1.0。"""
        count = 0
        event_nodes = {k: v for k, v in self.nodes.items() if v.get("node_type") == "event"}
        for eid_a, node_a in event_nodes.items():
            for eid_b, node_b in event_nodes.items():
                if eid_a >= eid_b:
                    continue
                for ioc_type in ["domains", "ips", "hashes", "cve_ids", "package_names"]:
                    shared = set(node_a["signals"].get(ioc_type, [])) & set(node_b["signals"].get(ioc_type, []))
                    for val in shared:
                        self._add_edge(eid_a, eid_b, "ioc_match", 1.0, val,
                                       f"IOC 精确匹配: {ioc_type}={val}")
                        count += 1
        self._save()
        return count

    def build_causal_edges(self) -> dict:
        """构建 4 种因果边，返回各类型计数。"""
        event_nodes = {k: v for k, v in self.nodes.items() if v.get("node_type") == "event"}
        ids = sorted(event_nodes.keys())
        counts = {"temporal_causal": 0, "semantic_causal": 0, "process_causal": 0, "dataflow_causal": 0}

        for i in range(len(ids)):
            for j in range(i + 1, len(ids)):
                a_id, a = ids[i], event_nodes[ids[i]]
                b_id, b = ids[j], event_nodes[ids[j]]

                # 只对有 Kill Chain 阶段的事件建因果边
                phase_a = a.get("kill_chain_phase", "UNKNOWN")
                phase_b = b.get("kill_chain_phase", "UNKNOWN")
                if phase_a == "UNKNOWN" or phase_b == "UNKNOWN":
                    continue
                if phase_a == phase_b:
                    continue

                # 时序因果：同设备 + 时间有序
                edge = self._detect_temporal_causal(a_id, a, b_id, b)
                if edge:
                    self._add_edge(**edge)
                    counts["temporal_causal"] += 1

                edge = self._detect_semantic_causal(a_id, a, b_id, b)
                if edge:
                    self._add_edge(**edge)
                    counts["semantic_causal"] += 1

                # LLM 因果判定（通过环境变量 ENABLE_LLM_CAUSAL=1 启用）
                if os.environ.get("ENABLE_LLM_CAUSAL"):
                    edge = self._llm_judge_causal(a_id, a, b_id, b, "process_causal")
                    if edge:
                        self._add_edge(**edge)
                        counts["process_causal"] += 1
                    edge = self._llm_judge_causal(a_id, a, b_id, b, "dataflow_causal")
                    if edge:
                        self._add_edge(**edge)
                        counts["dataflow_causal"] += 1

        self._save()
        return counts

    def _detect_temporal_causal(self, a_id: str, a: dict, b_id: str, b: dict) -> dict | None:
        """时序因果：同设备 + a 的阶段在 b 之前。"""
        if a.get("device_id") != b.get("device_id"):
            return None
        phase_a = a.get("kill_chain_phase", "")
        phase_b = b.get("kill_chain_phase", "")
        if phase_a not in KILL_CHAIN_ORDER or phase_b not in KILL_CHAIN_ORDER:
            return None
        if KILL_CHAIN_ORDER.index(phase_a) >= KILL_CHAIN_ORDER.index(phase_b):
            return None
        dist = _kill_chain_phase_distance(phase_a, phase_b)
        return {"source":a_id, "target": b_id, "edge_type": "temporal_causal",
                "weight": _phase_distance_weight(dist),
                "value": f"{phase_a}→{phase_b}",
                "evidence": f"同设备时序因果: {a.get('device_id')} / {phase_a}→{phase_b}"}

    def _detect_semantic_causal(self, a_id: str, a: dict, b_id: str, b: dict) -> dict | None:
        """语义因果：Kill Chain 阶段递进（跨设备）。"""
        phase_a = a.get("kill_chain_phase", "")
        phase_b = b.get("kill_chain_phase", "")
        if phase_a not in KILL_CHAIN_ORDER or phase_b not in KILL_CHAIN_ORDER:
            return None
        if KILL_CHAIN_ORDER.index(phase_a) >= KILL_CHAIN_ORDER.index(phase_b):
            return None
        dist = _kill_chain_phase_distance(phase_a, phase_b)
        return {"source":a_id, "target": b_id, "edge_type": "semantic_causal",
                "weight": _phase_distance_weight(dist),
                "value": f"{phase_a}→{phase_b}",
                "evidence": f"Kill Chain 阶段递进: {phase_a}→{phase_b} (距离={dist})"}

    def _llm_judge_causal(self, a_id: str, a: dict, b_id: str, b: dict, edge_type: str) -> dict | None:
        """LLM 判定进程/数据流因果。粗筛：同设备 + 两个事件分类不同。"""
        if a.get("device_id") != b.get("device_id"):
            return None
        try:
            base_url = os.environ.get("LLM_BASE_URL", "").rstrip("/")
            client = httpx.Client(timeout=httpx.Timeout(connect=10, read=60, write=30, pool=10))

            prompt_type = "进程父子关系" if edge_type == "process_causal" else "数据流转关系"
            response = client.post(
                f"{base_url}/chat/completions",
                headers={"Authorization": f"Bearer {os.environ.get('LLM_API_KEY', '')}", "Content-Type": "application/json"},
                json={
                    "model": os.environ.get("LLM_MODEL", ""),
                    "messages": [{"role": "user", "content": f"两个事件之间是否存在{prompt_type}？\n事件A: {json.dumps({k: str(v)[:200] for k, v in a.items()}, ensure_ascii=False)}\n事件B: {json.dumps({k: str(v)[:200] for k, v in b.items()}, ensure_ascii=False)}\n输出 JSON: {{\"causal\": true/false, \"confidence\": 0.0-1.0, \"reason\": \"...\"}}"}],
                    "stream": False, "temperature": 0, "max_tokens": 300,
                    "chat_template_kwargs": {"enable_thinking": False},
                },
            )
            if response.is_error:
                return None
            content = response.json()["choices"][0]["message"]["content"]
            client.close()
            result = json.loads(content) if content.strip().startswith("{") else None
            if result and result.get("causal") and result.get("confidence", 0) >= 0.5:
                return {"source":a_id, "target": b_id, "edge_type": edge_type,
                        "weight": round(result["confidence"], 2),
                        "value": result.get("reason", "")[:100],
                        "evidence": f"LLM 判定{prompt_type}: {result.get('reason', '')[:150]}"}
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------
    # C: 冲突检测
    # ------------------------------------------------------------------

    def detect_conflicts(self) -> list[dict]:
        """检测分类冲突：同一事件不同分类 / 同一设备矛盾阶段。"""
        self.conflicts = []
        event_nodes = {k: v for k, v in self.nodes.items() if v.get("node_type") == "event"}

        # 同设备上的事件，按照设备分组
        by_device: dict[str, list[str]] = {}
        for eid, node in event_nodes.items():
            dev = node.get("device_id", "")
            if dev:
                by_device.setdefault(dev, []).append(eid)

        for dev, eids in by_device.items():
            phases = set()
            for eid in eids:
                phase = event_nodes[eid].get("kill_chain_phase", "UNKNOWN")
                if phase != "UNKNOWN" and phase in phases:
                    self.conflicts.append({
                        "node": eid, "device": dev,
                        "conflict_type": "duplicate_phase",
                        "severity": "low",
                    })
                phases.add(phase)

            det_types = set(event_nodes[eid].get("classification", {}).get("detection_type", "") for eid in eids)
            if len(det_types) > 1:
                self.conflicts.append({
                    "node": dev, "device": dev,
                    "conflict_type": "contradictory_classification",
                    "conflicting_types": list(det_types),
                    "severity": "medium",
                })

        self._save()
        return self.conflicts

    # ------------------------------------------------------------------
    # 导出 + 覆盖
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """导出完整 EAG JSON。"""
        return {
            "graph_id": self.graph_id,
            "V": {"nodes": self.nodes, "total": len(self.nodes)},
            "E": {"edges": self.edges, "total": len(self.edges),
                  "by_type": {t: sum(1 for e in self.edges if e["edge_type"] == t) for t in
                              ["ioc_match", "temporal_causal", "semantic_causal", "process_causal", "dataflow_causal"]}},
            "W": {"avg_weight": round(sum(e["weight"] for e in self.edges) / max(len(self.edges), 1), 2)},
            "C": {"conflicts": self.conflicts, "total": len(self.conflicts)},
        }

    def coverage(self) -> dict:
        phase_events: dict[str, list[str]] = {p: [] for p in KILL_CHAIN_ORDER}
        for eid, node in self.nodes.items():
            if node.get("node_type") != "event":
                continue
            phase = node.get("kill_chain_phase", "UNKNOWN")
            if phase != "UNKNOWN":
                phase_events[phase].append(eid)
        covered = [p for p in KILL_CHAIN_ORDER if phase_events[p]]
        missing = [p for p in KILL_CHAIN_ORDER if not phase_events[p]]
        return {"phase_events": phase_events, "covered": covered, "missing": missing}

    def get_clues_for_phase(self, phase: str) -> dict:
        idx = KILL_CHAIN_ORDER.index(phase) if phase in KILL_CHAIN_ORDER else -1
        clues: dict[str, Any] = {"nearby_events": [], "iocs": [], "devices": []}
        for offset in [-2, -1, 1, 2]:
            ni = idx + offset
            if 0 <= ni < len(KILL_CHAIN_ORDER):
                cov = self.coverage()
                for eid in cov["phase_events"].get(KILL_CHAIN_ORDER[ni], []):
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
    def __init__(self, phase: str, clues: dict, skills: list[str], priority: str = "normal") -> None:
        self.phase = phase
        self.clues = clues
        self.skills = skills
        self.priority = priority  # high / normal / low


class EvidenceGapEvaluator:
    """评估攻击图缺口。有 RAG 模板时优先排查模板指定的阶段。"""

    def __init__(self, rag_templates: list[dict] | None = None) -> None:
        self._rag_templates = rag_templates or []

    def evaluate(self, graph: AttackGraph) -> list[Gap]:
        cov = graph.coverage()
        # 从 RAG 模板中提取该攻击类型应该覆盖的阶段
        template_phases: set[str] = set()
        for tpl in self._rag_templates:
            for stage in tpl.get("stages", []):
                phase = self._tactic_to_kill_chain(stage.get("tactic_name", ""))
                if phase:
                    template_phases.add(phase)

        gaps = []
        for phase in cov["missing"]:
            clues = graph.get_clues_for_phase(phase)
            skills = PHASE_TO_SKILLS.get(phase, ["general_analysis"])

            # 模板指定了该阶段 → 高优先级；模板未提及 → 低优先级
            if template_phases and phase in template_phases:
                priority = "high"
            elif template_phases:
                priority = "low"
            else:
                priority = "normal"

            gaps.append(Gap(phase, clues, skills, priority))

        # 排序：高优先级在前，同类按 Kill Chain 顺序
        gaps.sort(key=lambda g: ({"high": 0, "normal": 1, "low": 2}[g.priority],
                                  KILL_CHAIN_ORDER.index(g.phase) if g.phase in KILL_CHAIN_ORDER else 99))
        return gaps

    @staticmethod
    def _tactic_to_kill_chain(tactic_name: str) -> str:
        """RAG 模板 tactic_name → Kill Chain 阶段。"""
        name = tactic_name.lower().replace(" ", "_").replace("-", "_")
        mapping = {
            "malicious_apk_install": "INITIAL_ACCESS",
            "initial_access": "INITIAL_ACCESS",
            "execution": "EXECUTION",
            "dynamic_payload_loading": "EXECUTION",
            "persistence": "PERSISTENCE",
            "privilege_escalation": "PRIVILEGE_ESCALATION",
            "defense_evasion": "DEFENSE_EVASION",
            "credential_access": "CREDENTIAL_ACCESS",
            "collection": "CREDENTIAL_ACCESS",
            "sensitive_permission_request": "CREDENTIAL_ACCESS",
            "command_and_control": "C2_COMMUNICATION",
            "c2_communication": "C2_COMMUNICATION",
            "exfiltration": "EXFILTRATION",
            "sensitive_data_upload": "EXFILTRATION",
        }
        return mapping.get(name, "")


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


def _rag_tactic_to_stages(content_summary: str) -> list[dict]:
    """从 RAG 内容摘要中提取战术阶段。"""
    stages = []
    keyword_to_tactic = {
        "malicious_apk": "malicious_apk_install",
        "permission": "sensitive_permission_request",
        "dynamic_load": "dynamic_payload_loading",
        "c2": "command_and_control",
        "exfiltration": "sensitive_data_upload",
        "data_upload": "sensitive_data_upload",
    }
    for kw, tactic in keyword_to_tactic.items():
        if kw in content_summary.lower():
            stages.append({"tactic_name": tactic})
    return stages


class OrchestrationEngine:
    """编排引擎主循环：加载 → 评估 → 选择 → 派遣 → 更新 → 停止。"""

    def __init__(self) -> None:
        self.graph = AttackGraph()
        self.selector = AgentSelector()
        self.evaluator = EvidenceGapEvaluator()  # 会被 _load_rag_templates 更新

    def _load_rag_templates(self) -> None:
        """从 RAG evidence pack 直接加载攻击链模板阶段。"""
        from pathlib import Path
        PROJECT_ROOT = Path(__file__).resolve().parents[1]
        RAG_SAMPLES = PROJECT_ROOT / "rag" / "samples" / "rag_evidence_packs"
        if not RAG_SAMPLES.exists():
            return

        templates: list[dict] = []
        for f in sorted(RAG_SAMPLES.glob("*.rag_evidence_pack.json")):
            try:
                pack = json.loads(f.read_text(encoding="utf-8"))
                stages = pack.get("attack_path", [])
                if stages:
                    templates.append({
                        "source": pack.get("input_event_id", ""),
                        "stages": stages,
                    })
            except Exception:
                pass

        if templates:
            self.evaluator = EvidenceGapEvaluator(templates)
            print(f"[编排] 加载 {len(templates)} 个 RAG 攻击链模板")
            for t in templates:
                names = [s.get("tactic_name", "?") for s in t["stages"]]
                print(f"  {t['source']}: {' → '.join(names)}")

    def run(self, max_rounds: int = 10, coverage_threshold: float = 0.5,
            min_marginal_gain: float = 0.1) -> dict:
        """运行编排循环。"""
        self._load_events_from_audit()
        ioc_count = self.graph.build_ioc_edges()
        causal_counts = self.graph.build_causal_edges()
        conflicts = self.graph.detect_conflicts()
        eag = self.graph.to_dict()
        print(f"[编排] EAG: {eag['V']['total']} 节点, {eag['E']['total']} 边 "
              f"(IOC={ioc_count} 因果={sum(causal_counts.values())}) 冲突={len(conflicts)}")
        by_type = eag['E']['by_type']
        for t, c in by_type.items():
            if c > 0:
                print(f"  {t}: {c} 条")
        self._load_rag_templates()
        rounds = []
        round_num = 0

        for round_num in range(1, max_rounds + 1):
            gaps = self.evaluator.evaluate(self.graph)
            if not gaps:
                print("[编排] 攻击图无缺口，停止")
                break

            # 优先排查高优先级缺口
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

            prio_label = {"high": "▲", "normal": " ", "low": "▽"}.get(gap.priority, " ")
            print(f"\n[编排 轮次 {round_num}] {prio_label} 缺口={gap.phase} | 技能={skill} | 概率={prob} | 覆盖={completeness:.0%}")

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
                    self.graph.add_event_node(eid, evt.get("signals", {}), evt.get("classification", {}),
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
        self.graph.add_event_node(
            eid,
            signals={"ttp_tags": result.get("ttp_tags", [])},
            classification={
                "detection_type": result.get("detection_type", "ATTACK"),
                "category": category,
            },
            device_id="orchestrator",
            timestamp="",
        )

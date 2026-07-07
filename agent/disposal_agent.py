from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import Field

from .runtime import AgentRuntime
from .tools import StrictArgs, ToolRegistration

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PLAYBOOKS_PATH = PROJECT_ROOT / "data" / "playbooks" / "playbooks.json"


# ---------------------------------------------------------------------------
# 工具参数模型
# ---------------------------------------------------------------------------

class DeviceContextArgs(StrictArgs):
    device_id: str = Field(min_length=1, max_length=128)


class RemediationHistoryArgs(StrictArgs):
    device_id: str = Field(min_length=1, max_length=128)
    category: str | None = Field(default=None, max_length=64)


class RemediationStateArgs(StrictArgs):
    device_id: str = Field(min_length=1, max_length=128)


class ExecuteRemediationArgs(StrictArgs):
    device_id: str = Field(min_length=1, max_length=128)
    action: str = Field(min_length=1, max_length=64)
    target: str | None = Field(default=None, max_length=256)


class PlaybookArgs(StrictArgs):
    category: str = Field(min_length=1, max_length=64)


class ServiceDependencyArgs(StrictArgs):
    target: str = Field(min_length=1, max_length=256)
    target_type: str = Field(default="domain", max_length=16)


# ---------------------------------------------------------------------------
# Mock 数据
# ---------------------------------------------------------------------------

_MOCK_DEVICES: dict[str, dict[str, Any]] = {
    "pixel-7": {
        "device_id": "pixel-7",
        "role": "employee-personal",
        "department": "engineering",
        "criticality": "medium",
        "user": "zhang.san@company.com",
        "managed_by_mdm": True,
    },
    "xiaomi-redmi-01": {
        "device_id": "xiaomi-redmi-01",
        "role": "kiosk-pos",
        "department": "retail",
        "criticality": "high",
        "user": "store-42@company.com",
        "managed_by_mdm": True,
    },
    "samsung-s21-01": {
        "device_id": "samsung-s21-01",
        "role": "executive",
        "department": "management",
        "criticality": "critical",
        "user": "ceo@company.com",
        "managed_by_mdm": True,
    },
}

_MOCK_DEPENDENCIES: dict[str, list[str]] = {
    "evil.example.com": ["mock: 无合法业务关联"],
    "uc.huawei.com": ["Huawei System Update Service", "Huawei AppGallery"],
    "103.45.67.89": ["mock: 无合法业务关联"],
}


# ---------------------------------------------------------------------------
# 系统提示词
# ---------------------------------------------------------------------------

DISPOSAL_SYSTEM_PROMPT = """
你是 Android EDR 处置策略 Agent，负责在高置信度自动处置场景下制定执行方案。

你有 6 个工具：
- get_device_context：查询设备业务角色和关键度
- get_remediation_history：查询历史处置记录
- get_current_remediation_state：查询设备当前是否已有处置在执行
- execute_remediation：执行处置动作（记录，不真正执行）
- query_remediation_playbook：查询标准处置 SOP（优先级、时机、回滚方案）
- query_service_dependency：查询目标（域名/IP/应用）是否关联合法业务

工作流程：
1. 先查设备上下文，了解影响范围
2. 查处置历史，避免重复处置
3. 查当前状态，避免冲突
4. 查处置 SOP，获取标准流程
5. 对每个处置目标查服务依赖，评估业务影响
6. 按 SOP 优先级调用 execute_remediation 执行各项处置动作
7. 全部执行完毕后输出最终 JSON 总结

必须遵守：
- 只执行白名单内的动作（BLOCK_DOMAIN/BLOCK_IP/ISOLATE_APP/DISABLE_PERMISSION/TRIGGER_SCAN/COLLECT_FORENSIC_DATA/CREATE_TICKET/SEND_ALERT）
- 不执行破坏性动作（WIPE_DEVICE/UNINSTALL_APP/RESET_POLICY/MODIFY_SYSTEM_CONFIG）
- 处置前评估业务影响，涉及高管或关键业务设备时需特别标注
- 处置顺序遵循 SOP 优先级的推荐
- 如果目标是合法业务服务，不得阻断，标记为需人工确认
- 不得重复调用相同工具和相同参数
- 工具返回足以完成方案时，立即输出最终 JSON，停止调用工具

最终输出必须是以下 JSON 格式：
{
  "disposal_plan": [
    {
      "step": 1,
      "action": "BLOCK_DOMAIN",
      "target": "evil.example.com",
      "timing": "immediate",
      "business_impact": "无，该域名无合法业务关联",
      "reason": "阻断 C2 通信，防止数据外泄"
    }
  ],
  "warnings": ["涉及高管设备，已降低处置等级"],
  "requires_manual_approval": false,
  "rollback_plan": "若确认为误报，解封域名并恢复应用权限",
  "summary": "处置方案简述（中文）"
}
""".strip()


# ---------------------------------------------------------------------------
# 工厂：构建处置 Agent 工具集
# ---------------------------------------------------------------------------

def build_disposal_tools() -> dict[str, ToolRegistration]:
    playbooks = {}
    if PLAYBOOKS_PATH.exists():
        playbooks = json.loads(PLAYBOOKS_PATH.read_text(encoding="utf-8"))

    def get_device_context(args: DeviceContextArgs) -> dict[str, Any]:
        device = _MOCK_DEVICES.get(args.device_id)
        if device:
            return {"ok": True, "device": device}
        return {"ok": True, "device": {
            "device_id": args.device_id,
            "role": "unknown",
            "criticality": "unknown",
            "note": "mock: 设备不在已知库中",
        }}

    def get_remediation_history(args: RemediationHistoryArgs) -> dict[str, Any]:
        return {"ok": True, "device_id": args.device_id, "history": [], "note": "mock: 无历史处置记录"}

    def get_current_state(args: RemediationStateArgs) -> dict[str, Any]:
        return {"ok": True, "device_id": args.device_id, "active_remediations": [], "note": "mock: 无进行中的处置"}

    def execute_remediation(args: ExecuteRemediationArgs) -> dict[str, Any]:
        return {
            "ok": True,
            "device_id": args.device_id,
            "action": args.action,
            "target": args.target,
            "status": "executed",
            "note": "mock: 处置动作已记录（未真正执行）",
        }

    def query_playbook(args: PlaybookArgs) -> dict[str, Any]:
        pb = playbooks.get(args.category) or playbooks.get("DEFAULT", {})
        return {"ok": True, "category": args.category, "playbook": pb}

    def query_dependency(args: ServiceDependencyArgs) -> dict[str, Any]:
        target = args.target.lower()
        services = _MOCK_DEPENDENCIES.get(target, [f"mock: 无 {target} 的依赖记录"])
        return {"ok": True, "target": target, "associated_services": services}

    return {
        "get_device_context": ToolRegistration(
            description="查询 Android 设备的业务角色、部门、关键度和用户信息。",
            args_model=DeviceContextArgs,
            handler=get_device_context,
        ),
        "get_remediation_history": ToolRegistration(
            description="查询设备或同类事件的历史处置记录，避免重复操作。",
            args_model=RemediationHistoryArgs,
            handler=get_remediation_history,
        ),
        "get_current_remediation_state": ToolRegistration(
            description="查询设备当前是否有处置动作正在执行，避免冲突。",
            args_model=RemediationStateArgs,
            handler=get_current_state,
        ),
        "execute_remediation": ToolRegistration(
            description="执行白名单内的处置动作（mock 模式仅记录不真执行）。",
            args_model=ExecuteRemediationArgs,
            handler=execute_remediation,
        ),
        "query_remediation_playbook": ToolRegistration(
            description="查询指定攻击类别的标准处置 SOP（优先级、时机、回滚方案）。",
            args_model=PlaybookArgs,
            handler=query_playbook,
        ),
        "query_service_dependency": ToolRegistration(
            description="查询目标（域名/IP/应用包名）是否关联已知合法业务服务。",
            args_model=ServiceDependencyArgs,
            handler=query_dependency,
        ),
    }


# ---------------------------------------------------------------------------
# 处置 Agent
# ---------------------------------------------------------------------------

class DisposalAgent:
    """高置信度自动处置时，制定执行方案。"""

    def __init__(self) -> None:
        tool_registry = build_disposal_tools()
        self._runtime = AgentRuntime(
            system_prompt=DISPOSAL_SYSTEM_PROMPT,
            tool_registry=tool_registry,
            max_steps=15,
        )

    def plan(self, context: dict[str, Any]) -> dict[str, Any]:
        """输入管道结果 JSON，输出处置方案。"""
        user_prompt = f"""请为以下事件制定处置方案：

{json.dumps(context, ensure_ascii=False, indent=2)}

请调用必要工具后输出最终 JSON 处置方案。"""

        raw_output = self._runtime.run(user_prompt)

        try:
            json_match = _extract_json(raw_output)
            return json.loads(json_match)
        except (json.JSONDecodeError, ValueError):
            return {
                "disposal_plan": [],
                "warnings": ["LLM 输出无法解析"],
                "requires_manual_approval": True,
                "summary": f"处置 Agent 输出解析失败，原始输出: {raw_output[:500]}",
            }

    def close(self) -> None:
        self._runtime.close()


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
    raise ValueError("无法从 LLM 输出中提取 JSON")

from __future__ import annotations

import ast
import json
import uuid
from typing import Any, Callable

from pydantic import BaseModel, ConfigDict, ValidationError


# ---------------------------------------------------------------------------
# 工具参数模型基类：禁止额外字段
# ---------------------------------------------------------------------------

class StrictArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------------------------
# 工具注册
# ---------------------------------------------------------------------------

class ToolRegistration:
    def __init__(
        self,
        description: str,
        args_model: type[BaseModel],
        handler: Callable[[Any], dict[str, Any]],
    ) -> None:
        self.description = description
        self.args_model = args_model
        self.handler = handler


# ---------------------------------------------------------------------------
# JSON Schema 构建
# ---------------------------------------------------------------------------

def remove_schema_titles(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: remove_schema_titles(item)
            for key, item in value.items()
            if key != "title"
        }

    if isinstance(value, list):
        return [remove_schema_titles(item) for item in value]

    return value


def build_tool_schemas(registry: dict[str, ToolRegistration]) -> list[dict[str, Any]]:
    tools: list[dict[str, Any]] = []

    for name, registration in registry.items():
        parameters = registration.args_model.model_json_schema()
        parameters = remove_schema_titles(parameters)

        tools.append(
            {
                "type": "function",
                "function": {
                    "name": name,
                    "description": registration.description,
                    "parameters": parameters,
                },
            }
        )

    return tools


# ---------------------------------------------------------------------------
# 参数解析：兼容 JSON 字符串、Python 字面量、dict
# ---------------------------------------------------------------------------

def parse_arguments(raw_arguments: Any) -> dict[str, Any]:
    if raw_arguments is None:
        return {}

    if isinstance(raw_arguments, dict):
        return raw_arguments

    if not isinstance(raw_arguments, str):
        raise ValueError(
            f"不支持的 arguments 类型: {type(raw_arguments).__name__}"
        )

    try:
        result = json.loads(raw_arguments)
    except json.JSONDecodeError:
        try:
            result = ast.literal_eval(raw_arguments)
        except (ValueError, SyntaxError) as exc:
            raise ValueError(
                f"工具参数不是合法JSON: {raw_arguments!r}"
            ) from exc

    if not isinstance(result, dict):
        raise ValueError("工具参数必须是JSON对象")

    return result


# ---------------------------------------------------------------------------
# 标准化 LLM 返回的 tool_calls
# ---------------------------------------------------------------------------

def normalize_tool_calls(message: dict[str, Any]) -> list[dict[str, Any]]:
    raw_calls = message.get("tool_calls") or []
    normalized: list[dict[str, Any]] = []

    for raw_call in raw_calls:
        function_block = raw_call.get("function")

        if isinstance(function_block, dict):
            name = function_block.get("name")
            raw_arguments = function_block.get("arguments", "{}")
        else:
            name = raw_call.get("name")
            raw_arguments = raw_call.get("arguments", "{}")

        if not isinstance(name, str) or not name:
            raise ValueError(f"工具调用缺少合法名称: {raw_call!r}")

        arguments = parse_arguments(raw_arguments)
        call_id = raw_call.get("id") or f"call_{uuid.uuid4().hex[:16]}"

        normalized.append(
            {
                "id": call_id,
                "type": "function",
                "function": {
                    "name": name,
                    "arguments": json.dumps(
                        arguments,
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ),
                },
                "_parsed_arguments": arguments,
                "_agent_policy_notes": [],
            }
        )

    return normalized


# ---------------------------------------------------------------------------
# 工具执行：查表 → 校验 → 执行 → 统一错误处理
# ---------------------------------------------------------------------------

def execute_tool(
    name: str,
    arguments: dict[str, Any],
    registry: dict[str, ToolRegistration],
) -> dict[str, Any]:
    registration = registry.get(name)

    if registration is None:
        return {
            "ok": False,
            "error": "tool_not_allowed",
            "tool": name,
        }

    try:
        validated = registration.args_model.model_validate(arguments)
        result = registration.handler(validated)

        return {
            "ok": True,
            "tool": name,
            "result": result,
        }

    except ValidationError as exc:
        return {
            "ok": False,
            "error": "invalid_tool_arguments",
            "tool": name,
            "details": exc.errors(
                include_url=False,
                include_input=False,
            ),
        }

    except Exception as exc:
        return {
            "ok": False,
            "error": "tool_execution_failed",
            "tool": name,
            "message": str(exc)[:300],
        }

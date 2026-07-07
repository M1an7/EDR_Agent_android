from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
AUDIT_DIR = PROJECT_ROOT / "logs" / "audit"


class AuditLogger:
    """追加式审计日志，JSONL 格式。"""

    def __init__(self, event_id: str) -> None:
        self.event_id = event_id
        self._start_time = datetime.now(timezone.utc)
        AUDIT_DIR.mkdir(parents=True, exist_ok=True)
        self._path = AUDIT_DIR / f"{self._start_time.strftime('%Y-%m-%d')}.jsonl"

    def log(self, stage: str, data: dict[str, Any]) -> None:
        record = {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "event_id": self.event_id,
            "stage": stage,
            "data": data,
        }
        with self._path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False, sort_keys=True))
            f.write("\n")

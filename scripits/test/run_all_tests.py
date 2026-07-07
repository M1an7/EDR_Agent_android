#!/usr/bin/env python3
"""
EDR Agent 全系统测试脚本
测试: 管道 / Skills / 编排引擎 / 攻击链溯源 / 反馈

用法:
    python scripits/test/run_all_tests.py              # 全量测试
    python scripits/test/run_all_tests.py --quick       # 快速测试（跳过 LLM 重调用）
    python scripits/test/run_all_tests.py --pipeline    # 仅管道
    python scripits/test/run_all_tests.py --skills      # 仅 Skills
    python scripits/test/run_all_tests.py --orchestrate # 仅编排引擎
"""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# 确保项目根目录在 sys.path 中
PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from dotenv import load_dotenv
load_dotenv()

from agent.main import run_pipeline, run_feedback, run_trace
from agent.attack_chain import KILL_CHAIN_ORDER

LOGS_DIR = PROJECT_ROOT / "logs" / "test_runs"


def log_header(title: str) -> None:
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print(f"{'=' * 70}")


def log_result(name: str, passed: bool, detail: str = "") -> None:
    status = "PASS" if passed else "FAIL"
    print(f"  [{status}] {name}")
    if detail:
        print(f"         {detail}")


def run_pipeline_test(event_name: str, event_json: str) -> bool:
    """运行单次管道测试，返回是否成功。"""
    try:
        log_header(f"管道: {event_name}")
        run_pipeline(event_json)
        return True
    except Exception as e:
        print(f"  [ERROR] {e}")
        return False


def test_pipeline() -> dict:
    """管道测试：规则直达 + 自动处置 + LLM 研判 + Skills。"""
    results = {"total": 0, "passed": 0}

    # 1. 高置信度自动处置
    passed = run_pipeline_test(
        "高置信度自动处置",
        json.dumps({
            "event_id": "test-pipe-001",
            "device_id": "pixel-7",
            "timestamp": "2026-07-07T10:00:00Z",
            "source": "EDR",
            "device_context": {"os_version": "Android 14", "is_rooted": True, "network_type": "WIFI"},
            "raw_logs": [
                "CVE-2026-5281 exploited via Mali GPU",
                "su executed by uid 0, inject system_server",
                "C2 beacon to evil.example.com:443 every 30s",
                "d41d8cd98f00b204e9800998ecf8427e APK detected",
            ],
            "app_context": {
                "package_name": "com.malware.c2app", "install_source": "sideload",
                "permissions": ["android.permission.READ_SMS", "android.permission.SEND_SMS", "android.permission.INTERNET"],
            },
            "vulnerability_context": {"cve_ids": ["CVE-2026-5281"], "patch_status": "UNPATCHED"},
        }),
    )
    results["total"] += 1
    if passed:
        results["passed"] += 1

    # 2. Skills Fast 模式 (恶意 APK)
    passed = run_pipeline_test(
        "Skills Fast: 恶意APK分析",
        json.dumps({
            "event_id": "test-pipe-002",
            "device_id": "xiaomi-redmi-01",
            "timestamp": "2026-07-07T10:30:00Z",
            "source": "EDR",
            "raw_logs": [
                "com.suspicious.app installed from sideload",
                "DEX classloader loading unknown.dex",
                "requests android.permission.READ_SMS",
            ],
            "app_context": {
                "package_name": "com.suspicious.app", "install_source": "sideload",
                "permissions": ["android.permission.READ_SMS", "android.permission.INTERNET"],
            },
        }),
    )
    results["total"] += 1
    if passed:
        results["passed"] += 1

    # 3. Skills Deep 模式 (复合攻击)
    os.environ["SKILL_MODE"] = "deep"
    passed = run_pipeline_test(
        "Skills Deep: 复合攻击（3技能并行+汇总）",
        json.dumps({
            "event_id": "test-pipe-003",
            "device_id": "samsung-s21-01",
            "timestamp": "2026-07-07T11:00:00Z",
            "source": "EDR",
            "raw_logs": [
                "com.suspicious.app installed from sideload",
                "C2 beacon to 203.0.113.99:8080 every 30s",
                "su executed, ptrace inject system_server",
            ],
            "app_context": {
                "package_name": "com.suspicious.app", "install_source": "sideload",
                "permissions": ["android.permission.READ_SMS", "android.permission.INTERNET"],
            },
        }),
    )
    os.environ["SKILL_MODE"] = "fast"
    results["total"] += 1
    if passed:
        results["passed"] += 1

    # 4. 规则未命中事件（纯 LLM 研判）
    passed = run_pipeline_test(
        "LLM研判: 新威胁（规则未命中）",
        json.dumps({
            "event_id": "test-pipe-004",
            "device_id": "pixel-7",
            "timestamp": "2026-07-07T11:30:00Z",
            "source": "EDR",
            "raw_logs": [
                "unknown process capturing keystrokes from browser",
                "POST to http://45.33.32.99:8080/collect with credentials",
            ],
        }),
    )
    results["total"] += 1
    if passed:
        results["passed"] += 1

    return results


def test_orchestrator() -> dict:
    """编排引擎测试。"""
    results = {"total": 1, "passed": 0}
    log_header("编排引擎: 攻击图缺口评估")

    try:
        graph_file = PROJECT_ROOT / "data" / "attack_graph" / "default.json"
        if graph_file.exists():
            graph_file.unlink()

        from agent.orchestrator import OrchestrationEngine
        engine = OrchestrationEngine()
        result = engine.run(max_rounds=5, coverage_threshold=0.75, min_marginal_gain=0.15)

        print(f"\n  最终覆盖: {result['completeness']:.0%} ({len(result['final_coverage']['covered'])}/{len(KILL_CHAIN_ORDER)})")
        print(f"  已覆盖: {result['final_coverage']['covered']}")
        print(f"  缺失: {result['final_coverage']['missing']}")
        for r in result["rounds"]:
            s = "hit" if r["success"] else "miss"
            print(f"  [{r['round']}] {s} {r['phase']} ← {r['skill']} (p={r['probability']})")

        # 编排成功条件：覆盖度有提升或正确检测到无缺口
        if result["total_rounds"] > 0:
            results["passed"] = 1
    except Exception as e:
        print(f"  [ERROR] {e}")

    return results


def test_attack_chain() -> dict:
    """攻击链溯源测试。"""
    results = {"total": 1, "passed": 0}
    log_header("攻击链溯源: IOC 跨事件关联")

    try:
        run_trace("evil.example.com", "domain")
        results["passed"] = 1
    except Exception as e:
        print(f"  [ERROR] {e}")

    return results


def test_feedback() -> dict:
    """反馈审视测试。"""
    results = {"total": 1, "passed": 0}
    log_header("反馈机制: 积累区审视")

    try:
        from agent.feedback import FeedbackManager, FeedbackStep
        fm = FeedbackManager()
        acc = fm.get_accumulated()
        pen = fm.get_pending()
        print(f"  积累区: {len(acc)} 条")
        print(f"  待审核: {len(pen)} 条")

        if acc:
            fs = FeedbackStep(fm)
            try:
                fb_result = fs.review_and_precipitate()
                print(f"  沉淀: {fb_result.get('precipitated', 0)} 条")
            finally:
                fs.close()
        results["passed"] = 1
    except Exception as e:
        print(f"  [ERROR] {e}")

    return results


def print_summary(all_results: dict, elapsed: float) -> None:
    """汇总所有测试结果。"""
    total = sum(r["total"] for r in all_results.values())
    passed = sum(r["passed"] for r in all_results.values())

    print(f"\n{'=' * 70}")
    print(f"  测试汇总")
    print(f"{'=' * 70}")
    for name, r in all_results.items():
        status = "PASS" if r["passed"] == r["total"] else "FAIL"
        print(f"  [{status}] {name}: {r['passed']}/{r['total']}")
    print(f"\n  总计: {passed}/{total} 通过")
    print(f"  耗时: {elapsed:.1f}s")
    print(f"{'=' * 70}")


def main() -> None:
    args = set(sys.argv[1:])
    quick = "--quick" in args

    if quick:
        print("快速模式: 跳过管道/Skills测试 (LLM调用耗时)")

    run_all = not any(a in args for a in ["--pipeline", "--skills", "--orchestrate", "--trace", "--feedback"])

    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    # 重定向输出到文件
    log_path = LOGS_DIR / f"test-{timestamp}.log"
    tee_file = open(log_path, "w", encoding="utf-8")

    class Tee:
        def __init__(self, *files):
            self.files = files

        def write(self, data):
            for f in self.files:
                f.write(data)
                f.flush()

        def flush(self):
            for f in self.files:
                f.flush()

    original_stdout = sys.stdout
    sys.stdout = Tee(original_stdout, tee_file)

    try:
        print(f"EDR Agent 全系统测试")
        print(f"时间: {timestamp}")
        print(f"模式: {'快速' if quick else '全量'}")
        start = time.time()

        all_results = {}

        # 管道测试
        if run_all or "--pipeline" in args:
            if quick:
                print("\n[跳过] 管道测试 (--quick)")
            else:
                all_results["管道"] = test_pipeline()

        # Skills 测试
        if run_all or "--skills" in args:
            if quick:
                print("\n[跳过] Skills 测试 (--quick)")
            elif "管道" not in all_results:
                all_results["Skills"] = test_pipeline()

        # 编排引擎
        if run_all or "--orchestrate" in args:
            all_results["编排引擎"] = test_orchestrator()

        # 攻击链溯源
        if run_all or "--trace" in args:
            all_results["攻击链"] = test_attack_chain()

        # 反馈
        if run_all or "--feedback" in args:
            all_results["反馈"] = test_feedback()

        elapsed = time.time() - start
        print_summary(all_results, elapsed)
        print(f"\n日志已保存: {log_path}")

    finally:
        sys.stdout = original_stdout
        tee_file.close()

    # 终端输出路径
    print(f"[日志] {log_path}", file=original_stdout)


if __name__ == "__main__":
    main()

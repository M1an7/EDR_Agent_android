from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from bs4 import BeautifulSoup
from tqdm import tqdm


ROOT = Path(__file__).resolve().parents[2]

RAW_ASB = ROOT / "data" / "raw" / "android_security_bulletin"
RAW_KEV = ROOT / "data" / "raw" / "cisa_kev"
RAW_LOGHUB = ROOT / "data" / "raw" / "loghub"

PROCESSED = ROOT / "data" / "processed"

OUT_ASB = PROCESSED / "android_vulnerabilities.jsonl"
OUT_KEV = PROCESSED / "cisa_kev.jsonl"
OUT_LOGS = PROCESSED / "android_logs.jsonl"


CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# 常见 Android logcat 格式之一：
# 03-17 16:13:38.811  1702  2395 I ActivityManager: Start proc ...
ANDROID_LOG_RE = re.compile(
    r"^(?P<date>\d{2}-\d{2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"(?P<pid>\d+)\s+"
    r"(?P<tid>\d+)\s+"
    r"(?P<level>[VDIWEF])\s+"
    r"(?P<tag>[^:]+):\s?"
    r"(?P<message>.*)$"
)


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True))
            f.write("\n")

    print(f"[write] {path} rows={len(rows)}")


def append_jsonl(path: Path, row: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False, sort_keys=True))
        f.write("\n")


def stable_id(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:24]


def normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def parse_android_security_bulletins() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    files = sorted(RAW_ASB.glob("*.html"))
    print(f"[parse ASB] html files={len(files)}")

    for html_path in tqdm(files, desc="ASB"):
        month = html_path.stem
        html = html_path.read_text(encoding="utf-8", errors="ignore")
        soup = BeautifulSoup(html, "lxml")

        title = normalize_text(soup.get_text(" ", strip=True)[:500])

        # 找所有 table row，尽量从同一行里抽 CVE / severity / component
        for tr in soup.find_all("tr"):
            cells = [normalize_text(td.get_text(" ", strip=True)) for td in tr.find_all(["td", "th"])]
            if not cells:
                continue

            row_text = " | ".join(cells)
            cves = sorted(set(c.upper() for c in CVE_RE.findall(row_text)))

            if not cves:
                continue

            severity = None
            for candidate in ["Critical", "High", "Moderate", "Low"]:
                if re.search(rf"\b{candidate}\b", row_text, re.IGNORECASE):
                    severity = candidate
                    break

            for cve in cves:
                rows.append(
                    {
                        "source": "Android Security Bulletin",
                        "dataset": "android_security_bulletin",
                        "bulletin_month": month,
                        "cve_id": cve,
                        "severity": severity,
                        "raw_row": row_text[:4000],
                        "source_file": str(html_path.relative_to(ROOT)),
                        "doc_title_sample": title,
                    }
                )

    # 去重：同一公告里同一个 CVE 可能重复出现
    dedup: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in rows:
        key = (
            row["dataset"],
            row["bulletin_month"],
            row["cve_id"],
        )
        dedup[key] = row

    return list(dedup.values())


def parse_cisa_kev() -> list[dict[str, Any]]:
    path = RAW_KEV / "known_exploited_vulnerabilities.json"
    data = json.loads(path.read_text(encoding="utf-8"))

    vulnerabilities = data.get("vulnerabilities", [])
    rows: list[dict[str, Any]] = []

    for item in vulnerabilities:
        cve_id = item.get("cveID")

        if not cve_id:
            continue

        rows.append(
            {
                "source": "CISA KEV",
                "dataset": "cisa_kev",
                "cve_id": cve_id,
                "vendor_project": item.get("vendorProject"),
                "product": item.get("product"),
                "vulnerability_name": item.get("vulnerabilityName"),
                "date_added": item.get("dateAdded"),
                "short_description": item.get("shortDescription"),
                "required_action": item.get("requiredAction"),
                "due_date": item.get("dueDate"),
                "known_ransomware_campaign_use": item.get("knownRansomwareCampaignUse"),
                "notes": item.get("notes"),
            }
        )

    return rows


def find_android_log_files() -> list[Path]:
    search_roots = [
        RAW_LOGHUB / "Android_v1",
        RAW_LOGHUB,
    ]

    candidates: list[Path] = []

    for search_root in search_roots:
        if not search_root.exists():
            continue

        for path in search_root.rglob("*"):
            if not path.is_file():
                continue

            if path.stat().st_size <= 0:
                continue

            suffix = path.suffix.lower()

            if suffix in {".zip", ".gz", ".tar", ".tgz", ".7z"}:
                continue

            # LogHub 解压后有些文件可能没有 .log 后缀，所以不能只靠后缀判断
            name = path.name.lower()
            path_text = str(path).lower()

            likely_android_log = (
                suffix in {".log", ".txt"}
                or "android" in name
                or "android" in path_text
            )

            if not likely_android_log:
                continue

            candidates.append(path)

    # 去重并排序
    candidates = sorted(set(candidates))

    if candidates:
        return candidates

    # 如果上面的启发式没找到，就列出实际解压内容，方便定位
    print("[debug] RAW_LOGHUB =", RAW_LOGHUB)
    print("[debug] existing files under RAW_LOGHUB:")
    if RAW_LOGHUB.exists():
        for path in list(RAW_LOGHUB.rglob("*"))[:100]:
            print(" -", path)

    return []


def parse_android_log_line(line: str) -> dict[str, Any]:
    raw = line.rstrip("\n")
    match = ANDROID_LOG_RE.match(raw)

    if not match:
        return {
            "parsed": False,
            "raw": raw,
        }

    d = match.groupdict()

    return {
        "parsed": True,
        "date": d["date"],
        "time": d["time"],
        "pid": int(d["pid"]),
        "tid": int(d["tid"]),
        "level": d["level"],
        "tag": d["tag"].strip(),
        "message": d["message"],
        "raw": raw,
    }


def parse_loghub_android(max_lines: int | None = None) -> int:
    files = find_android_log_files()

    if not files:
        raise RuntimeError("没有找到 LogHub Android_v1 解压后的日志文件")

    print("[LogHub files]")
    for f in files[:20]:
        print(" -", f.relative_to(ROOT))

    OUT_LOGS.parent.mkdir(parents=True, exist_ok=True)
    OUT_LOGS.write_text("", encoding="utf-8")

    count = 0

    for log_file in files:
        print(f"[parse log] {log_file.relative_to(ROOT)}")

        with log_file.open("r", encoding="utf-8", errors="ignore") as f:
            for line_no, line in enumerate(f, start=1):
                if not line.strip():
                    continue

                parsed = parse_android_log_line(line)
                raw = parsed.get("raw", "")

                row = {
                    "source": "LogHub",
                    "dataset": "Android_v1",
                    "source_file": str(log_file.relative_to(ROOT)),
                    "line_no": line_no,
                    "event_id": stable_id(f"{log_file}:{line_no}:{raw}"),
                    **parsed,
                }

                append_jsonl(OUT_LOGS, row)
                count += 1

                if max_lines is not None and count >= max_lines:
                    print(f"[limit reached] max_lines={max_lines}")
                    print(f"[write] {OUT_LOGS} rows={count}")
                    return count

    print(f"[write] {OUT_LOGS} rows={count}")
    return count


def build_joined_android_vuln(asb_rows: list[dict[str, Any]], kev_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    kev_by_cve = {row["cve_id"].upper(): row for row in kev_rows}

    joined: list[dict[str, Any]] = []

    for row in asb_rows:
        cve = row["cve_id"].upper()
        kev = kev_by_cve.get(cve)

        joined.append(
            {
                **row,
                "in_cisa_kev": kev is not None,
                "kev": kev,
            }
        )

    # 额外保留 KEV 里与 Android 关键词相关的项，即使没在 ASB 解析结果里匹配上
    existing = {row["cve_id"].upper() for row in joined}

    for kev in kev_rows:
        cve = kev["cve_id"].upper()
        text = json.dumps(kev, ensure_ascii=False).lower()

        if cve in existing:
            continue

        if "android" in text or "google" in text or "pixel" in text:
            joined.append(
                {
                    "source": "CISA KEV",
                    "dataset": "cisa_kev_android_keyword",
                    "bulletin_month": None,
                    "cve_id": cve,
                    "severity": None,
                    "raw_row": None,
                    "source_file": "data/raw/cisa_kev/known_exploited_vulnerabilities.json",
                    "in_cisa_kev": True,
                    "kev": kev,
                }
            )

    return joined


def main() -> None:
    PROCESSED.mkdir(parents=True, exist_ok=True)

    # print("\n== 1. Parse Android Security Bulletin ==")
    # asb_rows = parse_android_security_bulletins()
    # write_jsonl(OUT_ASB, asb_rows)

    print("\n== 2. Parse CISA KEV ==")
    kev_rows = parse_cisa_kev()
    write_jsonl(OUT_KEV, kev_rows)

    # print("\n== 3. Build joined vulnerability view ==")
    # joined = build_joined_android_vuln(asb_rows, kev_rows)
    # joined_path = PROCESSED / "android_vulnerabilities_joined.jsonl"
    # write_jsonl(joined_path, joined)

    # print("\n== 4. Parse LogHub Android_v1 logs ==")
    # # 第一轮先限制 20000 行，确认 Agent 检索链路。
    # # 稳定后改为 max_lines=None 处理全量 Android_v1。
    # parse_loghub_android(max_lines=20_000)

    print("\n[all done]")


if __name__ == "__main__":
    main()

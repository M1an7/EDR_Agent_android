from __future__ import annotations

import re
import zipfile
from pathlib import Path
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from tqdm import tqdm


ROOT = Path(__file__).resolve().parents[2]

RAW_ASB = ROOT / "data" / "raw" / "android_security_bulletin"
RAW_KEV = ROOT / "data" / "raw" / "cisa_kev"
RAW_LOGHUB = ROOT / "data" / "raw" / "loghub"

ASB_INDEX_URL = "https://source.android.com/docs/security/bulletin?hl=zh-cn"
CISA_KEV_JSON_URL = (
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/"
    "known_exploited_vulnerabilities.json"
)

# 先下载 Android_v1，体积小，适合第一轮验证
LOGHUB_ANDROID_V1_URL = (
    "https://zenodo.org/records/8196385/files/Android_v1.zip?download=1"
)

# 第二阶段再打开这个
LOGHUB_ANDROID_V2_URL = (
    "https://zenodo.org/records/8196385/files/Android_v2.zip?download=1"
)


def ensure_dirs() -> None:
    for path in [RAW_ASB, RAW_KEV, RAW_LOGHUB]:
        path.mkdir(parents=True, exist_ok=True)


def download_file(url: str, output_path: Path) -> None:
    print(f"[download] {url}")
    print(f"[to]       {output_path}")

    with requests.get(url, stream=True, timeout=120) as response:
        response.raise_for_status()
        total = int(response.headers.get("content-length", "0") or 0)

        with output_path.open("wb") as f:
            with tqdm(
                total=total,
                unit="B",
                unit_scale=True,
                desc=output_path.name,
            ) as bar:
                for chunk in response.iter_content(chunk_size=1024 * 1024):
                    if chunk:
                        f.write(chunk)
                        bar.update(len(chunk))


def fetch_cisa_kev() -> None:
    output = RAW_KEV / "known_exploited_vulnerabilities.json"
    download_file(CISA_KEV_JSON_URL, output)


def fetch_loghub_android_v1() -> None:
    zip_path = RAW_LOGHUB / "Android_v1.zip"
    extract_dir = RAW_LOGHUB / "Android_v1"

    if not zip_path.exists():
        download_file(LOGHUB_ANDROID_V1_URL, zip_path)
    else:
        print(f"[skip] {zip_path} already exists")

    extract_dir.mkdir(parents=True, exist_ok=True)

    print(f"[extract] {zip_path} -> {extract_dir}")
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(extract_dir)

    print("[done] LogHub Android_v1 extracted")


def find_android_bulletin_links(index_html: str) -> list[str]:
    soup = BeautifulSoup(index_html, "lxml")
    links: set[str] = set()

    for a in soup.find_all("a", href=True):
        href = a["href"]

        # 匹配：
        # /docs/security/bulletin/2026/2026-06-01
        # https://source.android.com/docs/security/bulletin/2026/2026-06-01
        if re.search(r"/docs/security/bulletin/\d{4}/\d{4}-\d{2}-01", href):
            full_url = urljoin(ASB_INDEX_URL, href)
            links.add(full_url)

    return sorted(links)


def fetch_android_security_bulletins(max_pages: int | None = None) -> None:
    print(f"[fetch index] {ASB_INDEX_URL}")
    response = requests.get(ASB_INDEX_URL, timeout=20)
    response.raise_for_status()
    input("debug")
    index_path = RAW_ASB / "index.html"
    index_path.write_text(response.text, encoding="utf-8")

    links = find_android_bulletin_links(response.text)

    if not links:
        raise RuntimeError("没有在 Android Security Bulletin 首页解析到月度公告链接")

    # 新的在后面还是前面不稳定，这里统一按 URL 排序后反转，优先下载新的
    links = sorted(links, reverse=True)

    if max_pages is not None:
        links = links[:max_pages]

    print(f"[found] {len(links)} bulletin pages")

    for url in links:
        month = url.rstrip("/").split("/")[-1]
        output = RAW_ASB / f"{month}.html"

        if output.exists():
            print(f"[skip] {output.name}")
            continue

        print(f"[download bulletin] {month}")
        r = requests.get(url, timeout=60)
        r.raise_for_status()
        output.write_text(r.text, encoding="utf-8")


def main() -> None:
    ensure_dirs()

    # print("\n== 1. CISA KEV ==")
    # fetch_cisa_kev()

    # print("\n== 2. LogHub Android_v1 ==")
    # fetch_loghub_android_v1()

    print("\n== 3. Android Security Bulletins ==")
    # 第一轮先取最近 36 个月，够你做验证。
    # 全量可以把 max_pages=None。
    fetch_android_security_bulletins(max_pages=36)

    print("\n[all done]")


if __name__ == "__main__":
    main()

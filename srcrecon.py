"""srcrecon —— 授权范围内的资产侦查流水线（只做被动/轻量探测，不打漏洞）。

用法：
  python srcrecon.py example.com
  python srcrecon.py example.com --out report.md --json out.json
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import re
import socket
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

UA = {"User-Agent": "Mozilla/5.0 (compatible; srcrecon/1.0)"}
COMMON_SUBS = ["www", "api", "admin", "test", "dev", "staging", "m", "app", "static", "cdn"]
COMMON_PATHS = [
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/admin", "/login", "/api", "/swagger-ui.html", "/actuator",
    "/.git/config", "/backup.zip", "/.env",
]
TIMEOUT = 6


def fetch(url: str, method: str = "GET", data: bytes | None = None):
    req = urllib.request.Request(url, headers=UA, method=method, data=data)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as resp:
        body = b""
        if method == "GET":
            body = resp.read(200_000)
        return resp.status, dict(resp.headers), body


def resolve(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


def crt_subs(domain: str) -> list[str]:
    try:
        status, _, body = fetch(f"https://crt.sh/?q=%25.{domain}&output=json")
        if status != 200:
            return []
        rows = json.loads(body.decode("utf-8", "ignore"))
        names = set()
        for row in rows:
            for name in str(row.get("name_value", "")).splitlines():
                name = name.strip().lower().lstrip("*.")
                if name.endswith(domain) and " " not in name:
                    names.add(name)
        return sorted(names)
    except Exception:
        return []


def brute_subs(domain: str) -> list[str]:
    return [f"{sub}.{domain}" for sub in COMMON_SUBS if resolve(f"{sub}.{domain}")]


def probe(host: str) -> dict | None:
    for scheme in ("https", "http"):
        try:
            status, headers, body = fetch(f"{scheme}://{host}/")
            title = ""
            m = re.search(rb"<title[^>]*>(.*?)</title>", body, re.I | re.S)
            if m:
                title = m.group(1).decode("utf-8", "ignore").strip()[:80]
            return {
                "host": host,
                "url": f"{scheme}://{host}/",
                "status": status,
                "title": title,
                "server": headers.get("Server", ""),
                "powered_by": headers.get("X-Powered-By", ""),
                "length": len(body),
            }
        except Exception:
            continue
    return None


def check_paths(base: str) -> list[dict]:
    out = []
    for path in COMMON_PATHS:
        try:
            status, _, body = fetch(base.rstrip("/") + path)
            out.append({"path": path, "status": status, "bytes": len(body)})
        except urllib.error.HTTPError as exc:
            out.append({"path": path, "status": exc.code, "bytes": 0})
        except Exception:
            continue
    return out


def js_endpoints(base: str) -> list[str]:
    try:
        _, _, body = fetch(base.rstrip("/") + "/")
    except Exception:
        return []
    text = body.decode("utf-8", "ignore")
    hits = set(re.findall(r"""["'](/[a-zA-Z0-9_\-/]*(?:api|v1|v2|graphql)[a-zA-Z0-9_\-/]*)["']""", text))
    return sorted(hits)[:40]


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("domain")
    ap.add_argument("--out", default="")
    ap.add_argument("--json", default="")
    args = ap.parse_args(argv[1:])

    domain = args.domain.strip().lower().replace("http://", "").replace("https://", "").split("/")[0]
    started = datetime.now(timezone.utc)
    print(f"[*] 目标 {domain}  开始 {started:%H:%M:%S} UTC", file=sys.stderr)

    subs = sorted(set(crt_subs(domain)) | set(brute_subs(domain)) | {domain})
    print(f"[*] 子域 {len(subs)} 个", file=sys.stderr)

    with cf.ThreadPoolExecutor(max_workers=8) as pool:
        alive = [r for r in pool.map(probe, subs) if r]
    print(f"[*] 存活 {len(alive)} 个", file=sys.stderr)

    details = []
    for host in alive[:6]:
        details.append({
            "host": host,
            "paths": check_paths(host["url"]),
            "endpoints": js_endpoints(host["url"]),
        })

    lines = [f"# 资产侦查报告 · {domain}\n"]
    lines.append(f"- 生成时间：{started:%Y-%m-%d %H:%M} UTC")
    lines.append(f"- 子域 {len(subs)} 个，存活 {len(alive)} 个\n")
    lines.append("## 存活资产\n")
    lines.append("| 主机 | URL | 状态 | 标题 | Server |")
    lines.append("| --- | --- | ---: | --- | --- |")
    for a in alive:
        lines.append(f"| {a['host']} | {a['url']} | {a['status']} | {a['title'][:40]} | {a['server'][:30]} |")

    for d in details:
        lines.append(f"\n## {d['host']['host']}\n")
        risky = [p for p in d["paths"] if p["status"] in (200, 401, 403, 500)]
        if risky:
            lines.append("| 路径 | 状态 | 字节 |")
            lines.append("| --- | ---: | ---: |")
            for p in risky:
                lines.append(f"| {p['path']} | {p['status']} | {p['bytes']} |")
        if d["endpoints"]:
            lines.append("\nJS 里出现的接口：")
            for e in d["endpoints"][:15]:
                lines.append(f"- `{e}`")

    lines.append("\n---\n")
    lines.append("> 仅做被动信息收集与轻量探测，未发送任何攻击载荷。请在授权范围内使用。")

    report = "\n".join(lines) + "\n"
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(report)
        print(f"[+] 报告：{args.out}", file=sys.stderr)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"domain": domain, "subdomains": subs, "alive": alive, "details": details}, fh, ensure_ascii=False, indent=2)
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

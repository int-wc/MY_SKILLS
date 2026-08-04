#!/usr/bin/env python3
"""
攻击面前匹配工具
================================================================
读取 Phase2 分析输出（含 `- /xxx POST business_attr=...` 原语判定行），
对照 references/attack_surfaces.json 按 signals + business_attr 匹配攻击面，
输出 attack_hints 供 Phase3 注入（程序化部分；agent 再对照攻击面库补充未命中）。

用法：
  # 从文件读 Phase2 分析文本
  python3 attack_surface_match.py -a phase2_analysis.txt -o attack_hints.json
  # 从 stdin
  cat phase2.txt | python3 attack_surface_match.py --surfaces references/attack_surfaces.json -o hints.json

输出 JSON:
  {"hints":[{"endpoint":"/api/translateUrl","method":"POST","business_attr":"transfer",
             "surfaces":[{"id":"sf_url_fetch_echo","name":"数据型URL拉取(网页/文档/截图)",
                          "base_primitives":["SSRF(回显)",...],"matched_signals":["url="]}]}],
   "unmatched":[{"endpoint":"/x","method":"GET"}]}
"""
import sys
import json
import re
import argparse
from pathlib import Path

# Phase2 Step5 原语判定行格式：- /xxx POST business_attr=read_file attr_target=... params=... risk=...
EP_LINE = re.compile(
    r"-\s+(\S+)\s+(GET|POST|PUT|DELETE|PATCH|HEAD)\s+business_attr=(\w+)",
    re.I,
)
PARAMS_RE = re.compile(r"params=(\{[^}]*\})", re.I)


def parse_endpoints(text: str) -> list[dict]:
    """从分析文本提取端点（含原语判定行）。"""
    eps = []
    for line in text.splitlines():
        m = EP_LINE.search(line)
        if not m:
            continue
        endpoint, method, attr = m.group(1), m.group(2), m.group(3)
        pm = PARAMS_RE.search(line)
        params = ""
        if pm:
            try:
                params = json.loads(pm.group(1))
                if isinstance(params, dict):
                    params = list(params.keys())
                elif isinstance(params, list):
                    params = [str(x) for x in params]
                else:
                    params = str(params)
            except Exception:
                params = pm.group(1)
        if not isinstance(params, list):
            params = [str(params)] if params else []
        eps.append({"endpoint": endpoint, "method": method, "business_attr": attr, "params": params})
    return eps


def load_surfaces(path: str) -> list[dict]:
    p = Path(path)
    if not p.exists():
        sys.stderr.write(f"[!] 攻击面库不存在: {p}\n")
        return []
    return json.load(open(p, encoding="utf-8")).get("surfaces", [])


def match_surfaces(ep: dict, surfaces: list[dict]) -> list[dict]:
    hay = " ".join([ep["endpoint"], ep["business_attr"], " ".join(map(str, ep["params"]))]).lower()
    hits = []
    for surf in surfaces:
        sigs = [s for s in surf.get("signals", []) if str(s).lower() in hay]
        prim = 2 if ep["business_attr"] in surf.get("primitives", []) else 0
        score = len(sigs) + prim
        if score > 0:
            hits.append({
                "id": surf["id"],
                "name": surf.get("name", ""),
                "base_primitives": surf.get("base_primitives", []),
                "risk": surf.get("risk", ""),
                "matched_signals": sigs,
                "primitive_hit": bool(prim),
            })
    hits.sort(key=lambda h: (h["primitive_hit"], len(h["matched_signals"])), reverse=True)
    return hits


def main():
    ap = argparse.ArgumentParser(description="攻击面前匹配")
    ap.add_argument("-a", "--analyses", help="Phase2 分析文本文件（默认 stdin）")
    ap.add_argument("-s", "--surfaces", default=None, help="攻击面库 JSON 路径")
    ap.add_argument("-o", "--output", help="输出 hints JSON 文件（默认 stdout）")
    args = ap.parse_args()

    # 默认攻击面库：脚本同级的 ../references/attack_surfaces.json
    if not args.surfaces:
        args.surfaces = str(Path(__file__).resolve().parent.parent / "references" / "attack_surfaces.json")

    text = open(args.analyses, encoding="utf-8").read() if args.analyses else sys.stdin.read()
    surfaces = load_surfaces(args.surfaces)
    eps = parse_endpoints(text)

    hints, unmatched = [], []
    for ep in eps:
        matched = match_surfaces(ep, surfaces)
        item = {"endpoint": ep["endpoint"], "method": ep["method"], "business_attr": ep["business_attr"]}
        if matched:
            item["surfaces"] = matched
            hints.append(item)
        else:
            item["surfaces"] = []
            hints.append(item)
            unmatched.append(item)

    out = {"total_endpoints": len(eps), "matched_count": len(hints) - len(unmatched), "hints": hints}
    js = json.dumps(out, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(js, encoding="utf-8")
        print(f"[✓] {len(hints)} 端点前匹配完成（命中 {out['matched_count']}）-> {args.output}")
    else:
        print(js)


if __name__ == "__main__":
    main()
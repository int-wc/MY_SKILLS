#!/usr/bin/env python3
"""
业务原语链联动推理工具
================================================================
读取 Phase2 分析文本（含 `- /xxx POST business_attr=...` 原语判定行），
对照 references/primitive-chains.json，检查每个链模板的组成原语在目标
端点清单中是否齐备，输出候选原语链（供 Phase4 验证实际可串联性）。

核心思想：单个业务原语(能力点)单独可能无法构成有效危害；若链模板的
组成原语在目标上都存在对应端点，则存在"业务信任串联→有效危害"的可能，
交给 Phase4 用只读方式验证组合。

用法：
  python3 chain_linking.py -e phase2_analysis.txt -o candidates.json
  cat phase2.txt | python3 chain_linking.py --chains references/primitive-chains.json

输出 JSON:
  {"total_endpoints": N, "candidates": [
    {"chain_id":"ch_ssrf_to_auth","name":"SSRF→内部认证绕过","primitives":[...],
     "gain":"...","logic":"...",
     "matched_endpoints":{"transfer":["/fetch_url"],"auth":["/login"]}}]}
"""
import sys
import json
import re
import argparse
from pathlib import Path

# Phase2 Step5 原语判定行格式：- /xxx POST business_attr=transfer ...
EP_LINE = re.compile(
    r"-\s+(\S+)\s+(GET|POST|PUT|DELETE|PATCH|HEAD)\s+business_attr=(\w+)",
    re.I,
)


def parse_endpoints(text: str) -> list[dict]:
    eps = []
    for line in text.splitlines():
        m = EP_LINE.search(line)
        if not m:
            continue
        eps.append({"endpoint": m.group(1), "method": m.group(2), "business_attr": m.group(3)})
    return eps


def load_chains(path: str) -> list[dict]:
    p = Path(path)
    if not p.exists():
        sys.stderr.write(f"[!] 原语链库不存在: {p}\n")
        return []
    return json.load(open(p, encoding="utf-8")).get("chains", [])


def link(eps: list[dict], chains: list[dict]) -> list[dict]:
    # attr -> 端点去重列表
    attr2eps: dict[str, list[str]] = {}
    for ep in eps:
        a = ep["business_attr"]
        if a not in attr2eps:
            attr2eps[a] = []
        if ep["endpoint"] not in attr2eps[a]:
            attr2eps[a].append(ep["endpoint"])

    available = set(attr2eps.keys())
    candidates = []
    for ch in chains:
        need = set(ch.get("primitives", []))
        if not need.issubset(available):
            continue
        matched = {a: attr2eps[a][:3] for a in sorted(need)}
        candidates.append({
            "chain_id": ch["id"],
            "name": ch.get("name", ""),
            "primitives": sorted(need),
            "logic": ch.get("logic", ""),
            "gain": ch.get("gain", ""),
            "matched_endpoints": matched,
        })
    return candidates


def main():
    ap = argparse.ArgumentParser(description="业务原语链联动推理")
    ap.add_argument("-e", "--endpoints", help="Phase2 分析文本文件（默认 stdin）")
    ap.add_argument("-c", "--chains", default=None, help="原语链库 JSON 路径")
    ap.add_argument("-o", "--output", help="输出 candidates JSON 文件（默认 stdout）")
    args = ap.parse_args()

    if not args.chains:
        args.chains = str(Path(__file__).resolve().parent.parent / "references" / "primitive-chains.json")

    text = open(args.endpoints, encoding="utf-8").read() if args.endpoints else sys.stdin.read()
    eps = parse_endpoints(text)
    chains = load_chains(args.chains)
    candidates = link(eps, chains)

    out = {"total_endpoints": len(eps), "candidates": candidates}
    js = json.dumps(out, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(js, encoding="utf-8")
        print(f"[✓] 原语链联动推理完成：{len(candidates)}/{len(chains)} 条链模板在目标上原语齐备 -> {args.output}")
    else:
        print(js)


if __name__ == "__main__":
    main()
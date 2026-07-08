#!/usr/bin/env python3
"""
merge_assets.py — 程序化合并 asset_test_status.json + asset_findings.json

用法:
  # 合并状态文件
  python3 merge_assets.py status <tracker_path> --dim-data <dim_data.json> [--asset-info <info.json>]
  # 合并发现文件
  python3 merge_assets.py findings <findings_path> --new-findings <new_findings.json>

流程:
  1. 读取已有文件（不存在则初始化）
  2. 合并新数据（保留旧记录，只追加和更新）
  3. 写回
"""
import sys
import os
import json
from datetime import date

def merge_status(tracker_path, dim_data=None, asset_info=None):
    """合并 asset_test_status.json"""
    # 初始化
    if os.path.exists(tracker_path):
        try:
            with open(tracker_path, 'r') as f:
                data = json.load(f)
        except:
            data = {"assets": {}}
    else:
        data = {"assets": {}}

    assets = data.setdefault("assets", {})
    today = str(date.today())
    changed = False

    # 合并 dimTracker 数据
    if dim_data:
        for url, info in dim_data.items():
            if not url or url.startswith('{'):
                continue
            dims = info.get('dims', {})
            completed_dims = [d for d, v in dims.items() if v.get('status') == 'done']

            if url in assets:
                # 更新已有资产：合并 phases_tested
                existing_phases = set(assets[url].get('phases_tested', []))
                new_phases = [p for p in completed_dims if p not in existing_phases]
                if new_phases:
                    assets[url]['phases_tested'] = list(existing_phases.union(completed_dims))
                    assets[url]['last_tested'] = today
                    changed = True
            else:
                # 追加新资产
                assets[url] = {
                    "status": "还未测试完毕",
                    "phases_tested": completed_dims,
                    "last_tested": today,
                    "reason": f"已完成维度: {', '.join(completed_dims) if completed_dims else '暂无'}"
                }
                changed = True

    # 补充资产信息（title, ip, port等）
    if asset_info:
        for item in asset_info:
            url = item.get('url')
            if url and url in assets:
                for k in ['title', 'ip', 'port']:
                    if item.get(k):
                        assets[url][k] = item[k]

    with open(tracker_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    return {"assets_count": len(assets), "changed": changed}

def merge_findings(findings_path, new_findings=None):
    """合并 asset_findings.json"""
    if os.path.exists(findings_path):
        try:
            with open(findings_path, 'r') as f:
                data = json.load(f)
        except:
            data = {"findings": []}
    else:
        data = {"findings": []}

    existing = data.get("findings", [])
    existing_endpoints = {f.get('endpoint', ''): i for i, f in enumerate(existing)}

    added = 0
    updated = 0

    if new_findings:
        for f_item in new_findings:
            ep = f_item.get('endpoint', '')
            if not ep:
                continue
            if ep in existing_endpoints:
                # 更新现有记录的 status
                idx = existing_endpoints[ep]
                if f_item.get('status') and existing[idx].get('status') != f_item['status']:
                    existing[idx]['status'] = f_item['status']
                    existing[idx]['phase_discovered'] = f_item.get('phase_discovered', 'phase3')
                    if f_item.get('curl_command'):
                        existing[idx]['curl_command'] = f_item['curl_command']
                    updated += 1
            else:
                existing.append({
                    "title": f_item.get('title', ''),
                    "type": f_item.get('type', ''),
                    "severity": f_item.get('severity', ''),
                    "target": f_item.get('target', ''),
                    "endpoint": ep,
                    "status": f_item.get('status', 'unverified'),
                    "phase_discovered": f_item.get('phase_discovered', 'phase3'),
                    "curl_command": f_item.get('curl_command', ''),
                })
                added += 1

    data["findings"] = existing

    with open(findings_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    return {"total": len(existing), "added": added, "updated": updated}

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("用法: merge_assets.py status|findings <path> [options]", file=sys.stderr)
        sys.exit(1)

    mode = sys.argv[1]
    path = sys.argv[2]

    if mode == 'status':
        import argparse
        parser = argparse.ArgumentParser()
        parser.add_argument('--dim-data', default='', help='dimTracker JSON数据')
        parser.add_argument('--asset-info', default='', help='资产信息JSON数组')
        args, _ = parser.parse_known_args()

        dim_data = json.loads(args.dim_data) if args.dim_data else None
        asset_info = json.loads(args.asset_info) if args.asset_info else None
        result = merge_status(path, dim_data, asset_info)

    elif mode == 'findings':
        import argparse
        parser = argparse.ArgumentParser()
        parser.add_argument('--new-findings', default='', help='新发现JSON数组')
        args, _ = parser.parse_known_args()

        new_findings = json.loads(args.new_findings) if args.new_findings else []
        result = merge_findings(path, new_findings)

    else:
        print(f"未知模式: {mode}", file=sys.stderr)
        sys.exit(1)

    print(json.dumps(result, ensure_ascii=False, indent=2))

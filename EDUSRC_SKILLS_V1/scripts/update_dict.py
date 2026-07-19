#!/usr/bin/env python3
"""
update_dict.py — 更新API模式字典本（去重+LRU裁剪）

用法:
  # 追加新发现
  python3 update_dict.py <dict_path> --add <findings.json>
  python3 update_dict.py <dict_path> --prefixes '["/api/v3/"]' --segments '["graphql"]' --endpoints '["/api/v3/user"]'

流程:
  1. 读取现有字典
  2. 合并新模式（去重）
  3. LRU裁剪：common_endpoints 上限1000条，api_prefixes 上限200条
  4. 写回
"""
import sys
import os
import json
from datetime import date

MAX_ENDPOINTS = 1000
MAX_PREFIXES = 200
MAX_SEGMENTS = 200

def load_dict(path):
    if os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            pass
    return {
        "updated": str(date.today()),
        "description": "SRC/ZC 通用API模式字典 — 每次运行自动积累新发现的模式",
        "api_prefixes": {},
        "path_segments": [],
        "common_endpoints": [],
        "framework_patterns": {},
    }

def update_dict(dict_path, new_prefixes=None, new_segments=None, new_endpoints=None, add_file=None):
    """更新字典本"""
    d = load_dict(dict_path)
    today = str(date.today())

    # 如果指定了 add_file，从文件读取
    if add_file and os.path.exists(add_file):
        with open(add_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if 'extracted_patterns' in data:
                ep = data['extracted_patterns']
                new_prefixes = ep.get('new_prefixes', new_prefixes or [])
                new_segments = ep.get('new_segments', new_segments or [])
            if 'new_endpoints' in data:
                new_endpoints = data.get('new_endpoints', new_endpoints or [])
            if 'findings' in data:
                for f_item in data['findings']:
                    if f_item.get('status_code') == 200 and f_item.get('endpoint'):
                        new_endpoints = (new_endpoints or []) + [f_item['endpoint']]

    changed = False

    # 1. 合并 api_prefixes（去重+计数）
    if new_prefixes:
        for p in new_prefixes:
            p = p.strip()
            if not p:
                continue
            if p in d.get('api_prefixes', {}):
                d['api_prefixes'][p]['count'] = d['api_prefixes'][p].get('count', 1) + 1
                d['api_prefixes'][p]['last_seen'] = today
            else:
                if 'api_prefixes' not in d:
                    d['api_prefixes'] = {}
                d['api_prefixes'][p] = {"count": 1, "first_seen": today, "last_seen": today}
                changed = True

    # 2. 合并 path_segments（去重）
    if new_segments:
        existing = set(d.get('path_segments', []))
        added = False
        for s in new_segments:
            s = s.strip()
            if s and s not in existing:
                d.setdefault('path_segments', []).append(s)
                existing.add(s)
                added = True
        changed = changed or added

    # 3. 合并 common_endpoints（去重）
    if new_endpoints:
        existing = set(d.get('common_endpoints', []))
        added = False
        for ep in new_endpoints:
            ep = ep.strip()
            if ep and ep not in existing:
                d.setdefault('common_endpoints', []).append(ep)
                existing.add(ep)
                added = True
        changed = changed or added

    # === P0: LRU裁剪 ===
    # common_endpoints 上限 MAX_ENDPOINTS
    if len(d.get('common_endpoints', [])) > MAX_ENDPOINTS:
        d['common_endpoints'] = d['common_endpoints'][-MAX_ENDPOINTS:]
        changed = True

    # api_prefixes 上限 MAX_PREFIXES（按 last_seen 排序淘汰最早）
    if len(d.get('api_prefixes', {})) > MAX_PREFIXES:
        sorted_prefixes = sorted(d['api_prefixes'].items(), key=lambda x: x[1].get('last_seen', ''))
        for p, _ in sorted_prefixes[:len(sorted_prefixes) - MAX_PREFIXES]:
            del d['api_prefixes'][p]
        changed = True

    # path_segments 上限 MAX_SEGMENTS
    if len(d.get('path_segments', [])) > MAX_SEGMENTS:
        d['path_segments'] = d['path_segments'][-MAX_SEGMENTS:]
        changed = True

    # 更新日期
    d['updated'] = today

    # 写回
    with open(dict_path, 'w', encoding='utf-8') as f:
        json.dump(d, f, ensure_ascii=False, indent=2)

    stats = {
        "api_prefixes": len(d.get('api_prefixes', {})),
        "path_segments": len(d.get('path_segments', [])),
        "common_endpoints": len(d.get('common_endpoints', [])),
        "changed": changed,
    }
    return stats

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='更新API模式字典本')
    parser.add_argument('dict_path', help='api_patterns.json 路径')
    parser.add_argument('--prefixes', default='', help='新API前缀JSON数组')
    parser.add_argument('--segments', default='', help='新路径段JSON数组')
    parser.add_argument('--endpoints', default='', help='新端点JSON数组')
    parser.add_argument('--add', default='', help='从smart_fuzz的输出JSON文件导入')
    args = parser.parse_args()

    prefixes = json.loads(args.prefixes) if args.prefixes else None
    segments = json.loads(args.segments) if args.segments else None
    endpoints = json.loads(args.endpoints) if args.endpoints else None

    stats = update_dict(args.dict_path, prefixes, segments, endpoints, args.add)
    print(json.dumps(stats, ensure_ascii=False, indent=2))

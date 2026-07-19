#!/usr/bin/env python3
"""
smart_fuzz.py — 基于系统特征的智能路径枚举

用法:
  python3 smart_fuzz.py <target_url> --dict <api_patterns.json> --output <results.json>
                        [--ua "UA"] [--interface iface] [--framework "框架名"]

流程:
  1. 读取字典本的 framework_patterns、api_prefixes、path_segments、common_endpoints
  2. 根据框架名匹配框架特有路径
  3. 前缀+路径段笛卡尔积组合
  4. curl 探测所有组合
  5. 输出 200/401/403 的发现 + 新提取的模式
"""
import sys
import os
import json
import subprocess
import urllib.parse
import time

def run(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.returncode
    except:
        return "", -1

def smart_fuzz(target_url, dict_path, output_path, ua='', iface='', framework='', api_prefixes_from_js=''):
    """智能fuzz主流程"""
    curl_base = 'curl -sL --max-time 8 --connect-timeout 5 -o /dev/null -w "%{http_code}"'
    if ua:
        curl_base += f" -H 'User-Agent: {ua}'"
    if iface:
        curl_base += f" --interface {iface}"

    # Step 1: 读取字典
    api_patterns = {"framework_patterns": {}, "api_prefixes": {}, "path_segments": [], "common_endpoints": []}
    if os.path.exists(dict_path):
        try:
            with open(dict_path, 'r') as f:
                api_patterns = json.load(f)
        except:
            pass

    base_url = target_url.rstrip('/')

    # Step 2: 生成探测路径列表
    paths_to_test = set()

    # 2a. 通用端点
    for ep in api_patterns.get('common_endpoints', []):
        if ep.startswith('/'):
            paths_to_test.add(ep)

    # 2b. 框架特有路径
    if framework:
        for fw_name in [framework, '通用']:
            for path in api_patterns.get('framework_patterns', {}).get(fw_name, []):
                if path.startswith('/'):
                    paths_to_test.add(path)

    # 如果没指定框架但字典里有，就全加
    if not framework:
        for fw_name, paths in api_patterns.get('framework_patterns', {}).items():
            for path in paths:
                if path.startswith('/'):
                    paths_to_test.add(path)

    # 2c. API前缀 + 路径段 组合
    path_segs = api_patterns.get('path_segments', [])
    # 从JS分析中提取的前缀（通过参数传入）
    extra_prefixes = []
    if api_prefixes_from_js:
        try:
            extra_prefixes = json.loads(api_prefixes_from_js)
        except:
            extra_prefixes = [api_prefixes_from_js]
    if isinstance(extra_prefixes, str):
        extra_prefixes = [extra_prefixes]

    all_prefixes = list(api_patterns.get('api_prefixes', {}).keys()) + extra_prefixes
    # 添加常见的API前缀兜底
    all_prefixes.extend(['/api/', '/api/v1/', '/api/v2/', '/api/v3/', '/gateway/', '/dwr/', '/sys/', '/manage/', '/crm/', '/erp/'])

    for prefix in set(all_prefixes):
        if not prefix.startswith('/'):
            prefix = '/' + prefix
        prefix = prefix.rstrip('/')
        paths_to_test.add(prefix)
        # 对每个前缀+常用段组合
        for seg in path_segs[:20]:  # 限制20个避免过多
            paths_to_test.add(f"{prefix}/{seg}")

    print(f"[*] 共 {len(paths_to_test)} 个路径待探测", file=sys.stderr)

    # Step 3: curl 探测
    findings = []
    new_endpoints = []

    for i, path in enumerate(sorted(paths_to_test)):
        test_url = f"{base_url}{path}"
        status_str, rc = run(f"{curl_base} '{test_url}'")

        try:
            status_code = int(status_str)
        except:
            continue

        if status_code in (200, 401, 403):
            entry = {
                "target": target_url,
                "endpoint": test_url,
                "status_code": status_code,
                "path": path,
                "source": "智能fuzz"
            }
            findings.append(entry)
            if status_code == 200:
                new_endpoints.append(path)
            print(f"  [{status_code}] {path}", file=sys.stderr)

        # 速率限制
        if i > 0 and i % 50 == 0:
            time.sleep(0.5)

    # Step 4: 提取新模式
    new_prefixes = set()
    new_segments = set()
    for f in findings:
        path = f['path']
        parts = path.strip('/').split('/')
        if len(parts) >= 2:
            prefix = '/' + parts[0] + '/'
            segment = parts[1]
            # 不在已知列表中才算新
            if prefix not in api_patterns.get('api_prefixes', {}) and not any(prefix in x for x in api_patterns.get('framework_patterns', {}).values()):
                new_prefixes.add(prefix)
            if segment not in api_patterns.get('path_segments', []):
                new_segments.add(segment)

    result = {
        "target": target_url,
        "total_tested": len(paths_to_test),
        "findings": findings,
        "finding_count": len(findings),
        "extracted_patterns": {
            "new_prefixes": list(new_prefixes)[:10],
            "new_segments": list(new_segments)[:20],
            "framework_hits": []
        },
        "new_endpoints": new_endpoints[:50],
    }

    if output_path:
        os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else '.', exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=2)

    return result

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='智能路径枚举')
    parser.add_argument('target_url', help='目标URL')
    parser.add_argument('--dict', required=True, help='api_patterns.json 路径')
    parser.add_argument('--output', required=True, help='结果输出文件')
    parser.add_argument('--ua', default='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36')
    parser.add_argument('--interface', default='')
    parser.add_argument('--framework', default='')
    parser.add_argument('--api-prefixes', default='', help='从JS分析中提取的API前缀JSON数组')
    args = parser.parse_args()

    result = smart_fuzz(args.target_url, args.dict, args.output, args.ua, args.interface, args.framework, args.api_prefixes)
    print(json.dumps(result, ensure_ascii=False, indent=2))

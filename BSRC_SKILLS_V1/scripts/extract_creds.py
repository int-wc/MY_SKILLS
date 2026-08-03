#!/usr/bin/env python3
"""
extract_creds.py — 从JS源码中提取鉴权凭证（结构化输出）

用法:
  python3 extract_creds.py <js_dump_dir>
  python3 extract_creds.py <js_dump_dir> --output creds.json

提取类型:
  - JWT Token (eyJ...)
  - Bearer Token / API Key
  - Basic Auth 凭证
  - Cookie (含敏感session)
  - OAuth token / refresh_token
  - 内网API地址 (含凭证)
  - 硬编码账号密码
"""
import sys
import os
import re
import json

JWT_PATTERN = r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'
BEARER_PATTERN = r'(?:Bearer|bearer|token)\s*[:=]\s*["\']([a-zA-Z0-9_\-\.=]{20,200})["\']'
API_KEY_PATTERN = r'(?:api[Kk]ey|apikey|API_KEY|api_key|secret[Kk]ey|accessKey|secretKey)\s*[:=]\s*["\']([a-zA-Z0-9_\-\./=+]{8,128})["\']'
BASIC_AUTH_PATTERN = r'(?:Authorization|auth)\s*[:=]\s*["\']Basic\s+([a-zA-Z0-9=]+)["\']'
COOKIE_PATTERN = r'(?:Cookie|cookie|session)\s*[:=]\s*["\']([a-zA-Z0-9_\-%=,;\.]+(?:session|token|sid|auth)[a-zA-Z0-9_\-%=,;\.]*)["\']'
PASSWORD_PATTERN = r'(?:password|pwd|passwd)\s*[:=]\s*["\']([^"\']{4,50})["\']'
OAUTH_PATTERN = r'(?:refresh_token|access_token|client_secret|client_id)\s*[:=]\s*["\']([a-zA-Z0-9_\-\.=]{8,200})["\']'
INTERNAL_URL_PATTERN = r'(?:https?://[a-z0-9.-]+(?:internal|dev|test|staging|intranet)[^"\']*)'
USERNAME_PATTERN = r'(?:username|user_name|login|account)\s*[:=]\s*["\']([^"\']{3,50})["\']'

def scan_file(filepath):
    """Scan a single JS file for credentials"""
    creds = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
    except:
        return creds

    filename = os.path.basename(filepath)
    relpath = filepath

    patterns = [
        ("jwt", JWT_PATTERN),
        ("bearer_token", BEARER_PATTERN),
        ("api_key", API_KEY_PATTERN),
        ("basic_auth", BASIC_AUTH_PATTERN),
        ("cookie", COOKIE_PATTERN),
        ("password", PASSWORD_PATTERN),
        ("oauth", OAUTH_PATTERN),
        ("username", USERNAME_PATTERN),
    ]

    for cred_type, pattern in patterns:
        for m in re.finditer(pattern, content, re.IGNORECASE):
            value = m.group(1) if m.lastindex else m.group(0)
            if len(value) < 6:
                continue
            # 过滤明显不是凭证的
            if cred_type == "password" and value in ('password', ' pass', '****', '123456'):
                continue
            # 找上下文
            start = max(0, m.start() - 60)
            end = min(len(content), m.end() + 60)
            context = content[start:end].replace('\n', ' ')[:120]

            creds.append({
                "type": cred_type,
                "value": value[:200],  # 截断避免过大
                "source_file": relpath,
                "context": context,
            })

    # 额外: 内网地址
    for m in re.finditer(INTERNAL_URL_PATTERN, content, re.IGNORECASE):
        creds.append({
            "type": "internal_url",
            "value": m.group(0)[:200],
            "source_file": relpath,
            "context": m.group(0)[:120],
        })

    return creds

def extract_creds(js_dump_dir, output_path=None):
    """主流程"""
    if not os.path.isdir(js_dump_dir):
        # 可能是单个文件
        if os.path.isfile(js_dump_dir):
            js_files = [js_dump_dir]
            js_dump_dir = os.path.dirname(js_dump_dir)
        else:
            return {"status": "error", "error": f"目录不存在: {js_dump_dir}", "credentials": []}
    else:
        # 收集所有 JS 文件
        js_files = []
        for root, dirs, files in os.walk(js_dump_dir):
            # 跳过 reconstructed 目录（已还原源码）
            if 'reconstructed' in root:
                # 但也扫描 reconstructed 下的文件
                pass
            for f in files:
                if f.endswith('.js') and not f.endswith('.map') and not f.startswith('_'):
                    js_files.append(os.path.join(root, f))

    if not js_files:
        return {"status": "ok", "scanned": 0, "credentials": []}

    all_creds = []
    for fp in js_files:
        all_creds.extend(scan_file(fp))

    # 去重 (按 type + value 去重)
    seen = set()
    unique_creds = []
    for c in all_creds:
        key = f"{c['type']}:{c['value'][:50]}"
        if key not in seen:
            seen.add(key)
            unique_creds.append(c)

    result = {
        "status": "ok",
        "js_dump_dir": js_dump_dir,
        "scanned": len(js_files),
        "credential_count": len(unique_creds),
        "credentials": unique_creds,
    }

    if output_path:
        os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else '.', exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=2)

    return result

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='从JS提取鉴权凭证')
    parser.add_argument('js_dump_dir', help='JS缓存目录或文件')
    parser.add_argument('--output', '-o', default='', help='输出JSON文件')
    args = parser.parse_args()

    result = extract_creds(args.js_dump_dir, args.output)
    # 打印摘要到 stderr，完整结果到 stdout
    creds = result.get('credentials', [])
    print(f"[*] 扫描 {result['scanned']} 个文件, 发现 {len(creds)} 条凭证", file=sys.stderr)
    for c in creds[:10]:
        print(f"  [{c['type']}] {c['value'][:60]}... ← {os.path.basename(c['source_file'])}", file=sys.stderr)
    if len(creds) > 10:
        print(f"  ... 还有 {len(creds)-10} 条", file=sys.stderr)
    print(json.dumps(result, ensure_ascii=False, indent=2))

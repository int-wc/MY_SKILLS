#!/usr/bin/env python3
"""
enumerate_chunks.py — 从已下载JS中提取webpack chunk引用并补下载

用法:
  python3 enumerate_chunks.py <js_dump_dir> <base_url> [--ua "UA"] [--interface iface]

流程:
  1. 扫描 <js_dump_dir>/*.js 提取 chunk-xxx、assets/xxx.js 等引用
  2. 排除已下载的文件
  3. 尝试下载缺失的chunk
  4. 输出下载结果 JSON
"""
import sys
import os
import json
import re
import subprocess
import urllib.parse

def run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", -1

def fetch(curl_base, test_url, out_path):
    """带TLS兜底的下载：校验失败时自动加 -k 重试"""
    cmd = f"{curl_base} '{test_url}' -o '{out_path}' -w '%{{http_code}}'"
    content, rc = run(cmd)
    if rc != 0 or content == '000':
        content2, rc2 = run(f"{curl_base} -k '{test_url}' -o '{out_path}' -w '%{{http_code}}'")
        if rc2 == 0:
            return content2, rc2
    return content, rc

# 需要枚举的chunk引用模式
CHUNK_PATTERNS = [
    r'(chunk-[a-f0-9]{8,64})',                    # webpack chunk-hash
    r'([a-f0-9]{20,64}\.chunk\.[a-z]+)',          # create-react-app chunk
    r'[\"\'](assets/[a-f0-9\-]+\.js)[\"\']',      # Vite assets
    r'[\"\'](static/js/[a-f0-9]+\.js)[\"\']',      # CRA static/js
    r'[\"\'](_nuxt/[a-f0-9]+\.js)[\"\']',          # Nuxt.js
    r'[\"\'](js/[a-zA-Z0-9\-]+\.js)[\"\']',        # js/ 目录
    r'[\"\'](pages/[a-zA-Z0-9/\-]+\.js)[\"\']',    # pages/
    r'[\"\'](components/[a-zA-Z0-9/\-]+\.js)[\"\']', # components/
    r'[\"\'](views/[a-zA-Z0-9/\-]+\.js)[\"\']',    # views/
    r'[\"\'](modules/[a-zA-Z0-9/\-]+\.js)[\"\']',  # modules/
    r'import\s*\(\s*[\"\']((?:\./)?[a-zA-Z0-9/\-]+\.js)',  # dynamic import
    r'require\.ensure\([\"\']([a-zA-Z0-9/\-]+\.js)',  # require.ensure
    r'define\([\"\']([a-zA-Z0-9/\-]+)',            # AMD/RequireJS
]

def enumerate_chunks(js_dump_dir, base_url, ua='', iface=''):
    """枚举并补下载chunk"""
    if not os.path.isdir(js_dump_dir):
        return {"status": "error", "error": f"目录不存在: {js_dump_dir}"}

    curl_base = 'curl -sL --max-time 10 --connect-timeout 5'
    if ua:
        curl_base += f" -H 'User-Agent: {ua}'"
    if iface:
        curl_base += f" --interface {iface}"

    # Step 1: 扫描所有已下载JS
    js_files = []
    for root, dirs, files in os.walk(js_dump_dir):
        # 跳过已经重构的源码目录
        if 'reconstructed' in root:
            continue
        for f in files:
            if f.endswith('.js') and not f.endswith('.map'):
                js_files.append(os.path.join(root, f))

    print(f"[*] 扫描 {len(js_files)} 个JS文件提取chunk引用...", file=sys.stderr)

    # Step 2: 提取所有chunk引用
    found_refs = set()
    already_have = set()

    # 收集已下载的文件名（用于去重）
    for f in js_files:
        already_have.add(os.path.basename(f))
    # 也收集reconstructed/ 和 lazy_ 前缀
    for f in js_files:
        already_have.add(os.path.basename(f))
        # 如果是带前缀的，也记录
        if f.startswith('lazy_'):
            already_have.add(f[5:])

    for js_path in js_files:
        try:
            with open(js_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
        except:
            continue

        for pattern in CHUNK_PATTERNS:
            for m in re.finditer(pattern, content, re.IGNORECASE):
                ref = m.group(1)
                # 过滤掉明显不是路径的
                if len(ref) < 5 or ref.startswith('//'):
                    continue
                # 去重: 提取最后的文件名部分
                ref_name = os.path.basename(ref)
                if ref_name and ref_name not in already_have:
                    found_refs.add(ref)
                    already_have.add(ref_name)

    print(f"[*] 发现 {len(found_refs)} 个缺失的chunk引用", file=sys.stderr)
    if not found_refs:
        return {"status": "ok", "downloaded": [], "new_count": 0}

    # Step 3: 尝试下载缺失的chunk
    downloaded = []
    base_url_clean = base_url.rstrip('/')

    # 尝试的路径前缀
    prefixes = ['', 'js/', 'assets/', 'static/', 'static/js/', '_nuxt/', 'chunk/', 'chunks/']

    for ref in found_refs:
        ref_name = os.path.basename(ref) if '/' not in ref else ref.replace('../', '').replace('./', '')
        if not ref_name:
            continue

        saved = False
        for prefix in prefixes:
            test_url = f"{base_url_clean}/{prefix}{ref_name}"
            out_path = os.path.join(js_dump_dir, f"lazy_{ref_name}")

            content, rc = fetch(curl_base, test_url, out_path)
            if rc == 0:
                # 检查是否成功下载（非404/非空）
                try:
                    file_size = os.path.getsize(out_path)
                    if file_size > 50:
                        downloaded.append({"url": test_url, "file": f"lazy_{ref_name}", "size": file_size})
                        print(f"[+] chunk: {ref_name} ({file_size}b) @ {prefix}", file=sys.stderr)
                        saved = True
                        break
                    else:
                        os.remove(out_path)
                except:
                    pass

        if not saved:
            # 尝试直接从base_url取
            test_url = f"{base_url_clean}/{ref}"
            out_path = os.path.join(js_dump_dir, f"lazy_{os.path.basename(ref)}")
            content, rc = fetch(curl_base, test_url, out_path)
            if rc == 0:
                try:
                    file_size = os.path.getsize(out_path)
                    if file_size > 50:
                        downloaded.append({"url": test_url, "file": f"lazy_{os.path.basename(ref)}", "size": file_size})
                        saved = True
                except:
                    pass

    return {
        "status": "ok",
        "found_refs": list(found_refs)[:50],
        "downloaded": downloaded,
        "new_count": len(downloaded),
        "total_chunks_found": len(found_refs),
    }

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='枚举webpack chunk并补下载')
    parser.add_argument('js_dump_dir', help='JS缓存目录 (js_dumps/<hash>/)')
    parser.add_argument('base_url', help='目标base URL')
    parser.add_argument('--ua', default='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36', help='User-Agent')
    parser.add_argument('--interface', default='', help='网络接口 (如 tun0)')
    args = parser.parse_args()

    result = enumerate_chunks(args.js_dump_dir, args.base_url, args.ua, args.interface)
    print(json.dumps(result, ensure_ascii=False, indent=2))

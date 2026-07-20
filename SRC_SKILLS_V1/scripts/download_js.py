#!/usr/bin/env python3
"""
download_js.py — 从目标URL下载所有JS源码到本地

用法:
  python3 download_js.py <url> <output_dir> [--ua "User-Agent"] [--interface iface]
  python3 download_js.py <url> <output_dir> [--ua "UA"] [--cookie "key=val"]

流程:
  1. curl 获取HTML → 提取 <script src>
  2. 对每个JS URL → curl -s -o 下载到 <output_dir>/<target_hash>/
  3. 检查 sourceMappingURL → 下载 .js.map
  4. 输出已下载文件列表 JSON 到 stdout
"""
import sys
import os
import json
import re
import subprocess
import urllib.parse
from hashlib import md5

def run(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", -1

def extract_script_srcs(html, base_url):
    """提取HTML中所有<script src>路径"""
    # 匹配 <script src="..."> 和 <script type="module" src="...">
    patterns = [
        r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']',
        r'<link[^>]+href\s*=\s*["\']([^"\']+\.js)["\']',
    ]
    urls = []
    for p in patterns:
        for m in re.finditer(p, html, re.IGNORECASE):
            src = m.group(1).strip()
            if not src or src.startswith('data:') or src.startswith('blob:'):
                continue
            # 解析相对路径
            full_url = urllib.parse.urljoin(base_url, src)
            urls.append(full_url)
    return list(dict.fromkeys(urls))  # 去重保持顺序

def download_js(target_url, output_dir, ua='', iface='', cookie=''):
    """主流程"""
    os.makedirs(output_dir, exist_ok=True)

    # 生成目标hash作为子目录名
    target_hash = md5(target_url.encode()).hexdigest()[:12]
    dump_dir = os.path.join(output_dir, target_hash)
    os.makedirs(dump_dir, exist_ok=True)

    # curl 基础参数
    curl_base = 'curl -sL --max-time 15 --connect-timeout 8'
    if ua:
        curl_base += f" -H 'User-Agent: {ua}'"
    if iface:
        curl_base += f" --interface {iface}"
    if cookie:
        curl_base += f" -H 'Cookie: {cookie}'"

    downloaded = []
    failed = []

    # Step 1: 获取HTML
    print(f"[*] 获取HTML: {target_url}", file=sys.stderr)
    html, rc = run(f"{curl_base} '{target_url}'")
    if rc != 0 or not html:
        print(f"[!] HTML获取失败 ({target_url})", file=sys.stderr)
        return {"status": "unreachable", "target": target_url, "files": [], "errors": ["HTML fetch failed"]}

    # 保存HTML
    html_path = os.path.join(dump_dir, '_page.html')
    with open(html_path, 'w', encoding='utf-8', errors='replace') as f:
        f.write(html)
    downloaded.append(html_path)

    # Step 2: 提取JS路径
    js_urls = extract_script_srcs(html, target_url)
    print(f"[*] 发现 {len(js_urls)} 个JS引用", file=sys.stderr)

    if not js_urls:
        # 内联JS可能没有src属性，扫描所有脚本标签
        inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL | re.IGNORECASE)
        for i, sc in enumerate(inline_scripts):
            if sc.strip():
                js_path = os.path.join(dump_dir, f'inline_{i:03d}.js')
                with open(js_path, 'w', encoding='utf-8', errors='replace') as f:
                    f.write(sc)
                downloaded.append(js_path)
        print(f"[*] 保存 {len([s for s in inline_scripts if s.strip()])} 个内联脚本", file=sys.stderr)

    # Step 3: 下载每个JS
    for js_url in js_urls:
        js_name = os.path.basename(urllib.parse.urlparse(js_url).path) or f'js_{md5(js_url.encode()).hexdigest()[:8]}.js'
        js_path = os.path.join(dump_dir, js_name)

        content, rc2 = run(f"{curl_base} '{js_url}'")
        if rc2 == 0 and content:
            with open(js_path, 'w', encoding='utf-8', errors='replace') as f:
                f.write(content)
            downloaded.append(js_path)

            # 检查 sourceMappingURL
            map_match = re.search(r'//#\s*sourceMappingURL=(\S+)', content)
            if map_match:
                map_url = urllib.parse.urljoin(js_url, map_match.group(1))
                map_name = js_name + '.map'
                map_path = os.path.join(dump_dir, map_name)
                map_content, _ = run(f"{curl_base} '{map_url}'")
                if map_content:
                    with open(map_path, 'w', encoding='utf-8', errors='replace') as f:
                        f.write(map_content)
                    downloaded.append(map_path)
                    print(f"[+] JS + SourceMap: {js_name}", file=sys.stderr)
                else:
                    print(f"[-] SourceMap 404: {map_url}", file=sys.stderr)
            else:
                print(f"[+] JS: {js_name}", file=sys.stderr)
        else:
            failed.append(js_url)
            print(f"[-] JS下载失败: {js_url}", file=sys.stderr)

    return {
        "status": "ok",
        "target": target_url,
        "dump_dir": dump_dir,
        "files": downloaded,
        "failed": failed,
        "file_count": len(downloaded),
        "target_hash": target_hash,
    }

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='下载JS源码到本地')
    parser.add_argument('url', help='目标URL')
    parser.add_argument('output_dir', help='输出目录')
    parser.add_argument('--ua', default='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36', help='User-Agent')
    parser.add_argument('--interface', default='', help='网络接口 (如 tun0)')
    parser.add_argument('--cookie', default='', help='Cookie')
    args = parser.parse_args()

    result = download_js(args.url, args.output_dir, args.ua, args.interface, args.cookie)
    print(json.dumps(result, ensure_ascii=False, indent=2))

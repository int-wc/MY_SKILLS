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
import base64

JWT_PATTERN = r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'
BEARER_PATTERN = r'(?:Bearer|bearer|token)\s*[:=]\s*["\']([a-zA-Z0-9_\-\.=]{20,200})["\']'
API_KEY_PATTERN = r'(?:api[Kk]ey|apikey|API_KEY|api_key|secret[Kk]ey|accessKey|secretKey)\s*[:=]\s*["\']([a-zA-Z0-9_\-\./=+]{8,128})["\']'
BASIC_AUTH_PATTERN = r'(?:Authorization|auth)\s*[:=]\s*["\']Basic\s+([a-zA-Z0-9=]+)["\']'
COOKIE_PATTERN = r'(?:Cookie|cookie|session)\s*[:=]\s*["\']([a-zA-Z0-9_\-%=,;\.]+(?:session|token|sid|auth)[a-zA-Z0-9_\-%=,;\.]*)["\']'
PASSWORD_PATTERN = r'(?:password|pwd|passwd)\s*[:=]\s*["\']([^"\']{4,50})["\']'
OAUTH_PATTERN = r'(?:refresh_token|access_token|client_secret|client_id)\s*[:=]\s*["\']([a-zA-Z0-9_\-\.=]{8,200})["\']'
INTERNAL_URL_PATTERN = r'(?:https?://[a-z0-9.-]+(?:internal|dev|test|staging|intranet)[^"\']*)'
USERNAME_PATTERN = r'(?:username|user_name|login|account)\s*[:=]\s*["\']([^"\']{3,50})["\']'


def scan_html_inline_json(js_dump_dir):
    """Scan _page.html (saved by download_js.py) for SSR inline JSON (Nuxt/Next/React)"""
    creds = []
    html_path = os.path.join(js_dump_dir, '_page.html')
    if not os.path.isfile(html_path):
        return creds

    try:
        with open(html_path, 'r', encoding='utf-8', errors='replace') as f:
            html = f.read()
    except:
        return creds

    # Helper: extract JSON from between assignment and next </script> or ;
    def _extract_json_after_assign(html, var_pattern):
        """Match `window.VAR_NAME = <json>` before </script> or ;"""
        m = re.search(var_pattern, html)
        if not m:
            return None
        start = m.end()
        # Find end: </script> or ; or <
        end_match = re.search(r'</script|;\s*<|;\s*$', html[start:])
        if end_match:
            end = start + end_match.start()
        else:
            end = len(html)
        raw = html[start:end].strip().rstrip(';').strip()
        # Try to parse as JSON; if fails, try truncating at different } positions
        for i in range(len(raw), 0, -1):
            if raw[i-1] == '}':
                try:
                    candidate = raw[:i]
                    json.loads(candidate)
                    return candidate
                except:
                    continue
        return None

    ssr_patterns = [
        ("nuxt_data", r'window\.__NUXT__\s*=\s*'),
        ("react_initial_state", r'window\.__INITIAL_STATE__\s*=\s*'),
        ("react_preloaded", r'window\.__PRELOADED_STATE__\s*=\s*'),
        ("react_initial_props", r'window\.__INITIAL_PROPS__\s*=\s*'),
        ("apollo_state", r'window\.__APOLLO_STATE__\s*=\s*'),
        ("remix_data", r'window\.__remixContext\s*=\s*'),
    ]

    for cred_type, pattern in ssr_patterns:
        value = _extract_json_after_assign(html, pattern)
        if not value or len(value) < 20:
            continue

        extracted_fields = {}
        try:
            data = json.loads(value)

            def walk_json(obj, path=''):
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        cp = f"{path}.{k}" if path else k
                        if isinstance(v, str):
                            if v.startswith('http') and ('api' in v.lower() or '/v1/' in v or '/v2/' in v):
                                extracted_fields[f"api_url_{cp}"] = v[:200]
                            elif any(tok in cp.lower() for tok in ['token', 'jwt', 'secret', 'key', 'password', 'auth']):
                                extracted_fields[f"creds_{cp}"] = v[:100]
                            elif 'role' in cp.lower() or 'permission' in cp.lower() or 'menu' in cp.lower():
                                extracted_fields[f"perms_{cp}"] = v[:200]
                        elif isinstance(obj, list) and cp.split('.')[-1] in ('roles', 'permissions', 'menus', 'routes'):
                            extracted_fields[f"perms_{cp}"] = json.dumps(v, ensure_ascii=False)[:300]
                        walk_json(v, cp)
            walk_json(data)
        except:
            pass

        context = value[:200]
        if extracted_fields:
            context += f" | extracted: {json.dumps(extracted_fields, ensure_ascii=False)[:300]}"

        creds.append({
            "type": f"ssr_{cred_type}",
            "value": context[:500],
            "source_file": html_path,
            "context": f"SSR inline JSON ({cred_type}) in _page.html",
        })

    # next_data and svelte_kit_data use dedicated <script> tags
    tag_patterns = [
        ("next_data", r'<script id="__NEXT_DATA__"[^>]*type="application/json"[^>]*>([\s\S]{10,}?)</script>'),
        ("svelte_kit_data", r'<script[^>]*data-sveltekit-data-url[^>]*>([\s\S]{10,}?)</script>'),
    ]
    for cred_type, pattern in tag_patterns:
        for m in re.finditer(pattern, html):
            value = m.group(1)
            if len(value) < 20:
                continue
            # Verify it's valid JSON
            try:
                json.loads(value)
            except:
                continue
            extracted_fields = {}
            try:
                data = json.loads(value)
                def walk_json(obj, path=''):
                    if isinstance(obj, dict):
                        for k, v in obj.items():
                            cp = f"{path}.{k}" if path else k
                            if isinstance(v, str):
                                if v.startswith('http') and ('api' in v.lower() or '/v1/' in v or '/v2/' in v):
                                    extracted_fields[f"api_url_{cp}"] = v[:200]
                                elif any(tok in cp.lower() for tok in ['token', 'jwt', 'secret', 'key', 'password', 'auth']):
                                    extracted_fields[f"creds_{cp}"] = v[:100]
                                elif 'role' in cp.lower() or 'permission' in cp.lower() or 'menu' in cp.lower():
                                    extracted_fields[f"perms_{cp}"] = v[:200]
                            elif isinstance(obj, list) and cp.split('.')[-1] in ('roles', 'permissions', 'menus', 'routes'):
                                extracted_fields[f"perms_{cp}"] = json.dumps(v, ensure_ascii=False)[:300]
                            walk_json(v, cp)
                walk_json(data)
            except:
                pass
            context = value[:200]
            if extracted_fields:
                context += f" | extracted: {json.dumps(extracted_fields, ensure_ascii=False)[:300]}"
            creds.append({
                "type": f"ssr_{cred_type}",
                "value": context[:500],
                "source_file": html_path,
                "context": f"SSR inline JSON ({cred_type}) in _page.html",
            })
    return creds


def scan_runtime_api_paths(js_dump_dir):
    """Scan JS for runtime API path assembly patterns (array.join, atob, GraphQL, template literals, config objects)"""
    creds = []

    js_files = []
    for root, dirs, files in os.walk(js_dump_dir):
        for f in files:
            if f.endswith('.js') and not f.endswith('.map'):
                js_files.append(os.path.join(root, f))

    for fp in js_files:
        try:
            with open(fp, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
        except:
            continue

        fname = os.path.basename(fp)

        # Pattern 1: array.join('/') API path assembly
        for m in re.finditer(r'\[([\'"][a-zA-Z0-9_\-/.]+[\'"](?:\s*,\s*[\'"][a-zA-Z0-9_\-/.]+[\'"]){1,10})\]\s*\.\s*join\s*\(\s*[\'"]/[\'"]\s*\)', content):
            parts_str = m.group(1)
            parts = re.findall(r'[\'"]([^\'"]+)[\'"]', parts_str)
            assembled = '/'.join(parts)
            if any(kw in assembled.lower() for kw in ['api', 'v1/', 'v2/', 'auth', 'login', 'token', 'user', 'admin']):
                creds.append({
                    "type": "array_join_api",
                    "value": assembled[:200],
                    "source_file": fp,
                    "context": f"array.join('/') assembled path: {assembled[:120]}",
                })

        # Pattern 2: atob/base64 decoded URL paths
        for m in re.finditer(r'(?:atob|btoa|base64_decode|Base64\.decode)\s*\(\s*[\'"]([a-zA-Z0-9+/=]{10,200})[\'"]\s*\)', content):
            try:
                decoded = base64.b64decode(m.group(1)).decode('utf-8', errors='replace')
                if any(kw in decoded.lower() for kw in ['http', 'api', 'token', 'auth', 'login', 'admin']):
                    creds.append({
                        "type": "atob_decoded",
                        "value": decoded[:200],
                        "source_file": fp,
                        "context": f"base64 decoded: {decoded[:120]}",
                    })
            except:
                pass

        # Pattern 3: GraphQL operation names with sensitive context
        for m in re.finditer(r'(?:query|mutation)\s+([a-zA-Z][a-zA-Z0-9_]+)\s*[({]', content):
            op_name = m.group(1)
            start = max(0, m.start() - 100)
            ctx = content[start:m.end() + 100]
            if any(kw in ctx.lower() for kw in ['password', 'token', 'secret', 'auth', 'login', 'admin', 'role']):
                creds.append({
                    "type": "graphql_op",
                    "value": op_name[:100],
                    "source_file": fp,
                    "context": f"GraphQL operation with sensitive context: ...{ctx[:120]}...",
                })

        # Pattern 4: Template literal URL assembly
        for m in re.finditer(r'`(/[^`]{3,200})`', content):
            url = m.group(1)
            if any(kw in url.lower() for kw in ['api', 'v1/', 'v2/', 'auth', 'token', 'admin', 'login']) and '${' in url:
                creds.append({
                    "type": "template_literal_api",
                    "value": url[:200],
                    "source_file": fp,
                    "context": f"template literal URL: {url[:120]}",
                })

        # Pattern 5: Config object with API base URLs
        for m in re.finditer(r'(?:apiBaseUrl|baseUrl|BASE_URL|API_URL|api_url|apiHost|apiBase|basePath|endpoint)\s*[:=]\s*[\'"]([^\'"]+)[\'"]', content):
            val = m.group(1)
            if val.startswith('http') and not val.startswith('https://www.google') and not val.startswith('https://www.baidu'):
                creds.append({
                    "type": "api_base_url",
                    "value": val[:200],
                    "source_file": fp,
                    "context": f"config object API URL: {val[:120]}",
                })

    return creds


def scan_wasm_refs(js_dump_dir):
    """Scan JS and HTML for WebAssembly references and wasm file paths"""
    creds = []
    js_files = []

    # Also scan _page.html for wasm refs
    html_path = os.path.join(js_dump_dir, '_page.html')
    if os.path.isfile(html_path):
        try:
            html = open(html_path, 'r', encoding='utf-8', errors='replace').read()
            for m in re.finditer(r'(?:fetch|XMLHttpRequest|WebAssembly)\s*\(?\s*["\']([^"\']+\.wasm)["\']', html):
                creds.append({
                    "type": "wasm_url",
                    "value": m.group(1)[:200],
                    "source_file": html_path,
                    "context": f"wasm file reference in _page.html",
                })
        except:
            pass

    for root, dirs, files in os.walk(js_dump_dir):
        for f in files:
            if f.endswith('.js') and not f.endswith('.map'):
                js_files.append(os.path.join(root, f))

    for fp in js_files:
        try:
            with open(fp, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
        except:
            continue

        fname = os.path.basename(fp)

        # WebAssembly.instantiate / instantiateStreaming
        for m in re.finditer(r'WebAssembly\.(?:instantiate|instantiateStreaming|compile|compileStreaming)\s*\(', content):
            start = max(0, m.start() - 80)
            end = min(len(content), m.end() + 200)
            ctx = content[start:end].replace('\n', ' ')[:250]
            # 提取wasm路径
            wasm_paths = re.findall(r'["\']([^"\']+\.wasm)["\']', ctx)
            creds.append({
                "type": "wasm_instantiate",
                "value": wasm_paths[0] if wasm_paths else fname,
                "source_file": fp,
                "context": f"WebAssembly API call: {ctx[:200]}",
            })

        # wasm 模块路径
        for m in re.finditer(r'["\'](https?://[^"\']+\.wasm)["\']', content):
            creds.append({
                "type": "wasm_url",
                "value": m.group(1)[:200],
                "source_file": fp,
                "context": f"wasm file path: {m.group(1)[:120]}",
            })

        # wasm 二进制导入 (.wasm import from esm)
        for m in re.finditer(r'import\s+[\s\S]{0,50}?\s+from\s+["\']([^"\']+\.wasm)["\']', content):
            creds.append({
                "type": "wasm_import",
                "value": m.group(1)[:200],
                "source_file": fp,
                "context": f"ESM wasm import: {m.group(1)[:120]}",
            })

    # Scan for .wasm files already downloaded
    for root, dirs, files in os.walk(js_dump_dir):
        for f in files:
            if f.endswith('.wasm'):
                fpath = os.path.join(root, f)
                try:
                    size = os.path.getsize(fpath)
                    creds.append({
                        "type": "wasm_file",
                        "value": f"{f} ({size} bytes)",
                        "source_file": fpath,
                        "context": f"downloaded wasm file, may contain obfuscated logic",
                    })
                except:
                    pass

    return creds


def scan_service_worker(js_dump_dir):
    """Scan JS and HTML for Service Worker registrations and request interception"""
    creds = []
    js_files = []

    # Scan _page.html for SW registration
    html_path = os.path.join(js_dump_dir, '_page.html')
    if os.path.isfile(html_path):
        try:
            html = open(html_path, 'r', encoding='utf-8', errors='replace').read()
            for m in re.finditer(r'navigator\.serviceWorker\.register\s*\(\s*["\']([^"\']+)["\']', html):
                creds.append({
                    "type": "sw_register",
                    "value": m.group(1)[:200],
                    "source_file": html_path,
                    "context": f"SW registration in _page.html",
                })
        except:
            pass

    for root, dirs, files in os.walk(js_dump_dir):
        for f in files:
            if f.endswith('.js') and not f.endswith('.map'):
                js_files.append(os.path.join(root, f))

    for fp in js_files:
        try:
            with open(fp, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
        except:
            continue

        # navigator.serviceWorker.register
        for m in re.finditer(r'navigator\.serviceWorker\.register\s*\(\s*["\']([^"\']+)["\']', content):
            start = max(0, m.start() - 100)
            end = min(len(content), m.end() + 200)
            ctx = content[start:end].replace('\n', ' ')[:250]
            creds.append({
                "type": "sw_register",
                "value": m.group(1)[:200],
                "source_file": fp,
                "context": f"SW registration: {ctx[:200]}",
            })

        # sw.js file found — analyze its content for request interception
        if 'sw.' in os.path.basename(fp) or 'service-worker' in os.path.basename(fp):
            # fetch event listeners — request interception
            for m2 in re.finditer(r'self\.addEventListener\s*\(\s*["\']fetch["\']', content):
                start = max(0, m2.start() - 80)
                end = min(len(content), m2.end() + 300)
                ctx = content[start:end].replace('\n', ' ')[:300]
                creds.append({
                    "type": "sw_fetch_intercept",
                    "value": f"fetch interception in {os.path.basename(fp)}",
                    "source_file": fp,
                    "context": f"SW fetch listener: {ctx[:250]}",
                })

            # Cache API usage — what URLs are cached
            for m3 in re.finditer(r'caches?\.(?:open|add|addAll|match)\s*\(', content):
                start = max(0, m3.start() - 80)
                end = min(len(content), m3.end() + 200)
                ctx = content[start:end].replace('\n', ' ')[:250]
                creds.append({
                    "type": "sw_cache_api",
                    "value": f"Cache API in {os.path.basename(fp)}",
                    "source_file": fp,
                    "context": f"SW cache: {ctx[:200]}",
                })

            # importScripts in sw
            for m4 in re.finditer(r'importScripts\s*\(\s*["\']([^"\']+)["\']', content):
                creds.append({
                    "type": "sw_import",
                    "value": m4.group(1)[:200],
                    "source_file": fp,
                    "context": f"SW importScripts loads external dependency",
                })

    return creds


def scan_esm_cdn_refs(js_dump_dir):
    """Scan JS for ESM CDN import references (esm.sh, unpkg, cdn.jsdelivr.net, skypack)"""
    creds = []
    cdn_domains = [
        'esm\\.sh',
        'cdn\\.jsdelivr\\.net',
        'unpkg\\.com',
        'cdn\\.skypack\\.dev',
        'cdn\\.esm\\.dev',
        'cdn\\.xsh',
    ]

    js_files = []
    for root, dirs, files in os.walk(js_dump_dir):
        for f in files:
            if f.endswith('.js') and not f.endswith('.map'):
                js_files.append(os.path.join(root, f))

    cdn_re = r'(https?://(?:' + '|'.join(cdn_domains) + r')/[^"\')\s]+)'

    for fp in js_files:
        try:
            with open(fp, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
        except:
            continue

        fname = os.path.basename(fp)

        for m in re.finditer(cdn_re, content):
            url = m.group(1)[:300]
            # Determine import style
            import_style = 'unknown'
            pre = content[max(0, m.start()-50):m.start()]
            if 'import ' in pre and ' from ' in pre:
                import_style = 'esm_import'
            elif 'import(' in pre:
                import_style = 'dynamic_import'
            elif 'require(' in pre or 'require ' in pre:
                import_style = 'require'

            creds.append({
                "type": f"cdn_{import_style}",
                "value": url[:200],
                "source_file": fp,
                "context": f"CDN {import_style}: {url[:120]}",
            })

    # Also scan for CDN-hosted .wasm or other binary assets
    for fp in js_files:
        try:
            with open(fp, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
        except:
            continue
        for m in re.finditer(cdn_re.replace('\\.js', '\\.(js|wasm|mjs)'), content):
            pass  # already covered above

    return creds


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
                # reconstructed 目录也要扫描（包含Source Map还原的原始TS/Vue/React/JSX源码）
                pass
            for f in files:
                if f.endswith('.js') and not f.endswith('.map') and not f.startswith('_'):
                    js_files.append(os.path.join(root, f))

    if not js_files:
        # 即使没有JS文件也继续——_page.html中可能有SSR内联JSON
        pass

    all_creds = []
    for fp in js_files:
        all_creds.extend(scan_file(fp))

    # 扫描SSR内联JSON（_page.html中的__NUXT__/__NEXT_DATA__等）
    if os.path.isdir(js_dump_dir):
        ssr_creds = scan_html_inline_json(js_dump_dir)
        all_creds.extend(ssr_creds)

    # 扫描运行时API路径组装（array.join/atob/GraphQL等）
    if os.path.isdir(js_dump_dir):
        runtime_creds = scan_runtime_api_paths(js_dump_dir)
        all_creds.extend(runtime_creds)

    # 扫描 WebAssembly 引用
    if os.path.isdir(js_dump_dir):
        wasm_creds = scan_wasm_refs(js_dump_dir)
        all_creds.extend(wasm_creds)

    # 扫描 Service Worker 注册与拦截
    if os.path.isdir(js_dump_dir):
        sw_creds = scan_service_worker(js_dump_dir)
        all_creds.extend(sw_creds)

    # 扫描 ESM CDN 依赖引用
    if os.path.isdir(js_dump_dir):
        cdn_creds = scan_esm_cdn_refs(js_dump_dir)
        all_creds.extend(cdn_creds)

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

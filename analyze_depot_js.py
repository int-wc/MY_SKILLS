import urllib.request
import ssl
import re

ctx = ssl.create_default_context()

url = 'https://depot.oocllogistics.com/js/index.e6566849.js'
req = urllib.request.Request(url)
req.add_header('User-Agent', 'Mozilla/5.0')
resp = urllib.request.urlopen(req, timeout=15, context=ctx)
text = resp.read().decode('utf-8', errors='replace')
print(f'Size: {len(text)} bytes')

# Look for baseURL, API URL config
base_urls = re.findall(r'baseURL["\']?\s*[:=]\s*["\']([^"\']+)["\']', text)
if base_urls:
    print(f'baseURLs: {base_urls[:5]}')

# Look for internal hosts/IPs
ips = re.findall(r'(?:localhost|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})', text)
if ips:
    print(f'Internal IPs/hosts: {list(set(ips))[:10]}')

# Check for comments with sensitive keywords
lines = text.split('\n')
sensitive_comments = []
for line in lines:
    if '//' in line:
        comment = line.split('//')[1]
        for kw in ['todo', 'fixme', 'hack', 'bug', 'password', 'secret', 'key', 'token', 'api', 'debug']:
            if kw in comment.lower():
                sensitive_comments.append((kw, comment.strip()[:100]))
                break
if sensitive_comments:
    print(f'Sensitive comments ({len(sensitive_comments)}):')
    for kw, c in sensitive_comments[:10]:
        print(f'  [{kw}] {c}')

# Look for all paths
all_paths = re.findall(r'["\'](/[a-zA-Z0-9_/]+)["\']', text)
api_paths = [p for p in all_paths if '/portal/' in p or '/api/' in p]
if api_paths:
    print(f'\nAdditional API paths: {sorted(set(api_paths))[:30]}')

# Look for version info
versions = re.findall(r'["\']version["\']\s*[=:]\s*["\']([^"\']+)["\']', text)
print(f'\nVersions: {versions[:5]}')

# Look for internal URLs
internal_urls = re.findall(r'["\'](https?://[^"\']*oocl[^"\']*)["\']', text)
if internal_urls:
    print(f'\nInternal OOCL URLs: {list(set(internal_urls))[:15]}')

# Look for any hardcoded credentials
creds = re.findall(r'["\'](password|pwd|passwd|secret|apiKey|apikey)["\']\s*[=:]\s*["\']([^"\']{4,})["\']', text)
if creds:
    print(f'\nHardcoded credentials: {creds[:10]}')
else:
    print('\nNo hardcoded credentials found')

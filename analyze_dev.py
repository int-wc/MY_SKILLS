import urllib.request
import ssl
import re

ctx = ssl.create_default_context()

# Download the main app JS
url = 'https://developer.cargosmart.com/static/js/app.eb389e04.js'
print(f'Downloading {url}...')
try:
    req = urllib.request.Request(url)
    resp = urllib.request.urlopen(req, timeout=15, context=ctx)
    body = resp.read()
    print(f'Size: {len(body)} bytes')
    text = body.decode('utf-8', errors='replace')

    # Look for API paths
    apis = re.findall(r'(?:https?://[^/]+|)(/api/[a-zA-Z0-9_/.-]+)', text)
    if apis:
        print(f'\nAPI paths ({len(apis)} total, {len(set(apis))} unique):')
        for a in sorted(set(apis))[:30]:
            print(f'  {a}')

    # Look for URLs
    urls = re.findall(r'"(https?://[^"]+)"', text)
    if urls:
        print(f'\nExternal URLs:')
        for u in sorted(set(urls))[:20]:
            print(f'  {u}')

    # Look for version strings
    versions = re.findall(r'version["\']\s*:\s*["\']([^"\']+)["\']', text)
    if versions:
        print(f'\nVersions: {versions[:10]}')

    # Check for any interesting patterns
    if 'graphql' in text.lower():
        print('\nGraphQL endpoint found!')
    if 'swagger' in text.lower():
        print('Swagger/OpenAPI reference found!')
    if 'rest' in text.lower():
        print('REST API references found!')
    if 'api' in text.lower():
        print('API references found!')

except Exception as e:
    print(f'Error: {e}')

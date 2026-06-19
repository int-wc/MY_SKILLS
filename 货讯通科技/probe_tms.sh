#!/bin/bash
# Probe TMS (tms.weikayun.com)
for path in \
  /cas/login \
  /cas/ \
  /cas/logout \
  /cas/status \
  /cas/info \
  /api \
  /api/login \
  /api/v1 \
  /api/v1/user \
  /api/v1/users \
  /api/v1/order \
  /api/v1/tms \
  /api/v1/config \
  /api/v1/transport \
  /login \
  /admin \
  /admin/ \
  /swagger-ui.html \
  /v2/api-docs \
  /v3/api-docs \
  /doc.html \
  /actuator \
  /actuator/health \
  /actuator/info \
  /actuator/env \
  /.env \
  /.git/HEAD \
  /robots.txt; do
  result=$(curl -s -o /dev/null -w "%{http_code}:%{size_download}" --connect-timeout 10 -k "https://tms.weikayun.com${path}" 2>/dev/null)
  code=$(echo "$result" | cut -d: -f1)
  size=$(echo "$result" | cut -d: -f2)
  if [ "$code" != "302" ] && [ "$size" -gt "0" ]; then
    echo "[$code] [$size b] https://tms.weikayun.com${path}"
    if [ "$code" = "200" ] && [ "$size" -lt 50000 ]; then
      curl -s --connect-timeout 10 -k "https://tms.weikayun.com${path}" 2>/dev/null | head -c 200
      echo ""
    fi
  fi
done

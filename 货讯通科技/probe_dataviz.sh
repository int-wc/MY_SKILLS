#!/bin/bash
# Probe DataViz (dataviz.weikayun.com)
for path in \
  /api \
  /api/ \
  /api/v1 \
  /api/v1/user \
  /api/v1/users \
  /api/v1/config \
  /api/v1/data \
  /api/v1/visual \
  /api/v1/dashboard \
  /api/v1/login \
  /api/v1/auth \
  /api/v1/info \
  /api/v1/status \
  /api/user \
  /api/auth \
  /api/login \
  /api/health \
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
  /actuator/heapdump \
  /api-docs \
  /single \
  /single/ \
  /single/api \
  /.env \
  /.git/HEAD \
  /robots.txt \
  /login; do
  result=$(curl -s -o /dev/null -w "%{http_code}:%{size_download}" --connect-timeout 10 -k "https://dataviz.weikayun.com${path}" 2>/dev/null)
  code=$(echo "$result" | cut -d: -f1)
  size=$(echo "$result" | cut -d: -f2)
  if [ "$code" != "302" ] && [ "$size" -gt "0" ]; then
    echo "[$code] [$size b] https://dataviz.weikayun.com${path}"
    if [ "$code" = "200" ] && [ "$size" -lt 50000 ]; then
      curl -s --connect-timeout 10 -k "https://dataviz.weikayun.com${path}" 2>/dev/null | head -c 200
      echo ""
    fi
  fi
done

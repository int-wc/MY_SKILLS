#!/bin/bash
BASE="$1"
PATHS=("/actuator" "/actuator/env" "/actuator/health" "/actuator/info" "/actuator/beans" "/actuator/mappings" "/actuator/heapdump" "/swagger-ui.html" "/v2/api-docs" "/v3/api-docs" "/doc.html" "/.env" "/.git/config" "/robots.txt" "/WEB-INF/web.xml")
for path in "${PATHS[@]}"; do
  resp=$(curl -sk -o /dev/null -w "HTTP %{http_code} Size: %{size_download}" --connect-timeout 8 --max-time 10 "${BASE}${path}" 2>&1)
  echo "${path} -> ${resp}"
done

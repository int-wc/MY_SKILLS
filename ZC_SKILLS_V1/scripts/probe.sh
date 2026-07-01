#!/bin/bash
# Probe a target with multiple paths
BASE="$1"
shift
for path in "$@"; do
  resp=$(curl -s -o /dev/null -w "HTTP %{http_code} Size: %{size_download}" --connect-timeout 8 --max-time 10 "${BASE}${path}" 2>&1)
  echo "${path} -> ${resp}"
done

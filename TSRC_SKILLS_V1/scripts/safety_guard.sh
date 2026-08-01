#!/usr/bin/env bash
# ============================================================
# SAFETY GUARD — 渗透测试安全护栏（执行层硬拦截）
# 作用：拦截对"删除/修改"类 API 发送的任何请求
# 用法：作为 Claude Code PreToolUse hook（matcher: Bash）
# stdin : {"tool_name":"Bash","tool_input":{"command":"..."},"session_id":"..."}
# stdout: {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"block|allow","permissionDecisionReason":"..."}}
# ============================================================
set -u

# 读取 hook 输入
input="$(cat)"
cmd="$(printf '%s' "$input" | python3 -c 'import sys,json
try:
    d=json.load(sys.stdin)
    ti=d.get("tool_input",{})
    print(ti.get("command","") if isinstance(ti,dict) else "")
except Exception:
    print("")' 2>/dev/null)"

# 只检查网络请求类命令；其余放行
case "$cmd" in
  *curl*|*wget*|*Invoke-WebRequest*|*requests.*|*httpx*|*http.request*|*http.client*|*aiohttp*|*urllib.request*)
    ;;
  *)
    printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}'
    exit 0
    ;;
esac

block() {
  printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"block","permissionDecisionReason":"%s"}}' "$1"
  exit 0
}

allow() {
  printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}'
  exit 0
}

# ---- 规则1: HTTP 方法级拦截 (curl) ----
# curl -X DELETE / -X 'DELETE' / --request PUT / --request=PATCH / -X PATCH / -X MERGE / -X TRACE
if printf '%s' "$cmd" | grep -qiE 'curl[^|;]*(\s-X\s+["'"'"']?(DELETE|PUT|PATCH|MERGE|TRACE)["'"'"']?|\s--request[= ]+["'"'"']?(DELETE|PUT|PATCH|MERGE|TRACE)["'"'"']?)'; then
  block "🚨 SAFETY GUARD: 拦截删除/修改类HTTP方法(DELETE/PUT/PATCH)。仅允许只读探测(GET/只读POST)。"
fi

# ---- 规则2: Python requests/httpx/aiohttp 库写方法拦截 ----
if printf '%s' "$cmd" | grep -qiE '(requests|httpx|aiohttp)\.(delete|put|patch)\s*\('; then
  block "🚨 SAFETY GUARD: 拦截 requests/httpx delete/put/patch 删除/修改请求。仅允许只读请求。"
fi

# ---- 规则3: 修改/删除语义端点 + 提交数据方法组合 ----
# 路径含删除/修改语义 且 方法会提交数据(POST/PUT/PATCH/DELETE/form)
if printf '%s' "$cmd" | grep -qiE '/(delete|remove|drop|clear|truncate|update|edit|modify|save|write|upload|import|move|copy|publish|archive|deactivate|ban|block|reset|rebuild|sync|merge|approve|reject|submit|close)(/|_|\.|\?|$)' && \
   printf '%s' "$cmd" | grep -qiE '(-d |--data|--data-raw|-X POST|--request POST|-X PUT|-X PATCH|-X DELETE|--form|-F )'; then
  block "🚨 SAFETY GUARD: 检测到修改/删除语义端点 + 数据提交方法，已拦截该请求。"
fi

# ---- 规则4: 请求体/参数中的删除/修改指令 ----
# JSON/参数含 "delete":true, action="delete", method=DELETE, ?delete=true, action=update,
# form body: -d 'action=update' / op=delete / method=POST + write verb 等
if printf '%s' "$cmd" | grep -qiE '("[a-zA-Z_]*(delete|remove|drop|clear|update|modify|save|edit|approve|reject|submit)[a-zA-Z_]*"\s*[:=]\s*(true|1|yes)|("(action|operation|method|type|op)"\s*:\s*"(delete|remove|drop|update|modify|edit|approve|reject|submit)")|method\s*[=:]\s*["'"'"']?(DELETE|PUT|PATCH)|[?&](delete|remove|drop|clear|update|modify|save|edit)\s*=\s*(true|1|yes)|[?&]action\s*=\s*(delete|remove|drop|update|modify|save|edit|approve|reject|submit)|(^|[^a-zA-Z0-9])(action|op|operation|cmd|command|do|type)\s*=\s*(delete|remove|drop|update|modify|edit|save|approve|reject|submit|destroy|truncate)\b)'; then
  block "🚨 SAFETY GUARD: 请求体/参数含删除修改操作指令，已拦截。"
fi

# ---- 规则5: 强写操作端点（即使 GET 也拦截，防止无防护 GET 型写接口）----
# 含 deleteById/removeById/updateById、/delete[/?] 等写语义路径
if printf '%s' "$cmd" | grep -qiE '(deleteById|removeById|updateById|deleteAll|removeAll|doDelete|doUpdate|/truncate|/drop[/?]|/delete[/?]|/remove[/?]|/clear[/?]|/update[/?]|/modify[/?]|/save[/?]|/approve[/?]|/reject[/?])'; then
  block "🚨 SAFETY GUARD: 目标端点含删除/修改写操作语义，已拦截。"
fi

# ---- 规则5b: camelCase 写动词端点（区分大小写，避免误拦 deleted/deletion 只读页面）----
# /deleteUser /updateProfile /removeItem 等驼峰写接口，但 /deleted /deletion 等名词页放行
if printf '%s' "$cmd" | grep -qE '(/[a-zA-Z]*?(delete|remove|update|modify|save|drop|clear)[A-Z][a-zA-Z]+)' && \
   ! printf '%s' "$cmd" | grep -qiE '/(deleted|deletion|update\.html|delete\.html)' ; then
  block "🚨 SAFETY GUARD: 目标端点含删除/修改写操作语义，已拦截。"
fi

# ---- 规则6: POST 到"具体资源条目"路径（纯 IDOR 修改签名，无 action 词也拦）----
# 经典越权写：POST /api/order/999，body 无 action= 指令、路径不含 update/save 等词。
# 特征：POST(或携带请求体) + 路径含 /<资源名>/<数字ID>（条目而非集合）。
# 排除只读性质端点（login/search/detail/download 等，双保险防误拦）。
if printf '%s' "$cmd" | grep -qiE '(\s-X\s+POST|\s--request\s+POST|-d\b|--data\b|--data-raw\b|--form\b|-F\b|(requests|httpx)\.post\s*\()' && \
   printf '%s' "$cmd" | grep -qiE '/[a-zA-Z_][a-zA-Z0-9_.-]*/[0-9]+([^a-zA-Z0-9]|$)' && \
   ! printf '%s' "$cmd" | grep -qiE '/(login|auth|token|refresh|logout|search|query|list|check|verify|validate|captcha|code|download|export|swagger|api-docs|file|static|assets|public|health|version|detail|info|summary|read|get|find)([/?#]|$)' ; then
  block "🚨 SAFETY GUARD: POST 到具体资源条目路径(如 /api/order/999)，疑似纯IDOR修改/状态变更。请用GET只读对比差异或记录为疑似漏洞不验证。"
fi

allow
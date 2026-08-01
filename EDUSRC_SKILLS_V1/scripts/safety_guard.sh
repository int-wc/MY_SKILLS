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
# curl -X DELETE / --request PUT / -X PATCH / -X MERGE / -X TRACE
if printf '%s' "$cmd" | grep -qiE 'curl[^|;]*(\s-X\s+(DELETE|PUT|PATCH|MERGE|TRACE)|\s--request[= ]+(DELETE|PUT|PATCH|MERGE|TRACE))'; then
  block "🚨 SAFETY GUARD: 拦截删除/修改类HTTP方法(DELETE/PUT/PATCH)。仅允许只读探测(GET/只读POST)。"
fi

# ---- 规则2: Python requests 库方法拦截 ----
if printf '%s' "$cmd" | grep -qiE 'requests\.(delete|put|patch)\s*\('; then
  block "🚨 SAFETY GUARD: 拦截 requests.delete/put/patch 删除/修改请求。仅允许只读请求。"
fi

# ---- 规则3: 修改/删除语义端点 + 提交数据方法组合 ----
# 路径含删除/修改语义 且 方法会提交数据(POST/PUT/PATCH/DELETE/form)
if printf '%s' "$cmd" | grep -qiE '/(delete|remove|drop|clear|truncate|update|edit|modify|save|write|upload|import|move|copy|publish|archive|deactivate|ban|block|reset|rebuild|sync|merge|approve|reject|submit|close)(/|_|\.|\?|$)' && \
   printf '%s' "$cmd" | grep -qiE '(-d |--data|--data-raw|-X POST|--request POST|-X PUT|-X PATCH|-X DELETE|--form|-F )'; then
  block "🚨 SAFETY GUARD: 检测到修改/删除语义端点 + 数据提交方法，已拦截该请求。"
fi

# ---- 规则4: 请求体/参数中的删除/修改指令 ----
# JSON/参数含 "delete":true, action="delete", method=DELETE 等
if printf '%s' "$cmd" | grep -qiE '("[a-zA-Z_]*(delete|remove|drop|clear|update|modify|save|edit|approve|reject|submit)[a-zA-Z_]*"\s*[:=]\s*(true|1|yes)|("(action|operation|method|type|op)"\s*:\s*"(delete|remove|drop|update|modify|edit|approve|reject|submit)")|method\s*[=:]\s*["'"'"']?(DELETE|PUT|PATCH))'; then
  block "🚨 SAFETY GUARD: 请求体/参数含删除修改操作指令，已拦截。"
fi

# ---- 规则5: 强写操作端点（即使 GET 也拦截，防止无防护 GET 型写接口）----
if printf '%s' "$cmd" | grep -qiE '(deleteById|removeById|updateById|deleteAll|removeAll|doDelete|doUpdate|/truncate|/drop[/?]|/delete[/?]|/remove[/?]|/clear[/?]|/update[/?]|/modify[/?]|/save[/?]|/approve[/?]|/reject[/?])'; then
  block "🚨 SAFETY GUARD: 目标端点含删除/修改写操作语义，已拦截。"
fi

allow
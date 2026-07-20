const fs = require('fs')
const path = require('path')

const TEXT_EXTS = new Set(['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.vue', '.json', '.map'])
const MAX_FILES = 900
const MAX_FILE_BYTES = 2500000

const RISK_RULES = [
  { type: 'SSRF', re: /^(url|uri|href|src|link|target|redirect|redirect_url|callback|callback_url|returnUrl|next|file_url|image_url|download_url|proxy|fetchUrl)$/i },
  { type: 'path_traversal_file_read', re: /^(file|file_path|filepath|path|filename|download|template_path|resource|key|objectKey)$/i },
  { type: 'XSS_SSTI_template_injection', re: /^(content|html|markdown|template|body|message|render|text|description)$/i },
  { type: 'IDOR_horizontal_privilege', re: /^(id|uid|userId|user_id|accountId|account_id|orderId|order_id|studentId|student_id|companyId|company_id|appId|app_id|tenantId|tenant_id)$/i },
  { type: 'batch_traversal_unauth_data', re: /^(page|limit|offset|pageSize|page_size|pageNum|page_num|size|start|end|cursor)$/i },
  { type: 'business_logic_tamper', re: /^(price|amount|quantity|discount|coupon|total|balance|score|points|role|status)$/i },
  { type: 'XXE_deserialization_injection', re: /^(xml|json|data|document|payload|config|yaml|yml)$/i },
  { type: 'token_auth_bypass', re: /^(token|accessToken|access_token|sessionKey|session_key|apiKey|api_key|secret|sign|signature)$/i },
  { type: 'upload_write_or_SSRF', re: /^(image|video|media|attachment|upload|avatar|photo|fileList|files)$/i },
  { type: 'RCE_expression_injection', re: /^(command|cmd|exec|shell|code|expression|script|sql|query)$/i },
]

function escRe(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

function walkFiles(root) {
  const out = []
  const stack = [root]
  while (stack.length && out.length < MAX_FILES) {
    const cur = stack.pop()
    let st
    try { st = fs.statSync(cur) } catch (_) { continue }
    if (st.isDirectory()) {
      let names = []
      try { names = fs.readdirSync(cur) } catch (_) { continue }
      for (const n of names) {
        if (n === 'node_modules' || n === '.git') continue
        stack.push(path.join(cur, n))
      }
      continue
    }
    if (!st.isFile() || st.size > MAX_FILE_BYTES) continue
    const ext = path.extname(cur)
    if (TEXT_EXTS.has(ext)) out.push(cur)
  }
  return out
}

function readText(file) {
  try { return fs.readFileSync(file, 'utf8') } catch (_) { return '' }
}

function inferRiskTypes(params, endpoint) {
  const risks = new Set()
  for (const p of params || []) {
    if (!p || p === 'unresolved') continue
    for (const r of RISK_RULES) {
      if (r.re.test(p)) risks.add(r.type)
    }
  }
  if (risks.size === 0) {
    const e = String(endpoint || '').toLowerCase()
    if (/(fetch|proxy|image|color|avatar|media|preview|convert|download|render)/.test(e)) risks.add('resource_processing_review')
    if (/(upload|file|import|export|attachment)/.test(e)) risks.add('file_surface_review')
    if (/(list|search|page|query|detail|info)/.test(e)) risks.add('data_access_review')
  }
  return Array.from(risks)
}

function cleanKey(k) {
  if (!k) return null
  const out = String(k).trim().replace(/^['"`]|['"`]$/g, '')
  if (!out || out.length > 80 || ['http', 'https'].includes(out)) return null
  return out
}

function addMany(set, values) {
  for (const v of values || []) {
    const k = cleanKey(v)
    if (k) set.add(k)
  }
}

function splitTopLevel(src, sep = ',') {
  const parts = []
  let cur = ''
  let depth = 0
  let quote = null
  let escaped = false
  for (const ch of String(src || '')) {
    cur += ch
    if (quote) {
      if (escaped) {
        escaped = false
      } else if (ch === '\\') {
        escaped = true
      } else if (ch === quote) {
        quote = null
      }
      continue
    }
    if (ch === '"' || ch === "'" || ch === '`') {
      quote = ch
    } else if ('({['.includes(ch)) {
      depth += 1
    } else if (')}]'.includes(ch)) {
      depth = Math.max(0, depth - 1)
    } else if (ch === sep && depth === 0) {
      parts.push(cur.slice(0, -1))
      cur = ''
    }
  }
  if (cur.trim()) parts.push(cur)
  return parts
}

function takeBalanced(text, openIndex, openCh = '(', closeCh = ')', maxLen = 8000) {
  let depth = 0
  let quote = null
  let escaped = false
  for (let i = openIndex; i < text.length && i - openIndex <= maxLen; i += 1) {
    const ch = text[i]
    if (quote) {
      if (escaped) {
        escaped = false
      } else if (ch === '\\') {
        escaped = true
      } else if (ch === quote) {
        quote = null
      }
      continue
    }
    if (ch === '"' || ch === "'" || ch === '`') {
      quote = ch
    } else if (ch === openCh) {
      depth += 1
    } else if (ch === closeCh) {
      depth -= 1
      if (depth === 0) return { body: text.slice(openIndex + 1, i), end: i }
    }
  }
  return null
}

function extractObjectInfo(src) {
  const keys = new Set()
  const spreads = new Set()
  for (const raw of splitTopLevel(src)) {
    const part = raw.trim()
    if (!part) continue
    const spread = part.match(/^\.\.\.\s*([A-Za-z_$][\w$]*)/)
    if (spread) {
      spreads.add(spread[1])
      continue
    }
    const quoted = part.match(/^['"`]([^'"`]+)['"`]\s*:/)
    const named = part.match(/^([A-Za-z_$][\w$-]*)\s*:/)
    const shorthand = part.match(/^([A-Za-z_$][\w$]*)$/)
    const destructured = part.match(/^([A-Za-z_$][\w$]*)\s*=\s*[^,]+$/)
    const key = cleanKey((quoted && quoted[1]) || (named && named[1]) || (shorthand && shorthand[1]) || (destructured && destructured[1]))
    if (key) keys.add(key)
  }
  return { keys: Array.from(keys), spreads: Array.from(spreads) }
}

function extractObjectKeys(src) {
  return extractObjectInfo(src).keys
}

function buildObjectVarMap(text) {
  const map = new Map()
  const re = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*\{/g
  let m
  while ((m = re.exec(text))) {
    const openIndex = text.indexOf('{', m.index)
    const bal = takeBalanced(text, openIndex, '{', '}', 5000)
    if (!bal) continue
    const info = extractObjectInfo(bal.body)
    map.set(m[1], {
      keys: info.keys,
      spreads: info.spreads,
      evidence: `${m[1]}={${bal.body.slice(0, 220)}}`.replace(/\s+/g, ' '),
    })
    re.lastIndex = bal.end + 1
  }
  return map
}

function resolveObjectVar(name, varMap, seen = new Set()) {
  if (!name || seen.has(name) || !varMap.has(name)) return { keys: [], evidence: [] }
  seen.add(name)
  const item = varMap.get(name)
  const keys = new Set(item.keys || [])
  const evidence = item.evidence ? [item.evidence] : []
  for (const spread of item.spreads || []) {
    const nested = resolveObjectVar(spread, varMap, seen)
    addMany(keys, nested.keys)
    evidence.push(...nested.evidence)
  }
  return { keys: Array.from(keys), evidence: evidence.slice(0, 3) }
}

function extractParamsFromExpression(expr, varMap) {
  const src = String(expr || '').trim()
  if (!src) return { keys: [], evidence: [], unresolved_reason: 'empty_argument' }
  if (src.startsWith('{')) {
    const bal = takeBalanced(src, 0, '{', '}', 5000)
    if (!bal) return { keys: [], evidence: [], unresolved_reason: 'unbalanced_object_literal' }
    const info = extractObjectInfo(bal.body)
    const keys = new Set(info.keys)
    const evidence = [`{${bal.body.slice(0, 220)}}`.replace(/\s+/g, ' ')]
    for (const spread of info.spreads) {
      const nested = resolveObjectVar(spread, varMap)
      addMany(keys, nested.keys)
      evidence.push(...nested.evidence)
    }
    return { keys: Array.from(keys), evidence: evidence.slice(0, 4), unresolved_reason: keys.size ? null : 'object_without_static_keys' }
  }
  const stringify = src.match(/JSON\.stringify\s*\(\s*(\{[\s\S]*\}|[A-Za-z_$][\w$]*)\s*\)/)
  if (stringify) return extractParamsFromExpression(stringify[1], varMap)
  const ident = src.match(/^([A-Za-z_$][\w$]*)$/)
  if (ident) {
    const resolved = resolveObjectVar(ident[1], varMap)
    return {
      keys: resolved.keys,
      evidence: resolved.evidence,
      unresolved_reason: resolved.keys.length ? null : 'identifier_argument_not_resolved',
    }
  }
  return { keys: [], evidence: [], unresolved_reason: 'dynamic_expression' }
}

function extractObjectPropertyExpression(objExpr, prop) {
  const src = String(objExpr || '').trim()
  if (!src.startsWith('{')) return ''
  const bal = takeBalanced(src, 0, '{', '}', 6000)
  if (!bal) return ''
  for (const raw of splitTopLevel(bal.body)) {
    const part = raw.trim()
    const m = part.match(/^([A-Za-z_$][\w$-]*|['"`][^'"`]+['"`])\s*:\s*([\s\S]*)$/)
    if (!m) continue
    const key = cleanKey(m[1])
    if (key === prop) return m[2].trim()
  }
  return ''
}

function extractFormalParamHints(src) {
  const keys = new Set()
  const objectFormal = String(src || '').match(/\(\s*\{([^)]{1,800})\}\s*\)\s*=>/)
  if (objectFormal) addMany(keys, extractObjectKeys(objectFormal[1]))
  return Array.from(keys)
}

function extractExportNames(text, wrapper) {
  const names = new Set()
  if (!wrapper) return []
  const exportAs = new RegExp(`\\b${escRe(wrapper)}\\s+as\\s+([A-Za-z_$][\\w$]*)`, 'g')
  let em
  while ((em = exportAs.exec(text))) names.add(em[1])
  // 压缩包里的 a/n/t 等短变量名跨文件误报极高；跨文件只信任显式 alias。
  const directExport = new RegExp(`export\\s+(?:const|let|var|function)\\s+${escRe(wrapper)}\\b`)
  if (directExport.test(text) && (wrapper.length >= 3 || wrapper.startsWith('$'))) names.add(wrapper)
  return Array.from(names)
}

function findCalleeCalls(text, callee) {
  const calls = []
  const re = new RegExp(`\\b${escRe(callee)}\\s*\\(`, 'g')
  let m
  while ((m = re.exec(text))) {
    const openIndex = text.indexOf('(', m.index)
    const bal = takeBalanced(text, openIndex, '(', ')', 6000)
    if (!bal) continue
    calls.push({ args: bal.body, start: m.index, end: bal.end })
    re.lastIndex = bal.end + 1
  }
  return calls
}

function addEndpointDef(defs, seen, def) {
  if (!def || !def.endpoint || def.endpoint.startsWith('http') || def.endpoint.length > 240) return
  const key = `${def.method || 'GET_OR_UNKNOWN'} ${def.endpoint} ${def.definition_file || ''} ${def.wrapper || ''} ${def.source_kind || ''} ${def.evidence || ''}`
  if (seen.has(key)) return
  seen.add(key)
  defs.push(def)
}

function parseApiDefs(files, root) {
  const defs = []
  const seen = new Set()
  for (const file of files) {
    const text = readText(file)
    if (!text) continue
    const rel = path.relative(root, file)
    const varMap = buildObjectVarMap(text)
    const urlRe = /url\s*:\s*['"`]([^'"`]*\/[^'"`]*)['"`]/g
    let m
    while ((m = urlRe.exec(text))) {
      const endpoint = m[1]
      if (!endpoint || endpoint.startsWith('http') || endpoint.length > 240) continue
      const start = Math.max(0, m.index - 500)
      const end = Math.min(text.length, m.index + 900)
      const win = text.slice(start, end)
      const before = text.slice(Math.max(0, m.index - 350), m.index)
      const methodM = win.match(/method\s*:\s*['"`]([A-Za-z]+)['"`]/)
      const method = methodM ? methodM[1].toUpperCase() : 'GET_OR_UNKNOWN'
      let wrapper = null
      let arg = null
      const wrapperMatches = Array.from(before.matchAll(/(?:(?:const|let|var)\s+|,\s*)([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\(([^)]{0,500})\)|([A-Za-z_$][\w$]*))?/g))
      if (wrapperMatches.length) {
        const last = wrapperMatches[wrapperMatches.length - 1]
        wrapper = last[1]
        arg = (last[2] || last[3] || '').trim() || null
      }
      const carrier = arg && new RegExp(`(?:req|data|params|body)\\s*:\\s*${escRe(arg)}\\b`).test(win) ? arg : null
      const inlineParams = new Set()
      const wrapperParamHints = new Set()
      addMany(wrapperParamHints, extractFormalParamHints(before))
      if (carrier) {
        const bodyProp = win.match(new RegExp(`(?:req|data|params|body)\\s*:\\s*(${escRe(carrier)}|\\{[\\s\\S]{0,1200}?\\})`))
        if (bodyProp) addMany(inlineParams, extractParamsFromExpression(bodyProp[1], varMap).keys)
      }
      addEndpointDef(defs, seen, {
        endpoint,
        method,
        wrapper,
        request_carrier: carrier || arg || null,
        exported_names: extractExportNames(text, wrapper),
        definition_file: rel,
        inline_request_params: Array.from(inlineParams),
        wrapper_param_hints: Array.from(wrapperParamHints),
        source_kind: 'config_url_property',
        evidence: win.slice(0, 260).replace(/\s+/g, ' '),
      })
    }

    const methodCallRe = /\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?)\s*\.\s*(get|post|put|patch|delete)\s*\(\s*['"`]([^'"`]*\/[^'"`]*)['"`]/g
    while ((m = methodCallRe.exec(text))) {
      const method = m[2].toUpperCase()
      const endpoint = m[3]
      if (!endpoint || endpoint.startsWith('http') || endpoint.length > 240) continue
      const openIndex = text.indexOf('(', m.index)
      const bal = takeBalanced(text, openIndex, '(', ')', 5000)
      if (!bal) continue
      const args = splitTopLevel(bal.body)
      const bodyCandidate = method === 'GET' || method === 'DELETE' ? args[1] : args[1]
      const params = extractParamsFromExpression(bodyCandidate, varMap)
      addEndpointDef(defs, seen, {
        endpoint,
        method,
        wrapper: null,
        request_carrier: null,
        exported_names: [],
        definition_file: rel,
        caller_files: [rel],
        inline_request_params: params.keys,
        wrapper_param_hints: [],
        source_kind: 'method_direct_call',
        unresolved_reason: params.unresolved_reason,
        evidence: text.slice(m.index, Math.min(text.length, bal.end + 1)).slice(0, 300).replace(/\s+/g, ' '),
      })
      methodCallRe.lastIndex = bal.end + 1
    }

    const fetchRe = /\bfetch\s*\(\s*['"`]([^'"`]*\/[^'"`]*)['"`]/g
    while ((m = fetchRe.exec(text))) {
      const endpoint = m[1]
      if (!endpoint || endpoint.startsWith('http') || endpoint.length > 240) continue
      const openIndex = text.indexOf('(', m.index)
      const bal = takeBalanced(text, openIndex, '(', ')', 6000)
      if (!bal) continue
      const args = splitTopLevel(bal.body)
      const options = args[1] || ''
      const methodM = options.match(/method\s*:\s*['"`]([A-Za-z]+)['"`]/)
      const bodyExpr = extractObjectPropertyExpression(options, 'body')
      const params = extractParamsFromExpression(bodyExpr, varMap)
      addEndpointDef(defs, seen, {
        endpoint,
        method: methodM ? methodM[1].toUpperCase() : 'GET_OR_UNKNOWN',
        wrapper: null,
        request_carrier: null,
        exported_names: [],
        definition_file: rel,
        caller_files: [rel],
        inline_request_params: params.keys,
        wrapper_param_hints: [],
        source_kind: 'fetch_direct_call',
        unresolved_reason: params.unresolved_reason,
        evidence: text.slice(m.index, Math.min(text.length, bal.end + 1)).slice(0, 300).replace(/\s+/g, ' '),
      })
      fetchRe.lastIndex = bal.end + 1
    }
  }
  return defs
}

function collectCalleesForFile(text, def, sameFile) {
  const callees = new Set()
  if (sameFile && def.wrapper) callees.add(def.wrapper)
  for (const exported of def.exported_names || []) {
    if (!exported) continue
    if (sameFile) callees.add(exported)
    const importRe = new RegExp(`(?:^|[^\\w$])${escRe(exported)}(?:\\s+as\\s+([A-Za-z_$][\\w$]*))?`, 'g')
    let im
    while ((im = importRe.exec(text))) callees.add(im[1] || exported)
  }
  return Array.from(callees)
}

function extractResponseParamHints(text, endpoint) {
  const hints = new Set()
  const banned = /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|http|https|url|api|error|message|msg|code|data|success|false|true)$/i
  const rel = String(endpoint || '').replace(/^https?:\/\/[^/]+/, '')
  const names = [rel, rel.split('/').filter(Boolean).pop()].filter(Boolean)
  for (const name of names) {
    const idx = text.indexOf(name)
    if (idx < 0) continue
    const start = Math.max(0, idx - 1000)
    const end = Math.min(text.length, idx + 2000)
    const win = text.slice(start, end)
    if (!/(缺少|不能为空|必填|required|missing|invalid|param|field|参数|字段|body|payload)/i.test(win)) continue
    const quoted = /(?:缺少|missing|required|invalid|参数|字段|field|param|不能为空|必填)[^'"`]{0,60}['"`]([A-Za-z_$][\w$]{1,60})['"`]|['"`]([A-Za-z_$][\w$]{1,60})['"`][^'"`]{0,60}(?:不能为空|必填|required|missing|invalid|参数|字段)/gi
    let m
    while ((m = quoted.exec(win))) hints.add(m[1] || m[2])
    const words = /(?:缺少|missing|required|invalid|参数|字段|field|param)\s*[:：=]?\s*([A-Za-z_$][\w$]{1,60})/gi
    while ((m = words.exec(win))) hints.add(m[1])
  }
  return Array.from(hints).filter(k => !banned.test(k)).slice(0, 20)
}

function mergeEntryParams(entry, params, strategy, evidence) {
  if (!params || !params.length) return
  for (const p of params) if (!entry.request_params.includes(p)) entry.request_params.push(p)
  entry.unresolved = false
  if (strategy && !entry.resolution_strategies.includes(strategy)) entry.resolution_strategies.push(strategy)
  for (const ev of evidence || []) {
    if (ev && entry.evidence.length < 8) entry.evidence.push(String(ev).replace(/\s+/g, ' ').slice(0, 320))
  }
}

function parseCallSites(files, root, defs) {
  const entries = new Map()
  for (const def of defs) {
    const key = `${def.method} ${def.endpoint} ${def.definition_file} ${def.wrapper || ''}`
    const inlineParams = Array.from(new Set([...(def.inline_request_params || []), ...(def.wrapper_param_hints || [])])).filter(Boolean)
    const unresolved = inlineParams.length === 0
    entries.set(key, {
      target: null,
      endpoint: def.endpoint,
      method: def.method,
      wrapper: def.wrapper || null,
      exported_names: def.exported_names || [],
      request_carrier: def.request_carrier || null,
      request_params: inlineParams,
      wrapper_param_hints: def.wrapper_param_hints || [],
      response_param_hints: [],
      unresolved,
      unresolved_reasons: unresolved ? [def.unresolved_reason || 'no_static_request_params_yet'] : [],
      resolution_strategies: inlineParams.length ? [def.source_kind || 'definition_inline'] : [],
      source_kind: def.source_kind || 'unknown',
      definition_file: def.definition_file,
      caller_files: def.caller_files || [],
      evidence: [def.evidence].filter(Boolean),
      risk_types: [],
      response_probe_required: unresolved,
    })
  }

  for (const file of files) {
    const text = readText(file)
    if (!text) continue
    const rel = path.relative(root, file)
    const varMap = buildObjectVarMap(text)
    for (const def of defs) {
      const key = `${def.method} ${def.endpoint} ${def.definition_file} ${def.wrapper || ''}`
      const entry = entries.get(key)
      const callees = collectCalleesForFile(text, def, rel === def.definition_file)
      for (const callee of callees) {
        if (!callee) continue
        for (const cm of findCalleeCalls(text, callee)) {
          const args = splitTopLevel(cm.args)
          const firstArg = args[0] || ''
          const params = extractParamsFromExpression(firstArg, varMap)
          mergeEntryParams(entry, params.keys, firstArg.trim().startsWith('{') ? 'callsite_object_literal' : 'callsite_variable_resolution', params.evidence)
          if (params.unresolved_reason && !entry.unresolved_reasons.includes(params.unresolved_reason)) entry.unresolved_reasons.push(params.unresolved_reason)
          if (!entry.caller_files.includes(rel)) entry.caller_files.push(rel)
          const sample = `${callee}(${cm.args.slice(0, 260)})`.replace(/\s+/g, ' ')
          if (sample && entry.evidence.length < 4) entry.evidence.push(sample)
        }
      }
    }
  }

  for (const file of files) {
    const text = readText(file)
    if (!text) continue
    for (const e of entries.values()) {
      if (!e.unresolved && !e.response_probe_required) continue
      const hints = extractResponseParamHints(text, e.endpoint)
      if (!hints.length) continue
      e.response_param_hints = Array.from(new Set([...(e.response_param_hints || []), ...hints])).slice(0, 20)
      mergeEntryParams(e, hints, 'local_response_hint', [`response hints: ${hints.join(', ')}`])
    }
  }

  for (const e of entries.values()) {
    if (e.request_params.length === 0) e.request_params = ['unresolved']
    e.risk_types = inferRiskTypes(e.request_params, e.endpoint)
    e.response_probe_required = e.unresolved || e.request_params.includes('unresolved')
    if (!e.unresolved && e.request_params.includes('unresolved')) {
      e.request_params = e.request_params.filter(p => p !== 'unresolved')
    }
    if (e.unresolved_reasons.length === 0 && e.response_probe_required) e.unresolved_reasons.push('needs_empty_body_or_error_response_probe')
  }
  return Array.from(entries.values())
}

function mergeCallSites(existing, additions) {
  const map = new Map()
  for (const item of [...(existing || []), ...(additions || [])]) {
    if (!item || !item.endpoint) continue
    const key = `${item.method || ''} ${item.endpoint} ${item.definition_file || ''} ${item.wrapper || ''}`
    const cur = map.get(key) || {
      ...item,
      request_params: [],
      caller_files: [],
      evidence: [],
      risk_types: [],
      exported_names: [],
      wrapper_param_hints: [],
      response_param_hints: [],
      unresolved_reasons: [],
      resolution_strategies: [],
    }
    for (const field of ['request_params', 'caller_files', 'evidence', 'risk_types', 'exported_names', 'wrapper_param_hints', 'response_param_hints', 'unresolved_reasons', 'resolution_strategies']) {
      const values = Array.isArray(item[field]) ? item[field] : []
      cur[field] = Array.from(new Set([...(cur[field] || []), ...values])).filter(Boolean).slice(0, field === 'evidence' ? 6 : 80)
    }
    if (cur.request_params.length > 1 && cur.request_params.includes('unresolved')) {
      cur.request_params = cur.request_params.filter(p => p !== 'unresolved')
    }
    cur.unresolved = cur.request_params.length === 0 || cur.request_params.includes('unresolved')
    cur.response_probe_required = cur.unresolved || item.response_probe_required === true
    cur.source_kind = cur.source_kind || item.source_kind || 'unknown'
    map.set(key, cur)
  }
  return Array.from(map.values()).slice(0, 500)
}

function extractFromDump(dumpDir, target) {
  if (!dumpDir || !fs.existsSync(dumpDir)) return []
  const files = walkFiles(dumpDir)
  const defs = parseApiDefs(files, dumpDir)
  const entries = parseCallSites(files, dumpDir, defs)
  return entries.map(e => ({ ...e, target: target || null }))
}

function summarize(entries, maxItems = 60) {
  const rows = (entries || []).slice(0, maxItems).map(e => {
    const params = (e.request_params || []).join(', ')
    const risks = (e.risk_types || []).join(', ')
    const callers = (e.caller_files || []).slice(0, 3).join(', ')
    const strategies = (e.resolution_strategies || []).slice(0, 3).join(',')
    const unresolved = e.response_probe_required ? ` probe=${(e.unresolved_reasons || []).slice(0, 2).join('|') || 'required'}` : ''
    return `${e.method || 'GET_OR_UNKNOWN'} ${e.endpoint} params={${params}} risks=[${risks}] via=[${strategies || e.source_kind || 'unknown'}] callers=[${callers || e.definition_file || 'definition_only'}]${unresolved}`
  })
  return rows.length ? rows.join('\n') : '（无结构化 call-site 参数）'
}

module.exports = {
  extractFromDump,
  mergeCallSites,
  summarize,
  inferRiskTypes,
}

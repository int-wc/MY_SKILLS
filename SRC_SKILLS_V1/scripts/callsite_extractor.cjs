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

function extractObjectKeys(src) {
  const keys = new Set()
  const keyRe = /(?:^|[,{]\s*)([A-Za-z_$][\w$-]*)\s*:/g
  let m
  while ((m = keyRe.exec(src))) {
    const k = m[1]
    if (!['http', 'https'].includes(k)) keys.add(k)
  }
  return Array.from(keys)
}

function parseApiDefs(files, root) {
  const defs = []
  for (const file of files) {
    const text = readText(file)
    if (!text) continue
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
      const wrapperMatches = Array.from(before.matchAll(/(?:(?:const|let|var)\s+|,\s*)([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(?\s*([A-Za-z_$][\w$]*)?/g))
      if (wrapperMatches.length) {
        const last = wrapperMatches[wrapperMatches.length - 1]
        wrapper = last[1]
        arg = last[2] || null
      }
      const carrier = arg && new RegExp(`(?:req|data|params|body)\\s*:\\s*${escRe(arg)}\\b`).test(win) ? arg : null
      const exportNames = []
      if (wrapper) {
        const exportAs = new RegExp(`\\b${escRe(wrapper)}\\s+as\\s+([A-Za-z_$][\\w$]*)`, 'g')
        let em
        while ((em = exportAs.exec(text))) exportNames.push(em[1])
      }
      defs.push({
        endpoint,
        method,
        wrapper,
        request_carrier: carrier || arg || null,
        exported_names: Array.from(new Set(exportNames)),
        definition_file: path.relative(root, file),
        evidence: win.slice(0, 260).replace(/\s+/g, ' '),
      })
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
    const importRe = new RegExp(`\\b${escRe(exported)}(?:\\s+as\\s+([A-Za-z_$][\\w$]*))?`, 'g')
    let im
    while ((im = importRe.exec(text))) callees.add(im[1] || exported)
  }
  return Array.from(callees)
}

function parseCallSites(files, root, defs) {
  const entries = new Map()
  for (const def of defs) {
    const key = `${def.method} ${def.endpoint} ${def.definition_file} ${def.wrapper || ''}`
    entries.set(key, {
      target: null,
      endpoint: def.endpoint,
      method: def.method,
      wrapper: def.wrapper || null,
      exported_names: def.exported_names || [],
      request_carrier: def.request_carrier || null,
      request_params: [],
      unresolved: true,
      definition_file: def.definition_file,
      caller_files: [],
      evidence: [def.evidence].filter(Boolean),
      risk_types: [],
      response_probe_required: true,
    })
  }

  for (const file of files) {
    const text = readText(file)
    if (!text) continue
    const rel = path.relative(root, file)
    for (const def of defs) {
      const key = `${def.method} ${def.endpoint} ${def.definition_file} ${def.wrapper || ''}`
      const entry = entries.get(key)
      const callees = collectCalleesForFile(text, def, rel === def.definition_file)
      for (const callee of callees) {
        if (!callee) continue
        const callRe = new RegExp(`\\b${escRe(callee)}\\s*\\(\\s*\\{([\\s\\S]{0,1200}?)\\}\\s*\\)`, 'g')
        let cm
        while ((cm = callRe.exec(text))) {
          const params = extractObjectKeys(cm[1])
          if (params.length) {
            entry.unresolved = false
            for (const p of params) if (!entry.request_params.includes(p)) entry.request_params.push(p)
          }
          if (!entry.caller_files.includes(rel)) entry.caller_files.push(rel)
          const sample = `${callee}({${cm[1].slice(0, 240)}})`.replace(/\s+/g, ' ')
          if (sample && entry.evidence.length < 4) entry.evidence.push(sample)
        }
      }
    }
  }

  for (const e of entries.values()) {
    if (e.request_params.length === 0) e.request_params = ['unresolved']
    e.risk_types = inferRiskTypes(e.request_params, e.endpoint)
    e.response_probe_required = e.unresolved || e.request_params.includes('unresolved')
  }
  return Array.from(entries.values())
}

function mergeCallSites(existing, additions) {
  const map = new Map()
  for (const item of [...(existing || []), ...(additions || [])]) {
    if (!item || !item.endpoint) continue
    const key = `${item.method || ''} ${item.endpoint} ${item.definition_file || ''} ${item.wrapper || ''}`
    const cur = map.get(key) || { ...item, request_params: [], caller_files: [], evidence: [], risk_types: [], exported_names: [] }
    for (const field of ['request_params', 'caller_files', 'evidence', 'risk_types', 'exported_names']) {
      const values = Array.isArray(item[field]) ? item[field] : []
      cur[field] = Array.from(new Set([...(cur[field] || []), ...values])).filter(Boolean).slice(0, field === 'evidence' ? 6 : 80)
    }
    cur.unresolved = cur.request_params.length === 0 || cur.request_params.includes('unresolved')
    cur.response_probe_required = cur.unresolved || item.response_probe_required === true
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
    return `${e.method || 'GET_OR_UNKNOWN'} ${e.endpoint} params={${params}} risks=[${risks}] callers=[${callers || e.definition_file || 'definition_only'}]`
  })
  return rows.length ? rows.join('\n') : '（无结构化 call-site 参数）'
}

module.exports = {
  extractFromDump,
  mergeCallSites,
  summarize,
  inferRiskTypes,
}

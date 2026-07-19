// SRC_SKILLS_V1 - 八阶段全流程 Workflow 编排
// 使用: Workflow({scriptPath: '...', args: {company: '货讯通科技', mode: 'full'}})
// mode: 'full' | 'phase3' (跳过资产发现和深度分析，直接挖洞) | 'phase5' (直接出报告) | 'url' (指定单个URL)

export const meta = {
  name: 'src-full-scan',
  description: '补天SRC全流程：资产发现→深度分析→漏洞挖掘→验证→资产标记→报告→自审→提交',
  phases: [
    { title: '资产发现', detail: '读取厂商信息 + 解析Hunter资产 + 目标分类标记' },
    { title: '深度分析', detail: 'JS逆向 + API枚举 + 组件审计 + 开源系统识别' },
    { title: '漏洞挖掘', detail: '按优先级测试所有攻击面 + 框架识别线索指向测试' },
    { title: '验证取证', detail: '复现确认 + 证据收集' },
    { title: '资产标记', detail: '标记已测资产状态并存储，避免重复测试' },
    { title: '报告编写', detail: 'MD+HTML双格式输出' },
    { title: '自审', detail: '格式检查 + 重复检测' },
    { title: '提交准备', detail: '最终清单 + 提交排序' },
  ],
}

// ============================================================
// 解析参数
// ============================================================
const SRC_BASE = '/home/my/butiansrc/Exclusive_SRC'

// P2: 共享字典 — SRC↔ZC 互相合并积累的API模式（合并而非覆盖，减少竞态丢失）
try {
  const fs = require('fs')
  const skillsRoot = '/home/my/.claude/skills'
  const pairs = [
    ['SRC_SKILLS_V1', 'ZC_SKILLS_V1'],
    ['ZC_SKILLS_V1', 'SRC_SKILLS_V1'],
  ]
  for (const [from, to] of pairs) {
    const src = `${skillsRoot}/${from}/references/api_patterns.json`
    const dst = `${skillsRoot}/${to}/references/api_patterns.json`
    if (fs.existsSync(src)) {
      if (fs.existsSync(dst)) {
        // 合并模式：读取双方，合并数组再写回
        try {
          const srcData = JSON.parse(fs.readFileSync(src, 'utf8'))
          const dstData = JSON.parse(fs.readFileSync(dst, 'utf8'))
          // 合并 common_endpoints
          const mergedEndpoints = [...new Set([...(srcData.common_endpoints || []), ...(dstData.common_endpoints || [])])]
          // 合并 path_segments
          const mergedSegments = [...new Set([...(srcData.path_segments || []), ...(dstData.path_segments || [])])]
          // 合并 api_prefixes（保留较大 count）
          const mergedPrefixes = { ...(dstData.api_prefixes || {}) }
          for (const [k, v] of Object.entries(srcData.api_prefixes || {})) {
            mergedPrefixes[k] = (mergedPrefixes[k] || 0) + (v.count || v)
          }
          dstData.common_endpoints = mergedEndpoints
          dstData.path_segments = mergedSegments
          dstData.api_prefixes = mergedPrefixes
          fs.writeFileSync(dst, JSON.stringify(dstData, null, 2))
          log(`  📚 字典合并: ${from} ↔ ${to} (${mergedEndpoints.length} endpoints, ${mergedSegments.length} segments)`)
        } catch(e) {
          // 合并失败回退到覆盖
          fs.copyFileSync(src, dst)
          log(`  📚 字典覆盖(合并失败): ${from} → ${to}`)
        }
      } else {
        fs.copyFileSync(src, dst)
        log(`  📚 字典初始同步: ${from} → ${to}`)
      }
    }
  }
} catch(e) { /* 字典共享非关键，失败不影响主流程 */ }
const SKILL_SCRIPTS = '/home/my/.claude/skills/SRC_SKILLS_V1/scripts'

// ============================================================
// 真实 User-Agent 配置 — 所有 curl 请求使用浏览器UA
// ============================================================
const REAL_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
const UA_FLAG = `-H 'User-Agent: ${REAL_UA}'`
const UA_INSTR = `⚠️ **User-Agent 硬性规则：所有 curl 命令必须添加 -H 'User-Agent: ${REAL_UA}'（或等效的浏览器UA），禁止使用默认 curl User-Agent，否则会被WAF/反爬识别拦截。同时添加 Accept-Language: zh-CN,zh;q=0.9 和 Accept: */* 头。**`

// 动态检测 dirsearch 字典路径（兼容不同 Python 版本）
const DIRSEARCH_DICT = (() => {
  const pyVers = ['python3.14', 'python3.13', 'python3.12', 'python3.11', 'python3.10']
  for (const v of pyVers) {
    try { const p = `/home/my/.local/lib/${v}/site-packages/dirsearch/db/dicc.txt`; if (require('fs').existsSync(p)) return p } catch(_) {}
  }
  return '/home/my/.local/lib/python3.14/site-packages/dirsearch/db/dicc.txt'
})()

let companyName, mode, singleUrl
if (typeof args === 'string') {
  // 修复：Workflow 工具传递的对象 args 可能被序列化为 JSON 字符串
  // 先尝试 JSON 解析，成功则作为对象处理，否则当做公司名
  let parsed = null
  try { parsed = JSON.parse(args) } catch (_) {}
  if (parsed && typeof parsed === 'object') {
    companyName = parsed.company || null
    mode = parsed.mode || 'full'
    singleUrl = parsed.url || null
  } else {
    companyName = args
    mode = 'full'
  }
} else if (typeof args === 'object' && args) {
  companyName = args.company || null
  mode = args.mode || 'full'
  singleUrl = args.url || null
  if (mode === 'url' && !singleUrl) {
    log('⚠️ 单URL模式需指定 url 参数，如: {mode: "url", url: "https://target:8080"}')
    return { error: 'need_url', message: '请指定url参数' }
  }
} else {
  companyName = null
  mode = 'full'
}

// 未指定公司名时从URL自动提取
let _isAutoCompany = false
if (!companyName && singleUrl) {
  _isAutoCompany = true
  try {
    const u = new URL(singleUrl)
    companyName = u.hostname
  } catch (_) {
    companyName = singleUrl.replace(/^https?:\/\//, '').replace(/[:\/?#].*$/, '')
  }
  // IP/localhost作为公司名会导致Phase1误读、目录创建异常、报告文件名含IP
  // 统一替换为 _CLI_TARGET_ 作为路径标识
  if (/^\d+\.\d+\.\d+\.\d+$/.test(companyName) || companyName === 'localhost') {
    companyName = '_CLI_TARGET_'
    log(`ℹ️ URL域名解析为IP/本地地址，统一使用 "_CLI_TARGET_" 作为目录标识`)
  } else {
    log(`ℹ️ 未指定公司名，自动使用URL域名作为公司标识`)
  }
}

// 目标进度追踪
const progress = {
  company: companyName || '未指定',
  phase1: '⬜',
  phase2: '⬜',
  phase3: '⬜',
  phase4: '⬜',
  phase5: '⬜',
  phase6: '⬜',
  phase7: '⬜',
  phase8: '⬜',
  findings_count: 0,
  reports_count: 0,
}

function showProgress() {
  log('')
  log('╔══════════════════════════════════════════════════════════════╗')
  log(`║  目标进度表 — ${(progress.company || '').padEnd(30)} ║`)
  log('╠══════════════════════════════════════════════════════════════╣')
  log('║  ①资产发现  ②深度分析  ③挖洞     ④验证     ⑤标记     ⑥报告     ⑦自审     ⑧提交  ║')
  log(`║    ${progress.phase1}       ${progress.phase2}       ${progress.phase3}       ${progress.phase4}       ${progress.phase5}       ${progress.phase6}       ${progress.phase7}       ${progress.phase8}    ║`)
  log(`║  发现: ${String(progress.findings_count).padEnd(4)}  |  报告: ${String(progress.reports_count).padEnd(4)}                            ║`)
  log('╚══════════════════════════════════════════════════════════════╝')
  log('')
}

function markPhase(n, status) {
  progress[`phase${n}`] = status
}

// ============================================================
// 资产测试状态加载（避免重复测试）
// ============================================================
const trackerPath = `${SRC_BASE}/${companyName || 'unknown'}/asset_test_status.json`
const findingsPath = `${SRC_BASE}/${companyName || 'unknown'}/asset_findings.json`
let p0_tracker = null

if (companyName && !mode.startsWith('phase5')) {
  p0_tracker = await agent(
    `读取资产测试状态文件。
路径: ${trackerPath}
用Read工具读取该文件。
如果文件不存在（Read返回错误），返回空对象。
文件格式为JSON: {"assets": {"url": {"status": "已完全测试完毕|还未测试完毕|无法进行测试", ...}}}`,
    { schema: {
      type: 'object',
      properties: {
        exists: { type: 'boolean' },
        assets: {
          type: 'object',
          additionalProperties: {
            type: 'object',
            properties: {
              status: { type: 'string' },
              phases_tested: { type: 'array', items: { type: 'string' } },
              last_tested: { type: 'string' },
              notes: { type: 'string' },
            },
          },
        },
      },
      required: ['exists'],
    }, label: '📋 加载资产测试状态' }
  )
}

// E: TTL 过期检查 — 降级过期资产（基于字符串日期比较，避免new Date()被Workflow禁用）
// 日期优先级: args.today > args.date > 默认值
const _todayStr = args?.today || args?.date || '2026-07-20'
if (p0_tracker?.exists && p0_tracker?.assets) {
  const _todayParts = _todayStr.split('-').map(Number)
  const _todayDays = _todayParts[0]*365 + _todayParts[1]*30 + _todayParts[2]
  for (const [url, info] of Object.entries(p0_tracker.assets)) {
    const ttl = info.ttl_days || 30
    const lastTested = info.last_tested
    if (lastTested && (info.status === '已完全测试完毕' || info.status === '无法进行测试')) {
      try {
        const lp = lastTested.split('-').map(Number)
        if (lp.length === 3 && !isNaN(lp[0])) {
          const lastDays = lp[0]*365 + lp[1]*30 + lp[2]
          const daysSinceTest = _todayDays - lastDays
          if (daysSinceTest > ttl) {
            info.status = '还未测试完毕'
            info.reason = `TTL过期(${ttl}天，距上次测试${daysSinceTest}天)，自动降级`
            delete info.ttl_days
            log(`  ⏰ TTL过期: ${url} (${daysSinceTest}天前，已降级)`)
          }
        }
      } catch(e) { /* TTL计算失败不影响主流程 */ }
    }
  }
}

// 构建已测试资产URL集合
const p0_testedUrls = new Set()
if (p0_tracker?.exists && p0_tracker?.assets) {
  for (const [url, info] of Object.entries(p0_tracker.assets)) {
    if (info.status === '已完全测试完毕' || info.status === '无法进行测试') {
      p0_testedUrls.add(url)
    }
  }
  if (p0_testedUrls.size > 0) {
    log(`  已加载 ${p0_testedUrls.size} 个已完成/无法测试的资产，将跳过重复测试`)
  }
}

// ============================================================
// 测试维度跟踪器 — 记录每个资产完成了哪些测试
// ============================================================
// 适用维度: http_probe, unauth_test, weak_pass
//           dir_enum(手动), dirsearch_scan(全量), js_analysis
const dimTracker = {
  _data: {},
  ensure(url) {
    if (!this._data[url]) this._data[url] = { dims: {} }
    return this._data[url]
  },
  record(url, dim, status = 'done', meta) {
    this.ensure(url).dims[dim] = { status, ...(meta || {}) }
  },
  completed(url) {
    const e = this._data[url]
    return e ? Object.keys(e.dims).filter(d => e.dims[d].status === 'done') : []
  },
  judge(url, isWeb, hasLogin) {
    const e = this._data[url]
    if (!e) return '无法进行测试'
    const app = ['http_probe', 'unauth_test', 'dir_enum']
    if (isWeb) app.push('dirsearch_scan')
    if (hasLogin) app.push('weak_pass')
    const done = this.completed(url)
    const allDone = app.every(d => done.includes(d))
    if (allDone && done.length > 0) return '已完全测试完毕'
    if (done.length === 0) return '无法进行测试'
    return '还未测试完毕'
  },
  missing(url, isWeb, hasLogin) {
    const e = this._data[url]
    if (!e) return ['http_probe', 'unauth_test', 'dir_enum']
    const app = ['http_probe', 'unauth_test', 'dir_enum']
    if (isWeb) app.push('dirsearch_scan')
    if (hasLogin) app.push('weak_pass')
    const done = this.completed(url)
    return app.filter(d => !done.includes(d))
  },
  toJSON() { return this._data },
  load(data) {
    this._data = {}
    if (!data) return
    for (const [url, info] of Object.entries(data)) {
      if (info.dims) this._data[url] = { dims: info.dims }
    }
  },
}

// 从已有状态文件恢复已完成维度
if (p0_tracker?.exists && p0_tracker?.assets) {
  const restored = {}
  for (const [url, info] of Object.entries(p0_tracker.assets)) {
    if (info.phases_tested && info.phases_tested.length > 0) {
      restored[url] = { dims: {} }
      info.phases_tested.forEach(d => { restored[url].dims[d] = { status: 'done' } })
    }
  }
  dimTracker.load(restored)
}

// ============================================================
// Phase 1: 资产发现与目标识别
// ============================================================
phase('资产发现')

// Fix 4: phase5 模式跳过整个资产发现阶段
// 用let声明p1_assets，以便在phase5模式下跳过资产发现后仍可在更外层作用域使用
let p1_assets
if (mode.startsWith('phase5')) {
  log('[1/8] ⏭️ 跳过（用户指定报告模式）')
  markPhase(1, '⏭️')
  p1_assets = { company_name: companyName, priority_targets: [], all_urls: [] }
} else if (mode === 'url' && singleUrl) {
  log('[1/8] 🔗 单URL模式 — 跳过资产发现，直接测试')
  markPhase(1, '⏭️')
  p1_assets = {
    company_name: singleUrl,
    src_scope_summary: '用户指定URL',
    priority_targets: [{
      url: singleUrl, ip: '', port: 443, title: '',
      tags: ['[用户指定]'], priority: '最高', reason: '用户指定目标'
    }],
    all_urls: [singleUrl],
  }
  // 记录基础维度
  dimTracker.record(singleUrl, 'http_probe', 'done', { title: '' })
  progress.findings_count = 1
  showProgress()
} else if (!companyName) {
  // 无参数：列出公司并退出
  const listing = await agent(
    `列出 ${SRC_BASE}/ 目录下的所有公司目录（排除 .html/.json/.js 文件和隐藏目录），
    输出格式为每行一个 "N. 公司名"，最后统计总数。`,
    { label: '📋 列出可用厂商', phase: '资产发现' }
  )
  log('可用目标厂商:')
  log(listing || '（无法列出）')
  log('')
  log('使用方式: 在 Workflow args 中指定 company 参数')
  log('  例: Workflow({scriptPath: "...", args: {company: "理想汽车", mode: "full"}})')
  throw new Error('need_company: 请指定目标公司名')
  } else {

markPhase(1, '🔄')
log(`[1/8] 资产发现 — ${companyName}`)

p1_assets = await agent(
  `你是SRC漏洞挖掘专家，负责 "资产发现与目标识别" 阶段。
  目标厂商: ${companyName}

  请依次执行:

  1. 读取厂商信息
     - 目录: ${SRC_BASE}/${companyName}/
     - 查找并读取 *_Information.html（提取SRC范围、赏金规则、域名列表、禁止事项）
     - 查找并读取 VulnType.html（提取接受的漏洞类型和忽略清单）

  2. 解析Hunter资产数据
     - 目录: ${SRC_BASE}/${companyName}/hunter_info/
     - 读取所有CSV文件，CSV格式: IP,端口,域名,IP标签,url,网站标题,高危协议,协议,通讯协议,网站状态码,操作系统,备案单位,备案号,备案异常,国家,省份,市区,Web资产,运营商,注册机构,应用/组件,资产标签,探查时间
     - 按以下维度给资产打标签:
       · [范围内] — 域名在 Information.html 收录范围内
       · [新发现] — Hunter发现但不在已知列表的子域名
       · [非常见端口] — 非80/443
       · [管理后台] — 标题含"登录/管理/后台/admin/dashboard/运维/控制台"
       · [组件指纹] — 应用/组件列识别到具体版本
       · [境外资产] — 备案异常/境外IP/无备案号
     - 同一域名多端口做URL聚合去重

  3. **严格域名合法性过滤（必须执行，不可跳过）**
     ⚠️ 只保留**主域后缀在 Information.html 定义的 SRC 范围内**的资产。参考示例：
       合法主域: *.lixiang.com / *.chehejia.com / *.lixiangoa.com
       非法示例（必须全部剔除）:
       - 第三方镜像/代理: *.xxx.domain.name, *.xxx.internet.com, *.xxx.com.com, *.xxx.itotolink.com, *.xxx.783.com, *.xxx.ht.com
       - CDN/云代理: *.xxx.baidu-itm.com, *.xxx.hz.ali.com, *.xxx.www.router.cmiot.cn, *.xxx.www.xshotel.com
       - 仿冒/抢注域名: ah-lixiang.com, gz-lixiang.com.cn, lixiang.com.cn, cn-lixiang.com, lixiang.com.uz, *.khcc.site, *.ixem.ru
       - 扫描陷阱/蜜罐: www_lixiang_com.*（下划线格式域名）, lixiang_com_cn.*
       - 其它公司域名: *.wucai.com, *.chehejia.com.cn, *.gxjmxy.com, *.gfxy.com, *.anti-spam.org.cn
     - 过滤方法: 取 url 的域名，提取最后两级主域（如 lixiang.com, baidu-itm.com），不在 Information.html 声明的 SRC 主域内的全部剔除
     - 结合备案单位（"备案单位"列）交叉验证：备案单位为其他公司的资产剔除
     - 有疑问的资产标记到 reason 字段中说明判断依据

  4. **优先级排序输出**
     - 最高: [管理后台][境外资产]
     - 高: [范围内][新发现]
     - 中: [非常见端口][组件指纹]

5. **URL聚合去重**：同域名多端口→保留HTTP+HTTPS各一；同IP多域名→独立保留

  JSON输出格式:
  {
    "company_name": "公司名",
    "src_scope_summary": "SRC范围简述",
    "accepted_vuln_types": "接受的漏洞类型",
    "prohibited_items": "禁止事项",
    "category_breakdown": {
      "management": N, "new_discovery": N, "uncommon_port": N,
      "overseas": N, "component_fingerprint": N, "in_scope": N
    },
    "priority_targets": [
      {"url": "https://xxx", "ip": "x.x.x.x", "port": 443, "title": "xxx",
       "tags": ["[管理后台]"], "priority": "最高", "reason": "标题含"管理""}
    ],
    "all_urls": ["url1", "url2", ...]
  }`,
  { label: `📡 ${companyName} 资产分析`, schema: {
    type: 'object',
    properties: {
      company_name: { type: 'string' },
      src_scope_summary: { type: 'string' },
      accepted_vuln_types: { type: 'string' },
      prohibited_items: { type: 'string' },
      category_breakdown: { type: 'object' },
      priority_targets: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            url: { type: 'string' },
            ip: { type: 'string' },
            port: { type: 'number' },
            title: { type: 'string' },
            tags: { type: 'array', items: { type: 'string' } },
            priority: { type: 'string', enum: ['最高', '高', '中', '低'] },
            reason: { type: 'string' },
          },
          required: ['url', 'priority'],
        },
      },
      all_urls: { type: 'array', items: { type: 'string' } },
    },
    required: ['company_name', 'priority_targets'],
  }, phase: '资产发现' }
)

if (!p1_assets) {
  log('⚠️ 资产发现无返回，请检查目录是否存在或内容格式')
  markPhase(1, '❌')
  showProgress()
  throw new Error('资产发现失败')
}

// ============================================================
// 🔧 程序化域名合法性过滤（第二层防线）
// 剔除 agent 可能遗漏的非厂商资产
// ============================================================
const ILLEGAL_TLDS = [
  'domain.name', 'baidu-itm.com', 'internet.com', 'com.com', 'itotolink.com',
  'dfgoshine.com', 'tianshikeji.cn', 'china-elenice.com', 'xjdd.net',
  'caiwangxing.net', 'twyls.cn', 'a300wr.net', 'ali.com', 'yjhst.com.cn',
  '52fad.com', 'rqorrvtz.cn', 'jiaojiang.cn', 'xshotel.com',
  'router.cmiot.cn', 'ht.com', '783.com', 'chehejia.com.cn',
  'com.uz', 'khcc.site', 'cast508.com', 'anti-spam.org.cn', 'gxjmxy.com',
  'cn-lixiang.com', 'gfxy.com', 'toptrans.com', 'weidesen.net',
  'yuelong56.com', 'wucai.com', 'ah-lixiang.com', 'gz-lixiang.com.cn',
  'lixiang.com.cn', 'ixem.ru',
]

function isDomainLegit(url) {
  try {
    const domain = url.split('://')[1].split(':')[0].toLowerCase()
    // 扫描陷阱: 包含下划线（如 www_lixiang_com.xxx）
    if (domain.includes('_')) return false
    // 检查主域后缀是否在黑名单中
    for (const bad of ILLEGAL_TLDS) {
      if (domain.endsWith(bad) || domain === bad) return false
    }
    return true
  } catch (_) { return false }
}

if (p1_assets?.priority_targets) {
  const before = p1_assets.priority_targets.length
  p1_assets.priority_targets = p1_assets.priority_targets.filter(t => isDomainLegit(t.url))
  const filtered = before - p1_assets.priority_targets.length
  if (filtered > 0) log(`  🛡️ 程序化域名过滤: 已剔除 ${filtered} 个非厂商资产（第三方代理/仿冒/扫描陷阱）`)
}
if (p1_assets?.all_urls) {
  const before2 = p1_assets.all_urls.length
  p1_assets.all_urls = p1_assets.all_urls.filter(u => isDomainLegit(u))
  const filtered2 = before2 - p1_assets.all_urls.length
  if (filtered2 > 0) log(`  🛡️ 程序化域名过滤: 已剔除 ${filtered2} 个非厂商URL`)
}
// ============================================================

// 过滤已测试资产（避免重复测试）
if (p0_testedUrls.size > 0 && p1_assets?.priority_targets) {
  const before = p1_assets.priority_targets.length
  p1_assets.priority_targets = p1_assets.priority_targets.filter(t => !p0_testedUrls.has(t.url))
  p1_assets.all_urls = (p1_assets.all_urls || []).filter(u => !p0_testedUrls.has(u))
  const filtered = before - p1_assets.priority_targets.length
  if (filtered > 0) log(`  已过滤 ${filtered} 个已测试资产，跳过重复测试`)
}

// 记录 Phase 1 资产维度
;(p1_assets.priority_targets || []).forEach(t => {
  const isLogin = (t.tags || []).includes('[管理后台]')
  dimTracker.record(t.url, 'http_probe', 'done', { title: t.title || '' })
  if (isLogin) dimTracker.record(t.url, 'weak_pass', 'pending')
})


markPhase(1, '✅')
progress.findings_count = p1_assets.priority_targets?.length || 0
showProgress()

// 打印资产摘要
const top3 = (p1_assets.priority_targets || []).slice(0, 3)
log(`  高优目标: ${p1_assets.priority_targets?.length || 0} 个`)
top3.forEach(t => log(`    ${t.priority} ${t.url} — ${t.reason || ''}`))
log(`  厂商范围: ${p1_assets.src_scope_summary || '未知'}`)
if (p1_assets.prohibited_items) log(`  禁止事项: ${p1_assets.prohibited_items}`)
  }

// ============================================================
// Phase 2: 深度分析
// ============================================================
phase('深度分析')

// 声明全局变量承载 Phase 2 JS分析结果，供 Phase 3 使用
let p2_discoveries_text = ''
// Phase 3/4 的发现结果也在外层声明，供后续阶段使用
let p3_unauth, p3_other, p3_quick, p3_dirsearch, p3_codeaudit, p4_dirscan, p4_verify
// 聚合发现数据，供 Phase 5 写入线索文件
let p3_findings_data = []

if (mode.startsWith('phase3') || mode.startsWith('phase5')) {
  log('[2/8] ⏭️ 跳过（用户指定模式）')
  markPhase(2, '⏭️')
} else {
  markPhase(2, '🔄')
  log(`[2/8] 深度分析 — ${companyName}`)

  // 从priority_targets + all_urls 合并取前10个去重，确保JS分析覆盖关键资产
  const p2_priority_urls = (p1_assets.priority_targets || []).map(t => t.url).filter(Boolean)
  const p2_all_urls = (p1_assets.all_urls || []).filter(u => !p2_priority_urls.includes(u))
  const targets = [...p2_priority_urls, ...p2_all_urls].slice(0, 10)

  if (targets.length === 0) {
    log('  ⚠️ 无高优先级目标可分析')
    markPhase(2, '⏭️')
  } else {
    let analyses = []
    try {
      analyses = await pipeline(
      targets,
      async (target) => {
        // === Step A: 下载JS（使用schema结构化输出，自动重试1次） ===
        let dlResult = null
        for (let _retry = 0; _retry < 2; _retry++) {
          dlResult = await agent(
            `执行以下命令:
python3 ${SKILL_SCRIPTS}/download_js.py "${target}" "${SRC_BASE}/${companyName}/js_dumps" --ua "${REAL_UA}"

将下载结果JSON原样输出，不要加任何额外文字。`,
            { label: `📥 下载JS: ${target}`, schema: {
              type: 'object',
              properties: {
                status: { type: 'string', enum: ['ok', 'unreachable'] },
                target: { type: 'string' },
                dump_dir: { type: 'string' },
                file_count: { type: 'number' },
                target_hash: { type: 'string' },
              },
              required: ['status', 'dump_dir', 'file_count', 'target_hash'],
            }, phase: '深度分析' }
          )
          if (dlResult && dlResult.file_count > 0) {
            log(`  📥 ${target}: 下载 ${dlResult.file_count} 个文件, hash=${dlResult.target_hash}`)
            break
          }
          if (_retry === 0) log(`  ⚠️ ${target}: JS下载0文件，重试...`)
          dlResult = null
        }

        const dump_dir = dlResult?.dump_dir || "${SRC_BASE}/${companyName}/js_dumps"
        const dl_file_count = dlResult?.file_count || 0
        const target_hash = dlResult?.target_hash || ''

        // 下载成功后执行枚举chunk和提取凭证
        if (dl_file_count > 0) {
          // === Step B: 枚举chunk补下 ===
          try {
            await agent(
              `python3 ${SKILL_SCRIPTS}/enumerate_chunks.py "${dump_dir}" "${target}" --ua "${REAL_UA}"
输出命令的stdout摘要。`,
              { label: `🧩 枚举chunk: ${target}`, phase: '深度分析' }
            )
          } catch(e) { log(`  ⚠️ chunk枚举跳过: ${e.message}`) }

          // === Step C: 提取凭证 ===
          try {
            const credsResult = await agent(
              `python3 ${SKILL_SCRIPTS}/extract_creds.py "${dump_dir}" --output "${dump_dir}/_credentials.json"
将最后一行的JSON结果原样输出。`,
              { label: `🔐 提取凭证: ${target}`, phase: '深度分析' }
            )
            const credLines = (credsResult || '').split('\\n').reverse()
            for (const l of credLines) {
              try {
                const parsed = JSON.parse(l.trim())
                if (parsed.credentials && parsed.credentials.length > 0) {
                  if (!globalThis.__p2_creds_json) globalThis.__p2_creds_json = '[]'
                  const existing = JSON.parse(globalThis.__p2_creds_json)
                  existing.push(...parsed.credentials)
                  globalThis.__p2_creds_json = JSON.stringify(existing)
                  log(`  🔐 ${target}: 提取 ${parsed.credentials.length} 条凭证`)
                }
                break
              } catch(_) { /* 不是JSON行，继续找下一行 */ }
            }
          } catch(e) { log(`  ⚠️ 凭证提取跳过: ${e.message}`) }

          // === 记录JS缓存目录信息 ===
          if (target_hash) {
            if (!globalThis.__p2_js_dirs_json) globalThis.__p2_js_dirs_json = '[]'
            const dirs = JSON.parse(globalThis.__p2_js_dirs_json)
            let hasRecon = false
            try { hasRecon = fs.existsSync(dump_dir + '/reconstructed') && fs.readdirSync(dump_dir + '/reconstructed').length > 0 } catch(_) {}
            dirs.push({
              target_hash: target_hash,
              dump_dir: dump_dir,
              js_count: dl_file_count,
              has_reconstructed: hasRecon,
              reconstructed_dir: hasRecon ? dump_dir + '/reconstructed' : null,
            })
            globalThis.__p2_js_dirs_json = JSON.stringify(dirs)
          }
        } else {
          log(`  ⚠️ ${target}: JS下载失败，跳过chunk枚举/凭证提取/分析`)
        }

        // === Step D: Agent 阅读本地文件 + 创造性分析 ===
        return await agent(
          `你是JS逆向和API发现专家，分析已下载到本地的JS文件: ${target}

    已下载文件目录: ${dump_dir}
    下载文件数: ${dl_file_count}

    **你的任务：用Read工具阅读本地JS文件，发挥创造性分析以下内容：**

    1. **定位API入口** — 查找 baseURL/API_HOST/API_BASE/gatewayUrl/serverUrl 等配置
    2. **路径模式提取** — 提取所有 "/xxx/yyy" 路径，关注非标准前缀 /gateway/ /dwr/ /sys/ /manage/ /crm/ /erp/
    3. **敏感信息提取** — 查找 AccessKey、SecretKey、JWT(eyJ...)、数据库连接串(mongodb://...)、内网IP、硬编码密码
    4. **鉴权方式识别** — Authorization: Bearer/Basic/X-TOKEN/Cookie/localStorage Token存放
    5. **凭证反思（关键思维环节）**:
       - 找到accessKey+secretKey → 哪个云服务？试枚举 OBS/S3/OSS Bucket
       - 找到JWT → 解码看user/role，试调API看是否越权
       - 找到API路径 → 功能命名推断数据敏感度
       - 找到内部域名 → 判断环境(dev/test/prod)

    **注意：**
    - 遇到混淆JS尝试识别混淆类型(webpack/jscrambler/_0x)
    - 本地文件分析完成后不要删除缓存文件，留作证据
    - 发挥第一性原理和创造性思维，不要局限于固定模式
    - 注意看Source Map还原出的文件: 检查是否有 reconstructed/ 目录（包含原始TS/Vue/React源码）
    - 注意检查 _page.html 中的内嵌JSON: 提取 __NUXT__(Nuxt.js)、__NEXT_DATA__(Next.js)、__INITIAL_STATE__(React)、__PRELOADED_STATE__ 等SSR注入数据，其中可能包含API路径、用户角色、权限配置
    - Source Map sourcesContent 深度分析: reconstructed/ 目录下还原出的源码中可能包含原始TypeScript/Vue/React/JSX，检查其中的API端点定义、配置对象、未公开功能接口
    - 检查 WebAssembly 引用: 扫描 .wasm 文件路径和 WebAssembly.instantiate 调用，wasm 中可能包含核心算法/密钥
    - 分析 Service Worker: 检查 sw.js 或 navigator.serviceWorker.register 中的请求拦截逻辑和缓存策略，可能改写/代理API请求
    - 注意 ESM CDN 依赖: 扫描 esm.sh/jsdelivr/unpkg 等CDN导入，CDN模块可能包含额外API端点

    ${UA_INSTR}`,
          { label: `🔬 分析: ${target}`, phase: '深度分析' }
        )
      },
      (result, target) => {
        return result
      }
    )
    } catch(e) {
      log(`  ⚠️ 管道分析执行异常: ${e.message || e}`)
    }

    log(`  完成 ${(analyses || []).filter(Boolean).length} 个目标的分析`)

    // 提取 JS 分析结果传给 Phase 3
    if (analyses && analyses.length > 0) {
      p2_discoveries_text = analyses.filter(Boolean)
        .map((a, i) => `【目标${i+1}JS分析结果】\n${a}`)
        .join('\n\n')
      // 记录JS分析维度
      targets.forEach(t => dimTracker.record(t, 'js_analysis', 'done'))
    }

    // ============================================================
    // Fix A+C: 提取鉴权凭证(结构化) + JS缓存目录捕获 → 供Phase3使用
    // ============================================================
    log('  🔐 提取JS中的鉴权凭证...')
    const p2_js_dump_base = "${SRC_BASE}/${companyName}/js_dumps"
    let p2_js_dirs = []
    let p2_credentials = []

    // 查找所有缓存子目录
    try {
      const findDirs = await agent(
        `python3 ${SKILL_SCRIPTS}/find_js_dumps.py "${p2_js_dump_base}"
输出最后一行为JSON结果。提取 dumps 数组。`,
        { label: '📂 查找JS缓存目录', phase: '深度分析' }
      )
      const dirLines = (findDirs || '').split('\\n').filter(l => l.trim().startsWith('{'))
      if (dirLines.length > 0) {
        const dirData = JSON.parse(dirLines[dirLines.length-1])
        p2_js_dirs = dirData.dumps || []
        log(`  📂 找到 ${p2_js_dirs.length} 个JS缓存目录`)

        // 对每个目录执行凭证提取
        for (const d of p2_js_dirs) {
          const credResult = await agent(
            `python3 ${SKILL_SCRIPTS}/extract_creds.py "${d.dump_dir}" --output "${d.dump_dir}/_credentials.json"
输出最后一行为JSON结果。提取 credentials 数组。`,
            { label: `🔐 提取: ${d.target_hash}`, phase: '深度分析' }
          )
          const credLines = (credResult || '').split('\\n').filter(l => l.trim().startsWith('{'))
          if (credLines.length > 0) {
            try {
              const credData = JSON.parse(credLines[credLines.length-1])
              const creds = credData.credentials || []
              if (creds.length > 0) {
                p2_credentials.push(...creds)
                log(`  🔐 ${d.target_hash}: 发现 ${creds.length} 条凭证`)
              }
            } catch(e) {}
          }
        }
      }
    } catch(e) {}

    //     // 凭证结构化已存入 globalThis.__p2_creds_json（供Phase 3直接引用）
    // 不再重复注入 p2_discoveries_text 避免过载
    if (globalThis.__p2_creds_json) {
      const credCount = JSON.parse(globalThis.__p2_creds_json).length
      if (credCount > 0) p2_discoveries_text += `\n【Phase 2提取了 ${credCount} 条结构化凭证，详见 globalThis.__p2_creds_json】\n`
    }
// JS缓存目录已存入 globalThis.__p2_js_dirs_json（供Phase 3直接使用）
    // 不再重复注入 p2_discoveries_text
    if (globalThis.__p2_js_dirs_json) {
      const dirCount = JSON.parse(globalThis.__p2_js_dirs_json).length
      if (dirCount > 0) p2_discoveries_text += `\n【Phase 2有 ${dirCount} 个JS缓存目录，详见 globalThis.__p2_js_dirs_json】\n`
    }

    // 【开源系统识别】— 识别快速开发框架/低代码平台（JeecgBoot, RuoYi, JeeSite 等）
    log('  🔍 执行开源系统识别（快速开发框架/低代码平台）...')
    const p2_oss = await agent(
      `你是快速开发框架识别专家，对 ${companyName} 的以下目标执行开源系统识别。
重点识别：JeecgBoot、RuoYi（若依）、JeeSite、Guns、TeaWeb、BladeX、Pear Admin、低代码平台/iPaas 等。

目标列表（前 20 个）:
${targets.slice(0, 20).map(function(t) { return '  ' + t.url }).join(String.fromCharCode(10))}

对每个目标执行以下步骤：

**Step 1: 指纹采集**
对每个目标执行 curl -sI -H 'User-Agent: ...' 获取响应头 + curl -s -H 'User-Agent: ...' 获取首页内容 + curl -sk -H 'User-Agent: ...' 获取 /swagger-ui.html /doc.html /v2/api-docs

**Step 2: 快速开发框架识别**

逐项检查以下框架特征（不限于此列表，可根据实际发现的特征推断）：

1. **JeecgBoot 系列**:
   - 响应头: X-Powered-By: JeecgBoot
   - 路径: /jeecg-boot/ 前缀, /sys/login, /sys/dict, /sys/permission
   - 特征: Swagger UI 常见 /doc.html (Knife4j), 登录页带有 Jeecg 标识
   - 默认口令: admin/admin123, admin/123456, jeecg/jeecg123
   - 特有攻击面: /sys/oss（Minio配置泄露）, /sys/file/upload, 代码生成器 /code, online 表单
   - 检测: curl -sk /jeecg-boot/sys/dict/list 是否返回字典数据

2. **RuoYi (若依)**:
   - 特征: 页面底部 "RuoYi" / "若依" 版权, 默认登录 /login
   - 路径: /ruoyi/, /prod-api/, /common/captcha, /system/user
   - 组合: Shiro + Thymeleaf, 响应头 Set-Cookie 含 JSESSIONID + rememberMe
   - 默认口令: admin/admin123
   - 特有攻击面: Shiro 反序列化(默认rememberMe密钥), /common/captcha 验证码绕过
   - 检测: curl -sk /prod-api/system/user/list 是否未授权

3. **JeeSite**:
   - 特征: Cookie 含 JeeSite, /js/a/login 路径
   - 默认口令: admin/admin123, admin/123456
   - 特有攻击面: $._csrf 鉴权可伪造, Beelt 模板注入, /sys/ 后台功能
   - 检测: curl -sk /js/a/login 看是否为 JeeSite 登录页

4. **Guns**:
   - 特征: Guns 标识, Beetl 模板, /guns-api/ 前缀
   - 默认口令: admin/admin
   - 特有攻击面: /guns-api/ 未授权, 代码生成器接口

5. **TeaWeb**:
   - 特征: Go 语言, TeaWeb 响应头, WebShell 管理特征
   - 特有攻击面: 默认配置泄露, 执行命令接口

6. **BladeX**:
   - 特征: /blade- 前缀, blade-auth 鉴权, blade-log
   - 默认口令: admin/admin
   - 特有攻击面: /blade- 未经授权, BladeX Redis 配置泄露

7. **Pear Admin / AntdV / Vue Admin / 其他前端模板**:
   - 判断是纯前端还是全栈（有API代理才是全栈）
   - 纯前端: 后端是单独接口服务，需找真实API地址
   - 全栈: 前后端一体，直接测试

8. **低代码平台 / iPaas**:
   - 特征: /designer/, /form/, /workflow/, /code/generate
   - 特有攻击面: 代码生成器未授权, 表单设计器RCE, 流程引擎越权

9. **悟空CRM / 72CMS / 企业系统**:
   - 特征: 版权信息, 特定文件路径
   - 默认口令: admin/admin123, admin/123456

**Step 2.5: 自主识别（不匹配已知框架时的通用检测 — 关键）**
如果以上预定义列表都不匹配，**不要直接返回"未发现"**。用以下通用线索自主判断是否疑似开源系统搭建：

针对每个目标，执行以下通用检测（**即使不在已知列表中也必须执行**）：

1. **路径结构探针** — curl 探测以下通用开源系统目录（任何命中都说明有第三方包依赖）:
   - 包管理: /vendor/phpunit, /vendor/composer, /node_modules/, /bower_components/
   - CMS特征: /plugins/, /modules/, /themes/, /uploads/, /sites/, /extensions/
   - 安装遗留: /install/, /setup/, /upgrade/, /wizard/, /migrations/
   - 源代码: /src/, /app/, /config/, /routes/, /database/, /resources/
   - 注意: 如果有多个命中（如 /vendor/ + /config/ + /routes/），高度疑似开源项目

2. **文件特征分析** — curl 获取关键配置文件:
   - curl -sk /robots.txt — 分析 Disallow 路径推断目录结构
   - curl -sk /sitemap.xml — 查看 URL 路径模式（模块名/控制器/动作）
   - curl -sk /package.json — 仅限 Node 项目，列出依赖推断框架
   - curl -sk /composer.json — 仅限 PHP 项目，列出依赖推断框架
   - curl -sk /.env — 如果能访问到说明环境配置完全泄露
   - 注意: 404/403 也是信息 — 说明该路径存在但被防护

3. **响应头/体特征**:
   - 响应头 X-Powered-By / Server / Set-Cookie — 注意异常值
   - 404 错误页的内容 — 默认 404 页风格可推断框架
   - 403 错误页 — 某些框架有默认 403 页（如 Spring Boot Whitelabel）
   - 响应体中的框架注释 — '<!-- /usr/local/... ->' 泄露路径

4. **Cookie 模式**:
   - PHPSESSID — PHP 通用
   - JSESSIONID — Java 通用
   - ASP.NET_SessionId — .NET
   - laravel_session — Laravel
   - csrftoken — Django

5. **前端框架推断**:
   - window.Vue / __VUE_DEVTOOLS__ — Vue.js
   - window.React / __REACT_DEVTOOLS__ — React
   - window.angular — Angular
   - Ant Design / ElementUI / Layui — UI 库

6. **综合判定**:
   - 命中 ≥3 条路径结构特征 + Cookie 模式匹配 → **高度疑似开源系统**
   - 命中 1-2 条 + 前端框架匹配 → **部分疑似**
   - 完全无特征 → **大概率自研**
   - **关键认知**：「疑似开源」本身就值得标记——即使不知道具体名称，也要输出所有线索供 Phase 3 参考

**Step 3: 特有攻击面清单（针对识别的框架，逐项检测）**
对每个已识别的框架，输出其特有攻击面及检测结果：

- 默认口令: 尝试框架默认账号密码登录
- Swagger 泄露: /swagger-ui.html, /doc.html, /v2/api-docs
- 代码生成器: /code/generate, /generator/, /gen/
- 文件上传: /file/upload, /common/upload, /sys/file/upload — 测试是否限制类型
- Minio/OSS: /sys/oss, /sys/minio — 是否泄露accessKey/secretKey
- 定时任务: /job/, /schedule/, /quartz/ — 未授权可操作
- Shiro 绕过: Shiro 过滤链是否有未收全的 /anon 端点
- Swagger 接口未授权: 从 swagger 文档中发现无需鉴权的API

**输出 JSON，每个目标一个条目。**

      ${UA_INSTR}
      ⚠️ **严格边界规则：仅使用 curl 探测目标URL。不要读取任何本地文件。不要提及或引用任何其他厂商的数据。**`,
      { label: '🔍 快速开发框架识别', schema: {
        type: 'object',
        properties: {
          findings: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                target: { type: 'string' },
                framework_name: { type: 'string', description: '识别的快速开发框架名称（已知则为具体名，未知则填"疑似开源系统"）' },
                version: { type: 'string', description: '版本号（如能识别）' },
                confidence: { type: 'string', enum: ['高', '中', '低'] },
                evidence: { type: 'string', description: '识别依据' },
                is_suspected_oss: { type: 'boolean', description: '是否通过自主识别判断为疑似开源系统（不依赖预定义列表）' },
                oss_clues: { type: 'array', items: { type: 'string' }, description: '自主识别线索列表（如：命中/vendor/、Cookie模式PHPSESSID、robots.txt暴露模块路径等）' },
                oss_verdict: { type: 'string', enum: ['高度疑似开源', '部分疑似', '大概率自研', '无法判断'], description: '自主识别综合判定结论' },
                default_credentials: { type: 'array', items: { type: 'string' }, description: '默认口令列表' },
                attack_surface: { type: 'array', items: { type: 'string' }, description: '特有攻击面清单' },
                notes: { type: 'string', description: '重点关注或挖掘建议' },
              },
              required: ['target', 'framework_name', 'confidence'],
            },
          },
        },
      }, phase: '深度分析' }
    )

    if (p2_oss && p2_oss.findings && p2_oss.findings.length > 0) {
      const known = p2_oss.findings.filter(f => !f.is_suspected_oss && f.framework_name !== '疑似开源系统')
      const suspected = p2_oss.findings.filter(f => f.is_suspected_oss || f.framework_name === '疑似开源系统')
      if (known.length > 0) log(`  快速开发框架识别: 发现 ${known.length} 个已知框架`)
      if (suspected.length > 0) log(`  🔍 自主识别: 发现 ${suspected.length} 个疑似开源系统`)
      p2_oss.findings.forEach(f => {
        if (f.is_suspected_oss || f.framework_name === '疑似开源系统') {
          const clues = f.oss_clues?.length ? ` | 线索: ${f.oss_clues.join(', ')}` : ''
          const verdict = f.oss_verdict ? ` [${f.oss_verdict}]` : ''
          log(`    🔍 疑似开源 @ ${f.target}${verdict}${clues}`)
        } else {
          const defCreds = f.default_credentials?.length ? ` | 默认口令: ${f.default_credentials.join(', ')}` : ''
          const attacks = f.attack_surface?.length ? ` | 攻击面: ${f.attack_surface.join(', ')}` : ''
          log(`    🏗️ ${f.framework_name}${f.version ? ' v'+f.version : ''} @ ${f.target} [${f.confidence}]${defCreds}${attacks}`)
        }
      })
      // 将识别结果纳入 Phase 3 上下文
      p2_discoveries_text += `\n\n【快速开发框架识别结果】\n` +
        p2_oss.findings.map(f => {
          if (f.is_suspected_oss || f.framework_name === '疑似开源系统') {
            return `${f.target}: 疑似开源系统 [${f.oss_verdict || '无法判断'}]
  线索: ${f.oss_clues?.join('; ') || 'N/A'}
  依据: ${f.evidence || 'N/A'}
  建议: ${f.notes || '深入探测是否存在通用漏洞/默认配置'}`
          }
          return `${f.target}: ${f.framework_name}${f.version ? ' v'+f.version : ''} [${f.confidence}]
  依据: ${f.evidence || 'N/A'}
  默认口令: ${f.default_credentials?.join(', ') || '未知'}
  特有攻击面: ${f.attack_surface?.join(', ') || '常规测试'}
  建议: ${f.notes || '按攻击面逐项测试'}`
        }).join('\n\n')
    } else {
      log('  识别完成: 未发现已知框架或疑似开源系统')
    }
    // == 开源系统识别结束 ==

    // ============================================================
    // Fix B: 结构化框架指纹 → 存入globalThis供Phase3使用
    // ============================================================
    if (p2_oss && p2_oss.findings && p2_oss.findings.length > 0) {
      const fwInfo = p2_oss.findings.map(f => ({
        target: f.target,
        framework_name: f.framework_name || '未知',
        confidence: f.confidence || '低',
        default_credentials: f.default_credentials || [],
        attack_surface: f.attack_surface || [],
        version: f.version || '',
      }))
      globalThis.__p2_fw_info = JSON.stringify(fwInfo)
      const hasCreds = fwInfo.filter(f => f.default_credentials.length > 0)
      if (hasCreds.length > 0) log(`  🔐 结构化框架指纹: ${hasCreds.length} 个框架有默认口令`)
    }
    // 同时保留已有文本注入（兼容旧prompt）
    // if (p2_oss && p2_oss.findings ... 原有代码保留

    // ============================================================
    // 2.5 dir_enum — 基于系统特征的智能路径枚举（智能fuzz）
    // 原理：根据已识别的框架 + JS发现的API路径格式，自动泛化fuzz
    // ============================================================
    log('  🔍 执行智能路径枚举（基于系统特征自动泛化fuzz）...')
    const P2_DICT_PATH = "${SKILL_SCRIPTS}/../references/api_patterns.json"

    // 对每个目标执行 smart_fuzz.py
    const fuzz_targets = targets.slice(0, 15)
    for (const ft of fuzz_targets) {
      const fuzz_out = "/tmp/smart_fuzz_" + companyName.replace(/[^a-zA-Z0-9]/g,'_') + "_" + ft.replace(/[^a-zA-Z0-9]/g,'_') + ".json"
      const fuzz_cmd = `python3 ${SKILL_SCRIPTS}/smart_fuzz.py "${ft}" --dict ${P2_DICT_PATH} --output ${fuzz_out} --ua "${REAL_UA}"`
      
      let fuzz_raw = null
      try {
        fuzz_raw = await agent(
          `执行fuzz:
${fuzz_cmd}
echo "---RESULT_JSON---"
cat ${fuzz_out}`,
        { label: `🤖 fuzz: ${ft}`, phase: '深度分析' }
        )
      } catch(e_fuzz) {
        log(`  ⚠️ fuzz agent调用失败: ${ft} - ${e_fuzz.message || e_fuzz}`)
        continue
      }

      // 解析并记录发现
      try {
        const jsonPart = (fuzz_raw || '').split('---RESULT_JSON---').pop()
        const fuzzData = JSON.parse(jsonPart.trim())
        const findings = fuzzData.findings || []
        // 存入全局变量供Phase3使用
        if (!globalThis.__p2_fuzz_findings) globalThis.__p2_fuzz_findings = []
        globalThis.__p2_fuzz_findings.push(...findings.map(f => ({...f, source_target: ft})))
        if (findings.length > 0) {
          log(`  ${ft}: 发现 ${findings.length} 个端点`)
          findings.forEach(f => log(`    [${f.status_code}] ${f.path}`))
        }
        // 更新字典本
        if (fuzzData.extracted_patterns || (fuzzData.new_endpoints && fuzzData.new_endpoints.length > 0)) {
          await agent(
            `python3 ${SKILL_SCRIPTS}/update_dict.py ${P2_DICT_PATH} --add ${fuzz_out}`,
            { label: '📚 更新字典', phase: '深度分析' }
          )
        }
      } catch(e) {
        log(`  ⚠️ fuzz结果解析失败: ${e.message}`)
      }
    }
    // 记录维度
    // 将fuzz发现注入p2_discoveries_text供Phase3使用
    if (globalThis.__p2_fuzz_findings && globalThis.__p2_fuzz_findings.length > 0) {
      const fuzzSummary = globalThis.__p2_fuzz_findings
        .filter(f => f.status_code === 200 || f.status_code === 401 || f.status_code === 403)
        .map(f => `  [${f.status_code}] ${f.endpoint} (${f.source_target})`)
        .join('\n')
      p2_discoveries_text += `\n\n【智能fuzz发现的潜在端点】\n${fuzzSummary}\n`
      log(`  🔄 ${globalThis.__p2_fuzz_findings.length} 个fuzz发现已注入Phase3上下文`)
    }
    // 仅在实际执行过fuzz的目标上记录dir_enum维度
    if (fuzz_targets.length > 0) {
      targets.forEach(t => dimTracker.record(t, 'dir_enum', 'done'))
    }
  // P0-2: 持久化 accumulated 状态到临时文件（避免agent崩溃丢失）
  try {
    const stateToSave = {
      creds: globalThis.__p2_creds_json || '[]',
      js_dirs: globalThis.__p2_js_dirs_json || '[]',
      fw_info: globalThis.__p2_fw_info || '[]',
    }
    require('fs').writeFileSync('/tmp/workflow_phase2_state.json', JSON.stringify(stateToSave))
  } catch(e) {}

  markPhase(2, '✅')
  showProgress()
  }
}

// ============================================================
// Phase 3: 漏洞挖掘
// 方法论参考: references/deep-mining-methodology.md
// 核心原则: 反思为主→迁跃为辅→分析为底→扩展为路
// ============================================================
phase('漏洞挖掘')

if (mode.startsWith('phase5')) {
  log('[3/8] ⏭️ 跳过（用户指定报告模式）')
  markPhase(3, '⏭️')
  markPhase(4, '⏭️')
} else {
  markPhase(3, '🔄')
  log(`[3/8] 漏洞挖掘 — ${companyName}`)

  // 所有高优目标全量测试（不限制top5，扩大覆盖到MAX_TARGETS个）
  // P3_TIER1_MAX 控制Tier 1全量测试的资产数上限
  // P3_TIER2_MAX 控制Tier 2全量测试的资产数上限（超出Tier 1的部分）
  const P3_TIER1_MAX = 50
  const P3_TIER2_MAX = 50
  const targets = (p1_assets.priority_targets || []).slice(0, P3_TIER1_MAX)

  // Tier 2: 剩余资产同样全量测试（非快速探测）
  const tier2_urls = [
    ...(p1_assets.priority_targets || []).slice(P3_TIER1_MAX).map(t => t.url),
    ...(p1_assets.all_urls || [])
  ].filter((v, i, a) => a.indexOf(v) === i)
   .filter(u => !targets.some(t => t.url === u))
   .slice(0, P3_TIER2_MAX)

  const allUrls = [...targets.map(t => t.url), ...tier2_urls]

  if (targets.length === 0 && allUrls.length === 0) {
    log('  ⚠️ 无可用测试目标')
    markPhase(3, '⏭️')
  } else {
    // ============================================================
    // 3.0 dirsearch — 基于字典的标准目录扫描
    // 原理：读取积累字典+通用字典，对目标做广度优先的路径爆破
    // ============================================================
    log('  📂 执行字典目录扫描 (dirsearch)...')
    const P3_DICT_PATH = "${SKILL_SCRIPTS}/../references/api_patterns.json"

    p3_dirsearch = await agent(
      `对 ${companyName} 执行 dirsearch 目录扫描（使用 dirsearch 内置字典 + 积累字典）。

===== 目标列表（前20个） =====
${targets.slice(0, 20).map(function(t) { return '  ' + t.url + ' — ' + (t.tags||[]).join(',') }).join(String.fromCharCode(10))}
============================

**操作方法（必须按顺序执行）：**

**Step 1: 准备积累字典扩展词表**
先Read ${P3_DICT_PATH} 获取积累的API模式。
从该JSON中提取所有可测试的路径:
- framework_patterns 下所有框架的路径
- api_prefixes 的每个key + path_segments 的每个值组合（如 /api/v3/user, /api/v3/admin ...）
- common_endpoints 列表
写入临时文件: \`/tmp/dirsearch_custom.txt\`（每行一个路径，无前导/）

**Step 2: 对每个目标执行 dirsearch 命令**
dirsearch 内置字典: ${DIRSEARCH_DICT}（9482条内置路径）

对每个目标URL依次执行:
\`\`\`bash
# 合并字典运行
dirsearch -u "<target_url>" \
  -w ${DIRSEARCH_DICT} \
  --extra-dict /tmp/dirsearch_custom.txt \
  -e php,asp,aspx,jsp,html,js,json,xml,txt,sql,conf,zip,tar.gz,bak,old,log \
  -t 10 --timeout=5 \
  -o /tmp/dirsearch_results.txt --format plain 2>&1 | tail -50
\`\`\`
如果 --extra-dict 参数不可用，则改为:
\`\`\`bash
cat ${DIRSEARCH_DICT} /tmp/dirsearch_custom.txt | sort -u > /tmp/merged_dict.txt
dirsearch -u "<target_url>" \
  -w /tmp/merged_dict.txt \
  -e php,asp,aspx,jsp,html,js,json,xml,txt,sql,conf,zip,tar.gz,bak,old,log \
  -t 10 --timeout=5 \
  -o /tmp/dirsearch_results.txt --format plain 2>&1 | tail -50
\`\`\`

**Step 3: 解析运行结果**
读取 /tmp/dirsearch_results.txt，提取所有状态码为 200/301/401/403 的端点。

**Step 4: 对发现的端点做快速验证（确认非空页面）**
对每个200端点，用 curl -s -o /tmp/verify.html -w "%{http_code}" 获取响应体，
检查文件大小 > 100字节才视为有效发现。

**输出要求：**
只记录确认有效的端点。每个发现附带: endpoint, status_code, source（dirsearch内置/积累字典/混合）
同时在 new_endpoints 中输出本次新发现的可积累端点。

      ${UA_INSTR}
      ⚠️ **边界规则：仅对目标列表URL执行。不要读取本地非字典文件。**`,
      { label: '📂 字典目录扫描 (dirsearch)', schema: {
        type: 'object',
        properties: {
          findings: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                target: { type: 'string' },
                endpoint: { type: 'string' },
                status_code: { type: 'number' },
                source: { type: 'string', enum: ['dirsearch内置', '积累字典', '混合', '通用路径'] },
                response_preview: { type: 'string', description: '响应体前100字符' },
                severity: { type: 'string', enum: ['高危', '中危', '低危', '信息'] },
              },
              required: ['target', 'endpoint', 'status_code', 'source'],
            },
          },
          new_endpoints: {
            type: 'array',
            items: { type: 'string' },
            description: '本次新发现的可用端点，用于更新字典本',
          },
        },
        required: ['findings'],
      }, phase: '漏洞挖掘' }
    )

    if (p3_dirsearch && p3_dirsearch.findings && p3_dirsearch.findings.length > 0) {
      log(`  目录扫描发现 ${p3_dirsearch.findings.length} 个端点:`)
      p3_dirsearch.findings.forEach(f => {
        const icon = f.status_code === 200 ? '✅' : f.status_code === 401 ? '🔒' : f.status_code === 403 ? '🚫' : '❓'
        log(`    ${icon} [${f.status_code}] ${f.endpoint} (${f.source})`)
      })
      // 更新字典本：新发现的端点追加到 common_endpoints
      if (p3_dirsearch.new_endpoints && p3_dirsearch.new_endpoints.length > 0) {
        await agent(
          `读取 ${P3_DICT_PATH}，将以下新端点追加到 common_endpoints 数组中并写入（去重）:
${p3_dirsearch.new_endpoints.map(function(e) { return '  - ' + e }).join(String.fromCharCode(10))}

用Read工具读取 → 去重合并 → Write工具写回。`,
          { label: '📚 更新字典 common_endpoints', phase: '漏洞挖掘' }
        )
      }
      // 记录维度
      ;(targets || []).forEach(t => dimTracker.record(t.url, 'dirsearch_scan', 'done'))
    } else {
      log('  目录扫描: 未发现新端点')
    }

    // dirsearch发现的端点 → 注入到unauth_test上下文
    let p3_dirsearch_context = ''
    if (typeof p3_dirsearch !== 'undefined' && p3_dirsearch?.findings && p3_dirsearch.findings.length > 0) {
      const dseps = p3_dirsearch.findings
        .filter(f => f.status_code === 200 || f.status_code === 401 || f.status_code === 403)
        .map(f => `  ${f.endpoint} [${f.status_code}] (${f.source || 'dirsearch'})`)
      if (dseps.length > 0) {
        p3_dirsearch_context = `\n**【dirsearch发现的端点 — 需对这些端点做未授权/越权测试】**\n${dseps.join('\n')}\n`
        log(`  🔄 dirsearch ${dseps.length} 个端点回注到未授权测试`)
      }
    }

    // 3.1 未授权/信息泄露测试（遵循: 反思为主→迁跃为辅→分析为底→扩展为路）
    p3_unauth = await agent(
      `你是SRC漏洞挖掘专家，对 ${companyName} 执行未授权访问和信息泄露测试。

**【核心方法论 — 请先ReadFile加载 references/deep-mining-methodology.md】**
先Read ${SKILL_SCRIPTS}/../references/deep-mining-methodology.md，然后按以下原则执行：

1. 反思为主 — 先深入分析已有资产，不急于扩展。对每个目标系统思考：这个系统做什么的？数据流？鉴权怎么实现的？
2. 迁跃为辅 — 从一个发现跳跃到相关系统，找横向关联
3. 分析为底 — 所有判断基于实际HTTP响应，不做猜测
4. 扩展为路 — 在已有发现基础上逐步扩展攻击面，而非盲目扫描

高优目标列表:
${targets.map(function(t) { return '  ' + t.priority + ' | ' + t.url + ' | tags: ' + (t.tags||[]).join(',') }).join('\\n')}

常规URL列表:
${allUrls.map(function(u) { return '  ' + u }).join('\\n')}

第2阶段JS逆向发现的隐藏端点/API路径:
${p2_discoveries_text != null && p2_discoveries_text !== '' ? p2_discoveries_text.substring(0, 10000) : typeof p2_discoveries_text === 'string' ? '（JS分析了但无发现）' : '（无 JS 分析数据）'}

**【Phase 2 提取的结构化凭证（优先级高 — 结构化数据优先于下方文本描述）】**
${typeof globalThis.__p2_creds_json !== 'undefined' ? '以下凭证可直接用于越权/认证测试:\n' + JSON.stringify(JSON.parse(globalThis.__p2_creds_json).slice(0, 15), null, 2).substring(0, 2000) : '（无结构化凭证提取）'}


**【Phase 2 JS缓存目录 — 可回查阅本地JS/还原源码】**
${typeof globalThis.__p2_js_dirs_json !== 'undefined' ? 'JS文件已下载到本地，可直接Read查阅:\n' + JSON.parse(globalThis.__p2_js_dirs_json).map(d => '  ' + d.dump_dir + ' (' + d.js_count + '个JS文件' + (d.has_reconstructed ? ', 含还原源码 reconstructed/' : '') + ')').join('\n') : '（无本地缓存）'}


测试矩阵（按优先级执行）:

**【核心策略 — 🎯 Agent 发散思维 + 靶标定制】**

**首先思考：这个系统做什么的？数据流？鉴权怎么实现的？哪个模块最可能有漏洞？**
基于 Phase 2 的 JS 分析 + 框架识别 + 发现的 API 路径，用第一性原理推断：
- 物流平台 → 关注订单/运单/用户API的越权和遍历
- 管理后台 → 关注权限提升/未授权/配置泄露
- API网关 → 关注SSRF/路径穿越/鉴权绕过
- **先理解系统再动手，不要机械照搬路径列表**

不要只测固定路径列表。对于从 JS 发现的 API 路径，先分析命名再选择测试手法：

1. 分析 API 命名 → 推断功能 → 对应攻击:
   upload/file/import/attachment       → **文件上传绕过/任意文件写入**
   download/export/backup/fetch        → **路径遍历/任意文件读取**
   order/payment/bill/account/balance  → **IDOR越权（替换id/userId参数）**
   login/auth/token/session            → **认证绕过/弱口令/JWT伪造**
   admin/manager/console/dashboard     → **垂直越权/权限提升**
   config/settings/env/param           → **配置泄露/敏感信息**
   sql/search/query/select             → **SQL注入/SSTI**
   exec/run/command/shell/exec     → **命令执行/RCE**
   delete/drop/remove/clear            → **未授权删除**
   page/list/search/query              → **批量遍历/未授权敏感数据**

2. 根据参数名判断测试方向:
   id/userId/orderId → 替换遍历看响应变化
   file/path/url     → 路径穿越(../)、SSRF
   page/pageSize     → 分页遍历
   callback/jsonp    → XSS/JSON劫持
   redirect/next/url → 开放重定向
   data/html/content → XSS/富文本注入

3. SSRF专项测试（参数含 url/path/redirect/domain/host/target）:
   - 替换为内网地址: http://127.0.0.1:8080, http://10.0.0.1, http://172.16.0.1
   - 云元数据: http://169.254.169.254/latest/meta-data/（AWS/阿里云）
   - 华为云元数据: http://169.254.169.254/openstack/latest/
   - 内部服务探测: http://localhost:6379(Redis), http://localhost:3306(MySQL)
   - 观察响应差异: 超时vs拒绝vs返回数据 = 内网服务存活

4. 组件版本识别 + CVE比对:
   - 识别组件指纹（从响应头Server/X-Powered-By/body中的版本号）
   - 对照已知CVE:
     · Spring Boot <2.6.6 → CVE-2022-22965
     · Log4j ≤2.14.1 → CVE-2021-44228
     · Fastjson ≤1.2.80 → RCE
     · Apache Shiro <1.9.1 → CVE-2023-22602
     · Nacos ≤2.0.3 → CVE-2021-29441
     · ThinkPHP ≤6.0 → RCE

5. HTTP方法过度:
   对发现的端点 OPTIONS → 允许的方法 → PUT修改/DELETE删除/POST创建

4. 未授权对比:
   带Cookie vs 无Cookie 响应差异 → 响应大小相近+200 = 可能未授权

5. 通用路径兜底（不在JS路径中的也扫）:
   API文档: /swagger-ui.html, /v3/api-docs, /doc.html
   配置:   /.env, /actuator, /actuator/heapdump

对每个潜在漏洞记录:
- 类型、端点、HTTP请求/响应摘要、状态码、置信度

**⚠️ 硬性过滤规则（必须遵守）:**
- JSON 响应中 data 字段为 []（空数组）、{}（空对象）、null → 不视为"信息泄露"或"未授权访问"
- HTTP 200 + {"code":"1","msg":"成功","data":[]} → 说明API存在但数据不可见，不是漏洞
- 这类发现的 confidence 必须标记为 "exploratory"，不能标记为 "confirmed" 或 "suspected"
- 只有响应体包含实际业务数据（用户信息/配置凭证/订单记录等）才算 confirmed

只做读取探测。


      ⚠️ **User-Agent 硬性规则：所有 curl 命令必须添加 -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'（或等效的浏览器UA），禁止使用默认 curl User-Agent，否则会被WAF/反爬识别拦截。同时添加 Accept-Language: zh-CN,zh;q=0.9 和 Accept: */* 头。**

      ⚠️ **严格边界规则：仅对目标列表中的URL进行测试。不要读取任何本地文件。不要引用、提及或包含任何其他厂商的数据。**`,
      { label: `🔓 未授权/信息泄露测试`, schema: {
        type: 'object',
        properties: {
          findings: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                title: { type: 'string' },
                type: { type: 'string' },
                severity: { type: 'string', enum: ['严重', '高危', '中危', '低危', '信息'] },
                target: { type: 'string' },
                endpoint: { type: 'string' },
                method: { type: 'string' },
                description: { type: 'string' },
                evidence: { type: 'string' },
                curl_command: { type: 'string' },
                confidence: { type: 'string', enum: ['confirmed', 'suspected', 'exploratory'] },
              },
              required: ['title', 'type', 'severity', 'target', 'endpoint', 'confidence'],
            },
          },
        },
      }, phase: '漏洞挖掘' }
    )

    // 3.2 越权/弱口令/其他测试（遵循: 反思为主→迁跃为辅→分析为底→扩展为路）
    p3_other = await agent(
      `你是SRC漏洞挖掘专家，对 ${companyName} 执行越权/弱口令等测试。

**【核心方法论 — 请先ReadFile加载 references/deep-mining-methodology.md】**
先Read ${SKILL_SCRIPTS}/../references/deep-mining-methodology.md 了解完整方法论，按以下原则执行：
1. 反思为主 — 对每个目标先理解其功能和鉴权机制
2. 迁跃为辅 — 从发现的越权点跳跃到关联系统
3. 分析为底 — 不靠猜测，每个结论必须有HTTP响应支撑
4. 扩展为路 — 从已发现的脆弱点逐步扩大

高优目标:
${targets.map(function(t) { return '  ' + t.url }).join('\\n')}

第2阶段JS逆向发现的隐藏端点/API路径:
${p2_discoveries_text != null && p2_discoveries_text !== '' ? p2_discoveries_text.substring(0, 10000) : typeof p2_discoveries_text === 'string' ? '（JS分析了但无发现）' : '（无 JS 分析数据）'}

第2阶段提取的结构化凭证:
${typeof globalThis.__p2_creds_json !== 'undefined' ? JSON.stringify(JSON.parse(globalThis.__p2_creds_json).slice(0, 10), null, 2) : '（无）'}

JS缓存目录（可回查本地JS/还原源码）:
${typeof globalThis.__p2_js_dirs_json !== 'undefined' ? JSON.parse(globalThis.__p2_js_dirs_json).map(d => d.dump_dir + (d.has_reconstructed ? ' (含还原源码)' : '')).join('\n') : '（无）'}

1. 越权测试:
   - 对含数字ID的路径，尝试替换ID值
   - 观察响应差异（是否返回不同用户数据）

2. 弱口令枚举（🎯 关键：发散思维 + 靶标定制，不要机械照搬列表）:
   - **Phase 2 识别的框架默认口令（结构化提取，优先级最高）**:
     ${typeof globalThis.__p2_fw_info !== 'undefined' ? (() => {
       const fw = JSON.parse(globalThis.__p2_fw_info)
       return fw.filter(f => f.default_credentials.length > 0).map(f =>
         `   · ${f.framework_name} ${f.version ? 'v'+f.version : ''} [${f.confidence}]: ${f.default_credentials.join(', ')}`
       ).join('\n') || '   （无框架默认口令识别）'
     })() : '   （Phase 2 未运行框架识别或未提取到口令）'}
   - **🎯 Agent 发散构造 — 根据目标系统特征生成针对性弱口令（关键思维能力，不要跳过）**:
     · 从公司名 "${companyName}" 拼音/英文名/缩写衍生: zhang san → zhangsan/zhangsan123, Zs@2024, zhang.san/pass
     · 从目标域名/系统名推断: 如目标含 lixiang → 试 lixiang/admin, admin/lixiang, lixiang/123456, admin/LiXiang@2024
     · 从JS中发现的硬编码/注释/测试账号发散: 如果JS中发现 test/test123 → 发散出 test1/test1, test2/Test@2024
     · 从JS中发现的邮箱/用户名发散: 如果发现 wangwu@company.com → 试 wangwu/company123, wangwu/Wang@2024
     · 常见的姓氏+名字拼音组合: 尝试性+名首字母、名+姓、全拼等组合作为口令
     · 从页面内容发散: 页面标题、版权年份、公司slogan → 作为口令上下文
     · 任何登录端点的错误信息推断: "用户名不存在" vs "密码错误" → 先枚举用户再爆破
   - **通用字典暴力枚举**（兜底）:
     · 组合1: admin/admin, admin/123456, admin/Admin@123, test/test
     · 组合2: admin/Admin@123456, admin/password, admin/12345678, root/root
     · 组合3: 框架默认口令（JeecgBoot: jeecg/jeecg123, RuoYi: admin/admin123, Shiro: admin/123456）
     · 组合4: 从 JS 配置/注释中发现硬编码凭证
   - 测试 JSON API 登录（Content-Type: application/json）

3. 信息泄露检查:
   - 响应体中是否包含多余字段（密码/身份证/手机号）
   - 错误信息是否泄露路径/版本

4. 目录/文件遍历:
   - 测试 ../ 路径穿越
   - 测试下载功能

5. 逻辑漏洞测试（如发现订单/支付/优惠券相关API）:
   - 金额/数量篡改: 修改 POST body 中的 amount/price/quantity 参数
   - 优惠券/折扣: 重复使用优惠码、篡改折扣比例
   - 流程绕过: 跳过支付步骤、负值参数(Integer溢出)
   - 并发竞态: 同时请求多次（点赞/领券/提现接口）

只做读取探测。


      ⚠️ **User-Agent 硬性规则：所有 curl 命令必须添加 -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'（或等效的浏览器UA），禁止使用默认 curl User-Agent，否则会被WAF/反爬识别拦截。同时添加 Accept-Language: zh-CN,zh;q=0.9 和 Accept: */* 头。**

      ⚠️ **严格边界规则：仅对目标列表中的URL进行测试。不要读取任何本地文件。不要引用、提及或包含任何其他厂商的数据。**`,
      { label: `🎯 越权/弱口令测试`, schema: {
        type: 'object',
        properties: {
          findings: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                title: { type: 'string' },
                type: { type: 'string' },
                severity: { type: 'string' },
                target: { type: 'string' },
                endpoint: { type: 'string' },
                description: { type: 'string' },
                confidence: { type: 'string' },
              },
              required: ['title', 'type', 'severity', 'target', 'endpoint', 'confidence'],
            },
          },
        },
      }, phase: '漏洞挖掘' }
    )

    // 3.3 快速开发框架识别 → 作为线索传递到 Phase 3（不执行本地部署和源码审计）
    if (p2_discoveries_text && p2_discoveries_text.includes('【快速开发框架识别结果】')) {
      log('  🔍 快速开发框架识别结果已作为线索传递到 Phase 3 漏洞挖掘（跳过本地部署和源码审计）')
    } else {
      log('  ⏭️ 无开源系统识别结果')
    }
    // == 框架识别线索传递结束（不执行本地部署和源码审计） ==


    // Tier 2: 剩余资产全量测试（非快速探测，所有目标做完整维度测试）
    p3_quick = null
    if (tier2_urls.length > 0) {
      // 预构建上下文信息字符串（避免解析器对嵌套引号的误判）
      var _t2urls = ''
      for (var _i2 = 0; _i2 < tier2_urls.length; _i2++) { _t2urls += '  ' + tier2_urls[_i2] + '\n' }
      var _crd = '（无）'
      if (typeof globalThis.__p2_creds_json !== 'undefined') {
        try { _crd = JSON.stringify(JSON.parse(globalThis.__p2_creds_json).slice(0, 10), null, 2) } catch(e) { _crd = '（无）' }
      }
      var _jsd = '（无）'
      if (typeof globalThis.__p2_js_dirs_json !== 'undefined') {
        try { _jsd = JSON.parse(globalThis.__p2_js_dirs_json).map(function(d) { return d.dump_dir }).join('\n') } catch(e) { _jsd = '（无）' }
      }
      p3_quick = await agent(
        `对 ${companyName} 的以下剩余资产做**全量漏洞测试**。

剩余资产列表（${tier2_urls.length} 个）:
${_t2urls}\t第2阶段提取的结构化凭证:
\t\t${_crd}
\t\tJS缓存目录:
\t\t${_jsd}

执行全量测试（每个目标深入测试）:
1. curl -sI -H 'User-Agent: ...' 每个URL确认HTTP状态码（必须带浏览器UA）
2. 对返回200/401/403的，探测以下维度:
   - 未授权API: /api/v1/user, /api/v1/config, /swagger-ui.html, /v2/api-docs
   - 后台管理: /admin/, /console/, /login, /manager/
   - 配置泄露: /.env, /robots.txt, /WEB-INF/web.xml
   - 组件端点: /actuator, /druid, /nacos
   - 备份文件: *.bak, *.zip, *.tar.gz
   - 路径穿越: ../../etc/passwd
3. 对登录页面尝试弱口令: admin/admin, admin/123456
4. 识别组件版本+CVE匹配
5. 有发现的才记录，无发现的不需输出
6. 每个发现附带 curl 命令


        ⚠️ **User-Agent 硬性规则：所有 curl 命令必须添加 -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'（或等效的浏览器UA），禁止使用默认 curl User-Agent，否则会被WAF/反爬识别拦截。同时添加 Accept-Language: zh-CN,zh;q=0.9 和 Accept: */* 头。**

        ⚠️ **严格边界规则：仅对当前列表中的URL进行测试。不要读取任何本地文件。不要引用、提及或包含任何其他厂商的数据。**`,
        { label: '⚡ Tier2快速探测', schema: {
          type: 'object',
          properties: {
            findings: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  title: { type: 'string' },
                  type: { type: 'string' },
                  severity: { type: 'string', enum: ['严重', '高危', '中危', '低危', '信息'] },
                  target: { type: 'string' },
                  endpoint: { type: 'string' },
                  description: { type: 'string' },
                  curl_command: { type: 'string' },
                  confidence: { type: 'string', enum: ['confirmed', 'suspected', 'exploratory'] },
                },
                required: ['title', 'type', 'severity', 'target', 'endpoint', 'confidence'],
              },
            },
          },
        }, phase: '漏洞挖掘' }
      )
    }

    // 记录已测维度（unauth_test 对所有目标适用，weak_pass 仅对后台/登录口）
    ;(targets || []).forEach(t => {
      dimTracker.record(t.url, 'unauth_test', 'done')
      if ((t.tags || []).includes('[管理后台]')) {
        dimTracker.record(t.url, 'weak_pass', 'done')
      }
    })
    ;(allUrls || []).forEach(u => dimTracker.record(u, 'unauth_test', 'done', { note: 'from allUrls' }))

    // 合并发现（含 Tier 1 + Tier 2）
    const allFindings = [
      ...(p3_unauth?.findings || []),
      ...(p3_other?.findings || []),
      ...(typeof p3_quick !== 'undefined' && p3_quick?.findings ? p3_quick.findings : []),
    ]
    progress.findings_count = allFindings.length

    log(`  发现 ${allFindings.length} 个潜在漏洞:`)
    allFindings.forEach(f => {
      const icon = f.severity === '严重' ? '🔥' : f.severity === '高危' ? '🔴' : f.severity === '中危' ? '🟡' : '⚪'
      log(`    ${icon} [${f.severity}] ${f.title}`)
      log(`        → ${f.endpoint} (${f.confidence})`)
      if (f.curl_command) log(`        → curl: ${f.curl_command.substring(0, 120)}`)
    })
    // 保存发现数据供 Phase 5 线索文件写入
    p3_findings_data = allFindings.map(f => ({
      title: f.title, type: f.type, severity: f.severity,
      target: f.target || '', endpoint: f.endpoint,
      confidence: f.confidence, curl_command: f.curl_command || '',
      phase_discovered: 'phase3', status: 'unverified'
    }))
  }

  markPhase(3, '✅')
  showProgress()
}

// ============================================================
// Phase 4: 验证与证据
// ============================================================
phase('验证取证')

if (progress.findings_count === 0) {
  log('[4/8] ⏭️ 无发现需要验证')
  markPhase(4, '⏭️')
} else {
  log('[4/8] 验证与证据收集')

  // 1. 对 Phase 3 发现的漏洞做确认性复测
  const p4_all_findings = [
    ...(typeof p3_unauth !== 'undefined' && p3_unauth?.findings ? p3_unauth.findings : []),
    ...(typeof p3_other !== 'undefined' && p3_other?.findings ? p3_other.findings : []),
    ...(typeof p3_quick !== 'undefined' && p3_quick?.findings ? p3_quick.findings : []),
    ...(typeof p3_dirsearch !== 'undefined' && p3_dirsearch?.findings ? p3_dirsearch.findings : []),
    ...(typeof p3_codeaudit !== 'undefined' && p3_codeaudit?.audit_findings ? p3_codeaudit.audit_findings : []),
  ]
  const p4_findings_json = JSON.stringify(p4_all_findings, null, 2)

  if (p4_all_findings.length > 0) {
    p4_verify = await agent(
      `你是SRC漏洞验证专家，对 ${companyName} 的发现做**严格 curl 验证**。

====== Phase 3 传入的发现列表 ======
${p4_findings_json.substring(0, 6000)}
==================================

### 验证规则

对每个发现，必须执行以下流程：

**Step 1: 提取可测试的 URL**
- 如果 endpoint 是具体 URL → 直接测试
- 如果 endpoint 是 "前端JS包" 或 "JS文件" → 从 target 提取域名，从描述中提取 API 路径，拼接成可测试 URL
- 如果完全无法提取可测试 URL → 标记为 needs_manual_test

**Step 2: 用 curl 测试**
1. 先 \`curl -sk -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' -o /dev/null -w "%{http_code}"\` 获取数字HTTP状态码（必须带浏览器UA）
2. 状态码 200/401/403 的，\`curl -sk -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'\` 获取响应体
3. 对比 带Cookie vs 无Cookie 的响应差异
4. **http_status 必须是数字，不能是字符串。每个 confirmed/suspected 发现都必须有。**

**Step 3: 判定**
| 判定 | 条件 |
|------|------|
| confirmed | curl 返回 **200 + 响应体含实际敏感数据**（用户信息/订单列表/配置凭证/数据库内容），并且**不是**权限错误 |
| suspected | 返回 200/401 但响应体是权限错误（如 "没有接口访问权限"）, 或需要复杂利用条件 |
| needs_manual_test | 无法构造可测试 URL（如 JS 分析发现但无具体路径）|
| false_positive | URL 不可达 / 404 / 超时 / 返回无敏感数据 |

⚠️ **confirmed 的严格标准：**
1. 必须有 curl_command + http_status(数字) + evidence
2. **HTTP 200 + 权限错误（"没有接口访问权限" / "Unauthorized" / "需要登录"）= NOT confirmed**，这是认证在正常工作
3. **JS中找到的API路径 + curl未返回实际数据 = NOT confirmed**，这是SPA源码泄漏但不是未授权漏洞
4. 证据必须是实际的敏感数据片段，不是状态码本身
5. 三项条件缺一不可，不满足的降级为 suspected 或 needs_manual_test

**🔥 关键 — JSON空响应检测规则（必须硬性遵守，不可覆盖）：**
- 如果响应体是 JSON，执行 curl 后用 python3 -c "import sys,json; d=json.load(sys.stdin); print(len(json.dumps(d.get('data', {}))))" 提取 data 字段
- **[data] 字段为 []（空数组）或 {}（空对象）或 null 或无 data 字段 → 一律标记为 false_positive**，理由: data_empty
- **[data] 字段长度 < 30 字符（最小有意义数据的阈值）→ 标记为 false_positive**
- **JSON 中只含非数据字段（code/msg/timestamp/success/pageNum/total 等状态元数据）但无实际业务数据 → 标记为 false_positive**
- **不要因为 HTTP 200 + JSON 包含 "成功" 字样就认为是真数据，必须检查 data 字段是否包含有意义的业务记录**

**检测步骤（按顺序执行，不可跳过）：**
Step A: 执行 curl -sk -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' -o /tmp/verify_resp.json -w "%{http_code}" "<URL>" 获取完整响应体
Step B: 用 python3 -c "import json; d=json.load(open('/tmp/verify_resp.json')); print(json.dumps(d, ensure_ascii=False)[:200])" 查看响应前200字符
Step C: 如果响应是 JSON → 提取 d.get('data') 判断类型:
  - data 是空列表 [] → false_positive (理由: data_empty_list)
  - data 是空对象 {} → false_positive (理由: data_empty_object)
  - data 是 null 或 undefined → false_positive (理由: data_null)
  - data 是非空列表但第一项不包含用户可读的业务字段（仅含 id/iid/total/pageNum 等元数据）→ suspected 或 false_positive
  - data 是包含用户/订单/配置/凭证等业务数据的非空列表 → confirmed

输出时 confirmed_findings 只放 confirmed + suspected 的。false_positives 和 needs_manual_test 各自归位。

---
### 🎯 Step 4: Agent 发散扩展（关键思维环节 — 不要跳过）

**验证一个发现时，发散思考是否存在变种/扩展，不要只复述已有发现。**

发散方向（对每个发现依次思考）：

**4a. 参数发散 — 同一端点的其他参数**
发现 /api/user?id=1 → 发散试:
- /api/user?orderId=2       (是否越权查其他资源)
- /api/user?page=1&size=100 (是否分页遍历)
- /api/user?id[0]=1&id[1]=2 (参数注入)
- /api/user?name=admin      (换个参数名)

**4b. HTTP方法发散 — 同一端点的其他方法**
GET /api/user/1 → 发散试:
- PUT /api/user/1  (Body: {"role":"admin"})  — 修改越权
- DELETE /api/user/1                           — 删除越权
- PATCH /api/user/1                            — 部分更新
- POST /api/user                               — 创建越权

**4c. 路径发散 — 同一前缀的其他路径**
发现 /api/v1/user → 发散试:
- /api/v1/admin, /api/v1/config, /api/v1/log
- /api/v1/user/export, /api/v1/user/import
- /api/v2/user（版本遍历）

**4d. 鉴权发散 — 不同认证方式的绕过尝试**
- 无Cookie → 带空Authorization: Bearer → 带伪造Token
- Cookie A → 替换为Cookie B（水平越权）
- 去除 X-Forwarded-For / Origin / Referer 头（看鉴权是否依赖）
- 添加 X-Admin: true / X-Role: admin（未授权header）

**4e. 内容类型发散 — 切换解析方式看后端行为差异**
JSON → XML（XXE测试）
JSON → Form-URLEncoded（参数解析差异）

**4f. 基于 Phase 2 JS 分析的发散**
如果 Phase 2 发现了隐藏API路径或凭证，思考这些路径是否存在与当前发现类似的漏洞模式。
访问本地JS文件确认（路径见上方JS缓存目录）。

**4g. 利用链思考 — 当前发现能否与其他发现串联**
存在利用链可能 → 报告时标记为利用链格式

**Step 5: 变种验证**
对 Step 4 发散出的每个有潜力的变种，用 curl 快速验证状态码。
只记录 200/401/403 且有实际响应内容的新发现（追加到 confirmed_findings）。
无新发现的正常结束，不是每个发散方向都必须有结果。

**关键原则：**
- 发散不是漫无目的，每个发散方向必须有「为什么这么试」的理由
- 发现一个IDOR → 思考同一资源类的其他端点是否也有IDOR（横向发散）
- 发现一个SSRF → 思考能否升级为RCE或内网扫描（纵向发散）
- 确认无新发现后正常收尾，不要虚构
- 发散结果追加到 new_variants 字段

---
之前发现的 false_positives 继续保留。
新增的变种发现追加到 confirmed_findings 数组。

      ⚠️ **User-Agent 硬性规则：所有 curl 命令必须添加 -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'（或等效的浏览器UA），禁止使用默认 curl User-Agent，否则会被WAF/反爬识别拦截。同时添加 Accept-Language: zh-CN,zh;q=0.9 和 Accept: */* 头。**

      ⚠️ **严格边界规则：仅验证当前公司的漏洞数据。不要引用、提及或包含任何其他厂商的数据。**`,
      { label: '🔍 漏洞复测验证', schema: {
        type: 'object',
        properties: {
          confirmed_findings: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                title: { type: 'string' },
                type: { type: 'string' },
                severity: { type: 'string', enum: ['严重', '高危', '中危', '低危', '信息'] },
                target: { type: 'string' },
                endpoint: { type: 'string' },
                http_status: { type: 'number', description: 'curl测试返回的HTTP状态码' },
                evidence: { type: 'string', description: '响应体关键片段（必填，confirmed必须含敏感数据）' },
                curl_command: { type: 'string', description: '实际执行的curl命令（必填）' },
                confidence: { type: 'string', enum: ['confirmed', 'suspected'] },
              },
              required: ['title', 'type', 'severity', 'endpoint', 'http_status', 'curl_command', 'confidence'],
            },
          },
          false_positives: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                title: { type: 'string' },
                endpoint: { type: 'string' },
                reason: { type: 'string' },
              },
              required: ['title', 'reason'],
            },
          },
          new_variants: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                title: { type: 'string' },
                type: { type: 'string' },
                severity: { type: 'string', enum: ['严重', '高危', '中危', '低危', '信息'] },
                target: { type: 'string' },
                endpoint: { type: 'string' },
                http_status: { type: 'number' },
                evidence: { type: 'string' },
                curl_command: { type: 'string' },
                confidence: { type: 'string', enum: ['confirmed', 'suspected'] },
                parent_finding: { type: 'string', description: '从哪个原始发现发散而来' },
                divergence_type: { type: 'string', enum: ['参数发散', '方法发散', '路径发散', '鉴权发散', '内容类型发散', 'JS分析发散', '利用链'] },
              },
              required: ['title', 'endpoint', 'http_status', 'divergence_type'],
            },
          },
          needs_manual_test: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                title: { type: 'string' },
                reason: { type: 'string', description: '为何无法curl测试' },
              },
            },
          },
        },
        required: ['confirmed_findings'],
      }, phase: '验证取证' }
    )

    if (p4_verify && p4_verify.confirmed_findings) {
      // ============================================================
      // 🔧 硬性程序化证据检查 — 确保 AI 的 confirmed/suspected 判定
      // 必须包含可验证的真实业务数据（而非空 JSON 容器）
      // ============================================================
      const EMPTY_DATA_PATTERNS = [
        '"data":[]', '"data":{}', '"data":null', '"data":""',
        '"data":\n[]', '"data":\n{}',
        '"list":[]', '"records":[]', '"rows":[]',
        '"total":0}', '"size":0}',
        '"success":false', '"success": false',
        '"code":1', '"code":-1', '"code":500',
        '"msg":"执行出现问题','"msg":"参数错误','"msg":"没有权限',
        '"msg":"Unauthorized','"msg":"登录已过期',
      ]
      const AUDIT_EVIDENCE_MIN = 40
      const audited = []
      for (const f of p4_verify.confirmed_findings) {
        let reason = null
        const ev = (f.evidence || '').replace(/\s+/g, '')
        // 403 状态码 → 非有效利用
        if (f.http_status === 403) {
          reason = 'http_403_forbidden'
        } else if (!f.evidence || f.evidence.trim().length < 3) {
          reason = 'evidence_empty_or_too_short'
        } else if (EMPTY_DATA_PATTERNS.some(p => ev.includes(p))) {
          reason = 'evidence_contains_empty_data_container'
        } else if (f.evidence.length < AUDIT_EVIDENCE_MIN) {
          reason = `evidence_too_short_${f.evidence.length}chars`
        }
        if (reason) {
          log(`  🔧 程序化验货: [${f.severity}] ${f.title} -> ${reason}，自动降级 false_positive`)
          p4_verify.false_positives = p4_verify.false_positives || []
          p4_verify.false_positives.push({
            title: f.title, endpoint: f.endpoint,
            reason: `自动证据检查: ${reason}，evidence="${(f.evidence||'').substring(0,120)}"`
          })
          log(`     -> ${f.title} 已从 confirmed 移至 false_positives`)
        } else {
          audited.push(f)
        }
      }
      const downgraded = p4_verify.confirmed_findings.length - audited.length
      if (downgraded > 0) log(`  🔧 程序化验货已自动降级 ${downgraded} 条空证据发现`)
      p4_verify.confirmed_findings = audited
      // ============================================================
      // 程序化证据检查结束
      // ============================================================

      const fp_count = p4_verify.false_positives?.length || 0
      const manual_count = p4_verify.needs_manual_test?.length || 0
      const fp_suffix = fp_count > 0 ? `, ${fp_count} 个 false_positive` : ''
const manual_suffix = manual_count > 0 ? `, ${manual_count} 个需手动验证` : ''
log(`  复测完成: ${p4_verify.confirmed_findings.length} 个确认有效${fp_suffix}${manual_suffix}`)
      // 记录各条验证的HTTP状态
      p4_verify.confirmed_findings.forEach(f => {
        const st = f.http_status || 0
        const statusIcon = st === 200 ? '✅' : st === 401 ? '🔒' : st === 403 ? '🚫' : '❓'
        log(`  ${statusIcon} [${st}] ${f.title} → ${f.endpoint}`)
        if (f.curl_command) log(`     curl: ${f.curl_command.substring(0, 120)}`)
      })
      progress.findings_count = p4_verify.confirmed_findings.length

      // 合并发散结果到主体发现
      if (p4_verify.new_variants && p4_verify.new_variants.length > 0) {
        log(`  🎯 发散发现 ${p4_verify.new_variants.length} 个变种:`)
        p4_verify.new_variants.forEach(v => {
          log(`    [${v.http_status}] ${v.endpoint} (${v.divergence_type} ← ${v.parent_finding || '原始发现'})`)
        })
        // 将发散结果追加到confirmed_findings
        p4_verify.confirmed_findings = p4_verify.confirmed_findings || []
        p4_verify.confirmed_findings.push(...p4_verify.new_variants)
        // 同时更新p3_findings_data
        p3_findings_data.push(...p4_verify.new_variants.map(v => ({
          title: v.title, type: v.type || '变种发现', severity: v.severity || '中危',
          target: v.target || '', endpoint: v.endpoint,
          confidence: v.confidence || 'suspected',
          curl_command: v.curl_command || '',
          phase_discovered: 'phase4_variant', status: v.confidence === 'confirmed' ? 'confirmed' : 'suspected'
        })))
      }

      // P2: 验证通过的端点 → 更新字典本
      if (p4_verify.confirmed_findings.length > 0) {
        const confirmed_endpoints = p4_verify.confirmed_findings
          .filter(f => f.http_status === 200 && f.confidence === 'confirmed')
          .map(f => f.endpoint)
        if (confirmed_endpoints.length > 0) {
          const endpoints_json = JSON.stringify(confirmed_endpoints)
          await agent(
            `python3 ${SKILL_SCRIPTS}/update_dict.py ${SKILL_SCRIPTS}/../references/api_patterns.json --endpoints '${endpoints_json}'`,
            { label: '📚 验证通过端点到字典', phase: '验证取证' }
          )
          log(`  📚 已将 ${confirmed_endpoints.length} 个已验证端点加入字典本`)
        }
      }
      // 更新发现状态（含 http_status + curl_command 要求检查）
      if (p3_findings_data.length > 0) {
        const confirmedEndpoints = new Set(
          p4_verify.confirmed_findings.filter(f => f.confidence === 'confirmed' && f.curl_command).map(f => f.endpoint)
        )
        const suspectedEndpoints = new Set(
          p4_verify.confirmed_findings.filter(f => f.confidence === 'suspected' || !f.curl_command).map(f => f.endpoint)
        )
        const fpEndpoints = new Set((p4_verify.false_positives || []).map(f => f.endpoint || f.title))
        const manualKeys = new Set((p4_verify.needs_manual_test || []).map(f => f.title))
        p3_findings_data = p3_findings_data.map(f => {
          if (fpEndpoints.has(f.endpoint || f.title)) return { ...f, status: 'false_positive', phase_discovered: 'phase4' }
          if (manualKeys.has(f.title)) return { ...f, status: 'needs_manual_test', phase_discovered: 'phase4' }
          if (confirmedEndpoints.has(f.endpoint)) return { ...f, status: 'confirmed', phase_discovered: 'phase4' }
          if (suspectedEndpoints.has(f.endpoint)) return { ...f, status: 'suspected', phase_discovered: 'phase4' }
          return f
        })
        // 从验证结果中补充 curl_command 和 http_status
        // 兜底：如果 agent 没填 http_status，从 evidence/curl_command 中提取
        p4_verify.confirmed_findings.forEach(f => {
          if (!f.http_status && f.evidence) {
            // 从 evidence 中提取 HTTP 状态码: HTTP 200, HTTP/1.1 200, -> 200, 状态码:200
            const m = f.evidence.match(/HTTP[ /\d.]*(\d{3})|->\s*(\d{3})|状态码[：:]\s*(\d{3})/)
            if (m) f.http_status = parseInt(m[1] || m[2] || m[3])
          }
          if (!f.http_status && f.curl_command) {
            // 有curl命令但无状态码 → 从 curl -w 输出或响应中提取
            const statusMatch = f.curl_command.match(/HTTP[/\d.]*\s+(\d{3})/)
            if (statusMatch) f.http_status = parseInt(statusMatch[1])
          }
          if (!f.http_status) f.http_status = 0  // 实在提取不到就标0
        })
        const verifyResults = {}
        p4_verify.confirmed_findings.forEach(f => { verifyResults[f.endpoint] = { curl: f.curl_command, http: f.http_status, evidence: f.evidence } })
        p3_findings_data = p3_findings_data.map(f => {
          if (verifyResults[f.endpoint]) {
            return { ...f, curl_command: verifyResults[f.endpoint].curl || f.curl_command, http_status: verifyResults[f.endpoint].http, evidence: verifyResults[f.endpoint].evidence }
          }
          return f
        })
      }
    }
  }

  markPhase(4, '✅')
  showProgress()
}

// ============================================================
// Phase 5: 资产标记与状态存储
// ============================================================
phase('资产标记')

if (mode.startsWith('phase5') || typeof p1_assets === 'undefined' || !p1_assets || (!p1_assets.priority_targets || p1_assets.priority_targets.length === 0)) {
  log('[5/8] ⏭️ 跳过（无资产需标记）')
  markPhase(5, '⏭️')
} else {
  markPhase(5, '🔄')
  log('[5/8] 资产标记与状态存储')

  // 收集本次运行涉及的所有资产
  const p5_all_assets = [
    ...(typeof p1_assets !== 'undefined' && p1_assets?.priority_targets ? p1_assets.priority_targets.map(t => ({ url: t.url, ip: t.ip, port: t.port, title: t.title || '', tags: t.tags || [] })) : []),
  ]
  // 去重
  const p5_urls_set = new Set()
  const p5_assets_deduped = p5_all_assets.filter(a => {
    if (p5_urls_set.has(a.url)) return false
    p5_urls_set.add(a.url)
    return true
  })

  if (p5_assets_deduped.length === 0) {
    log('  ⏭️ 无具体资产需标记')
    markPhase(5, '⏭️')
  } else {
    // 结构化维度数据：为每个资产计算已完成/适用维度 + 自动判定
    const p5_dim_rows = p5_assets_deduped.map(a => {
      const isLogin = (a.tags || []).includes('[管理后台]')
      const isWeb = !!a.title
      const completed = dimTracker.completed(a.url)
      const missing = dimTracker.missing(a.url, isWeb, isLogin)
      const auto = dimTracker.judge(a.url, isWeb, isLogin)
      return { ...a, isWeb, isLogin, completed, missing, auto }
    })

    const p5_dim_report = p5_dim_rows.map(a =>
      `【${a.url}】${a.title ? ' ('+a.title+')' : ''}
  已完成: ${a.completed.length > 0 ? a.completed.join(', ') : '(无)'}
  缺漏:   ${a.missing.length > 0 ? a.missing.join(', ') : '(全部完成)'}
  自动判定: ${a.auto}
`
    ).join('\n')

    // 准备线索数据，传给Phase 5 agent供存储
    // ============================================================
    // 🔧 程序化合并写入 — 确保 asset_test_status.json + asset_findings.json 为追加/合并模式
    // 不依赖AI agent自觉性，硬性执行读-合并-写
    // ============================================================
    log('  🔧 程序化合并 asset 文件 (merge_assets.py)...')

    // 合并 asset_test_status.json
    const dim_json = JSON.stringify(dimTracker.toJSON())
    const p5_dim_info = JSON.stringify(p5_dim_rows.map(a => ({url: a.url, title: a.title, ip: a.ip, port: a.port})))
    await agent(
      `python3 ${SKILL_SCRIPTS}/merge_assets.py status "${trackerPath}" \
  --dim-data '${dim_json}' \
  --asset-info '${p5_dim_info}'`,
      { label: '📊 合并状态文件', phase: '资产标记' }
    )

    // 合并 asset_findings.json
    if (p3_findings_data.length > 0) {
      const findings_json_str = JSON.stringify(p3_findings_data)
      await agent(
        `python3 ${SKILL_SCRIPTS}/merge_assets.py findings "${findingsPath}" \
  --new-findings '${findings_json_str}'`,
        { label: '📝 合并发现文件', phase: '资产标记' }
      )
      log(`  📝 线索已存档至 asset_findings.json（${p3_findings_data.length} 条）`)
    }

    // 仍保留AI标记环节（仅做状态判定，文件由上面脚本处理）
    const p5_dim_report_short = p5_dim_rows.map(a =>
      `【${a.url}】completed=[${a.completed.join(',')}] missing=[${a.missing.join(',')}] auto=${a.auto}`
    ).join('\n')

    const p5_mark = await agent(
      `你是SRC资产状态管理专家，对 ${companyName || ''} 的资产做测试状态判定。

结构化维度数据:
${p5_dim_report_short}

对每个资产判断「已完全测试完毕 / 还未测试完毕 / 无法进行测试」并给出 reason。

自动判定参考:
- 已完全测试完毕 = 所有适用维度已完成 + 无发现或已出报告（TTL=30天，到期自动降级）
- 还未测试完毕 = 存在缺漏维度或可疑点未跟进
- 无法进行测试 = 端口关闭/非HTTP/不在范围（TTL=30天，到期自动降级）`,
      { label: '🏷️ AI状态判定', schema: {
        type: 'object',
        properties: {
          assets: {
            type: 'object',
            additionalProperties: {
              type: 'object',
              properties: {
                status: { type: 'string', enum: ['已完全测试完毕', '还未测试完毕', '无法进行测试'] },
                reason: { type: 'string' },
              },
              required: ['status', 'reason'],
            },
          },
        },
        required: ['assets'],
      }, phase: '资产标记' }
    )

    if (p5_mark && p5_mark.assets) {
      const counts = { '已完全测试完毕': 0, '还未测试完毕': 0, '无法进行测试': 0 }
      Object.values(p5_mark.assets).forEach(a => { if (counts[a.status] !== undefined) counts[a.status]++ })
      log(`  📊 AI判定: 已完成 ${counts['已完全测试完毕']} | 未完成 ${counts['还未测试完毕']} | 无法测试 ${counts['无法进行测试']}`)
    }
  }
  markPhase(5, '✅')
  showProgress()
}

// ============================================================
// Phase 6: 报告编写
// ============================================================
phase('报告编写')

if (progress.findings_count === 0) {
  log('[6/8] ⏭️ 无有效发现，跳过报告编写')
  markPhase(6, '⏭️')
} else {
  markPhase(6, '🔄')
  log(`[6/8] 报告编写 — ${companyName}`)

  // 准备输出目录
  await agent(
    `执行以下命令创建报告输出目录:
    mkdir -p ${SRC_BASE}/${companyName}/submittable_reports/
    mkdir -p ${SRC_BASE}/${companyName}/submittable_reports/reports_html/
    确认目录已创建成功。`,
    { label: '📁 准备输出目录', phase: '报告编写' }
  )

  // 列出已有报告避免重复
  const existingReports = await agent(
    `列出 ${SRC_BASE}/${companyName}/submittable_reports/ 下所有 .md 文件的文件名（不含路径），
    每行一个。如果没有文件则返回空。`,
    { label: '📋 检查已有报告', phase: '报告编写' }
  )
  log(`  已有 ${(existingReports || '').split('\n').filter(Boolean).length} 个报告`)

  // 报告只优先使用 Phase 4 复测后的有效发现，避免把 Phase 3 原始误报写入报告。
  const p6VerifiedFindings = (p4_verify?.confirmed_findings || []).filter(f =>
    f.confidence === 'confirmed' || f.confidence === 'suspected' || !f.confidence
  )
  const p6FallbackFindings = [
    ...(typeof p3_unauth !== 'undefined' && p3_unauth?.findings ? p3_unauth.findings : []),
    ...(typeof p3_other !== 'undefined' && p3_other?.findings ? p3_other.findings : []),
    ...(typeof p3_quick !== 'undefined' && p3_quick?.findings ? p3_quick.findings : []),
    ...(typeof p3_dirsearch !== 'undefined' && p3_dirsearch?.findings ? p3_dirsearch.findings : []),
    ...(typeof p3_codeaudit !== 'undefined' && p3_codeaudit?.audit_findings ? p3_codeaudit.audit_findings : []),
  ]
  const allFindingsData = p6VerifiedFindings.length > 0 ? p6VerifiedFindings : p6FallbackFindings
  const findingsJSON = JSON.stringify(allFindingsData, null, 2)

  // 用结构化schema让agent返回【报告规划】（仅分片规划，不生成内容）
  // content由后续write agent根据finding_indices各自生成，避免token爆炸
  const p5_plan = await agent(
    `你是SRC报告编写专家，为 ${companyName} 的漏洞编写标准报告。

你的任务：规划需要生成的报告清单，仅规划分片方案（不生成报告正文）。

🎯 **发散思考原则（在规划分片前必须执行）：**

**① 发现间关系分析** — 这些发现之间是否存在前后依赖？
   A泄露凭证 → B用凭证获取数据 → C配置泄露扩大危害 → 合成利用链报告
   **综合等级以链路中最高的单步危害+可达性判定，高于单步最高级**

**② 同源推断** — 同一API前缀/同一模块/同一框架的多个漏洞，思考是否共享根因：
   - 同一个鉴权中间件缺陷导致多个接口未授权 → 1份报告描述根因，而非逐个接口提交
   - JS中同一个硬编码凭证导致多个功能越权 → 1份报告

**③ 系统上下文重估危害** — 结合目标系统类型和数据敏感度重新评估：
   物流/电商系统: 订单数据泄露=高危（即使单条）
   管理后台: 任意接口未授权=高危
   API网关: SSRF可升级为内网扫描=严重
   金融系统: 用户信息泄露=严重

**④ 利用链判定规则：**
   - 存在利用链可能 → 文件名为「利用链」标识，综合等级评估
   - 不存在利用链 → 正常分片，同类合并

⚠️ 重要规则：
1. 只对【确认有效】的漏洞写报告，不要虚构
2. 同类漏洞合并为一个综合报告
3. 文件名以中文开头：{严重等级}_{漏洞类型}_{公司简称}_{简述}.md
   例：高危_信息泄露_货讯通_DWR接口.md
4. 默认过滤规则（可被 user_request 覆盖）：
   - **低危漏洞默认不生成报告**（除非用户明确要求包含低危）
   - **CORS同源配置缺陷默认不生成报告**（CORS Access-Control-Allow-Origin: * 或任意源反射，除非用户明确要求）

====== 以下是从漏洞挖掘阶段传入的实际发现（结构化数据）======
${findingsJSON}
================================================================

先检查 ${SRC_BASE}/${companyName}/submittable_reports/ 下已有报告避免重复。

${existingReports ? `已有报告：
${existingReports}` : ''}

请规划报告分片方案，每份报告指定：
- file_name: 文件名
- severity: 严重等级
- title: 报告标题
- finding_indices: 包含哪些发现的索引（对应allFindingsData数组中的下标）`,
    { label: '📝 规划报告分片', schema: {
      type: 'object',
      properties: {
        reports: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              file_name: { type: 'string', description: '文件名，如 高危_信息泄露_浙旅院_XXX.md' },
              severity: { type: 'string', enum: ['严重', '高危', '中危', '低危', '信息'] },
              title: { type: 'string', description: '报告标题' },
              finding_indices: { type: 'array', items: { type: 'number' }, description: '该报告包含哪些发现的索引（从0开始，对应allFindingsData数组）' },
            },
            required: ['file_name', 'severity', 'title', 'finding_indices'],
          },
        },
      },
      required: ['reports'],
    }, phase: '报告编写' }
  )

  // 写每份报告 - 按分片并行写入（每个agent只处理自己分到的发现，避免token爆炸）
  // 每个write agent有retry机制（最多2次），重叠修复Fix 5
  if (p5_plan && p5_plan.reports && p5_plan.reports.length > 0) {
    log(`  规划写入 ${p5_plan.reports.length} 份报告...`)
    progress.reports_count = p5_plan.reports.length

    // 预读报告模板（避免N个并行writer各自独立Read，浪费token）
    let p5_template_content = ''
    try {
      p5_template_content = require('fs').readFileSync(${SKILL_SCRIPTS}/../references/report-templates.md, 'utf8')
      log(`  📖 预读报告模板 (${p5_template_content.length} 字符)`)
    } catch(e) {
      log(`  ⚠️ 预读报告模板失败: ${e.message}，writer将自行Read`)
    }

    // 按严重等级分批注入，让writer知道上下文
    const severityOrder = { '严重': 0, '高危': 1, '中危': 2, '低危': 3, '信息': 4 }

    const writeResults = await parallel(
      p5_plan.reports.map((rpt, idx) => () => {
        // 只取出该报告分到的发现数据（按finding_indices过滤）
        const myFindings = (rpt.finding_indices || []).map(i => allFindingsData[i])
        const myFindingsJSON = JSON.stringify(myFindings, null, 2)
        const filePath = `${SRC_BASE}/${companyName}/submittable_reports/${rpt.file_name}`

        // 用闭包包裹重试逻辑
        const tryWrite = async (attempt = 1) => {
          const label = `📄 ${rpt.file_name}`
          const result = await agent(
            `【关键 - 必须实际调用Write工具】你正在为SRC漏洞报告系统写入一份漏洞报告。

报告信息:
- 文件名: ${rpt.file_name}
- 标题: ${rpt.title}
- 严重等级: ${rpt.severity}
- 厂商: ${companyName}
- 目录: ${SRC_BASE}/${companyName}/submittable_reports/

====== 该报告包含的结构化发现（仅该报告所属的${myFindings.length}个发现）======
${myFindingsJSON}
================================================================

你的任务：
1. 🎯 **发散思考** — 在写作过程中如果发现当前报告与其他报告/发现存在利用链可能，主动调整报告结构（合并或标记为利用链）
2. 根据上述发现的原始数据，生成完整的Markdown格式报告
2. 调用Write工具写入文件 file_path: "${filePath}"
3. 执行 ls -la "${filePath}" 和 wc -l "${filePath}" 确认写入成功
4. 读取文件内容确认完整性

报告格式要求：
- 模板结构参考:
${p5_template_content ? '```\n' + p5_template_content.substring(0, 1500) + '\n```' : '（模板预读失败，请自行Read）'}
- 如果该报告是**利用链类型**（多个漏洞串联），使用攻击链路图格式：\`漏洞A -> 漏洞B -> 漏洞C -> 最终危害\`，每个步骤附带单独的请求/响应包
- 包含漏洞信息表（名称、等级、类型、范围、发现时间）
- 包含漏洞描述
- 包含漏洞复现步骤 + 完整的HTTP请求/响应包 + curl命令
- 每个发现单独一个漏洞描述段落
- 包含修复建议
- 敏感数据脱敏
- 如果已有报告中已包含相同内容，不要重复写入

注意：不要只描述将要做什么，必须实际调用Write工具。这是写入磁盘的真实操作。这是第 ${attempt} 次尝试。`,
            { label, phase: '报告编写' }
          )
          // 检查是否成功（result不为空表示成功）
          return { rpt, result, success: !!result }
        }

        // 执行带retry的写入
        return tryWrite(1).catch(err => {
          log(`  ⚠️ 第1次写入失败: ${rpt.file_name} — ${err.message}`)
          return tryWrite(2).catch(err2 => {
            log(`  ❌ 重试也失败: ${rpt.file_name} — ${err2.message}`)
            return { rpt, result: null, success: false }
          })
        })
      })
    )

    const successCount = writeResults.filter(Boolean).filter(w => w.success).length
    log(`  ✅ 完成 ${successCount}/${p5_plan.reports.length} 份报告的写入${successCount < p5_plan.reports.length ? '（有失败）' : ''}`)
  } else {
    log('  ⚠️ 没有规划出新报告（可能已有完整覆盖）')
  }


  // 生成HTML版本
  const p5_html = await agent(
    `运行HTML报告生成脚本:
    python3 ${SKILL_SCRIPTS}/generate_html.py ${SRC_BASE}/${companyName}/submittable_reports/

    检查输出目录 ${SRC_BASE}/${companyName}/submittable_reports/reports_html/ 是否生成了对应的 .html 文件。

    如果脚本不可用或报错，说明原因。`,
    { label: '🎨 生成HTML版本', phase: '报告编写' }
  )

  markPhase(6, '✅')
  showProgress()
}

// ============================================================
// Phase 7: 自审
// ============================================================
phase('自审')

if (progress.reports_count === 0) {
  log('[7/8] ⏭️ 无报告需自审')
  markPhase(7, '⏭️')
} else {
  markPhase(7, '🔄')
  log('[7/8] 报告自审')

  // 读取判定规则和厂商VulnType
  const p6_rules = await agent(
    `读取以下两个文件的内容（用Read工具）:

1.  ${SKILL_SCRIPTS}/../references/judgment-rules.md
   — 包含 F(不符)/R(保留)/T(属实) 三级判定规则
   — 包含严重等级判定参考表
   — 包含 401/403 处理规则

2.  ${SRC_BASE}/${companyName}/VulnType.html
   — 如果不存在则读取 ${SRC_BASE}/${companyName}/*_Information.html
   — 如果都不存在，读取 references/vulntype-matrix.md 中该厂商的条目
   — 提取接受的漏洞类型和忽略清单

输出读取结果摘要。`,
    { label: '📖 读取判定规则 + VulnType', phase: '自审' }
  )

  const p6_audit = await agent(
    `你是SRC报告审计专家，对 ${companyName} 的报告做**最终判定**。

===== 判定规则（已截断至2500字，完整版在文件中）=====
${(p6_rules || '(读取失败)').substring(0, 2500)}
======================================================

报告目录: ${SRC_BASE}/${companyName}/submittable_reports/
先用 ReadFile 读取完整的 judgment-rules.md 和 VulnType.html
运行审计脚本检查格式: python3 ${SKILL_SCRIPTS}/audit_reports.py 2>&1 | tail -30

你的任务 — 对每份报告逐项判定：

### 1. 文件格式检查
- 命名规范: {等级}_{类型}_{公司}_{简述}.md
- 包含完整HTTP请求/响应包
- 包含curl可复现命令
- 敏感数据已脱敏

### 2. 等级准确性判定
对照 judgment-rules.md 的等级判定表:
- 报告标注的严重等级是否与发现的实际危害匹配？
- 是否过高/过低？

### 3. 厂商接受度判定
对照厂商 VulnType:
- 漏洞类型是否在厂商接受范围内？
- 是否在忽略清单中？
- 如短信轰炸/Self-XSS/Swagger不可利用/HTTP头配置等

### 4. 重复检测（重要 — 提交前必须检查）
比较所有报告之间的端点重叠情况:
- 同API前缀 + 同类漏洞 → 标记为重复，建议合并
- 不同前缀 + 同类漏洞 → 确认非同一修复方案，可独立提交
- 重复报告 verdict 设为 skip_duplicate

### 5. 最终判定 (F/R/T)
- **F (不符)** — 资产不符/无复现细节/漏洞不成立/明确不收 → 移入 _invalid/
- **R (保留)** — 非敏感泄露/利用门槛高/暴露未深入 → 需进一步观察
- **T (属实)** — 可提交补天

输出JSON格式，每份报告一个判定结果。`,
    { label: '🔍 最终判定 (F/R/T)', schema: {
      type: 'object',
      properties: {
        reports: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              file_name: { type: 'string', description: '报告文件名' },
              verdict: {
                type: 'string',
                enum: ['T', 'R', 'F', 'skip_duplicate'],
                description: 'T=可提交, R=保留, F=不符, skip_duplicate=重复'
              },
              severity_accurate: { type: 'boolean', description: '严重等级判定是否准确' },
              type_accepted: { type: 'boolean', description: '漏洞类型是否在厂商接受范围内' },
              issues: { type: 'array', items: { type: 'string' }, description: '需要改进的问题列表' },
              suggestion: { type: 'string', description: '综合建议' },
            },
            required: ['file_name', 'verdict'],
          },
        },
      },
      required: ['reports'],
    }, phase: '自审' }
  )

  if (p6_audit && p6_audit.reports) {
    const tCount = p6_audit.reports.filter(r => r.verdict === 'T').length
    const rCount = p6_audit.reports.filter(r => r.verdict === 'R').length
    const fCount = p6_audit.reports.filter(r => r.verdict === 'F').length
    log(`  📊 判定结果: T(可提交) ${tCount} | R(保留) ${rCount} | F(不符) ${fCount}`)
    p6_audit.reports.filter(r => r.verdict === 'F').forEach(r => {
      log(`    🗑️ ${r.file_name}: ${(r.issues || []).join('; ')}`)
    })
    // F判定报告 → 移入 _invalid/ → 运行 consolidate_findings.py
    if (fCount > 0) {
      const fNames = p6_audit.reports.filter(r => r.verdict === 'F').map(r => r.file_name)
      await agent(
        `执行以下命令处理F判定的报告（${fCount} 份）:

1. 将以下报告移入 _invalid/ 目录:
${fNames.map(function(n) { return '   mv "' + SRC_BASE + '/' + companyName + '/submittable_reports/' + n + '" "' + SRC_BASE + '/' + companyName + '/submittable_reports/_invalid/' + n + '"' }).join('\\n')}

2. 运行整合脚本:
   python3 ${SKILL_SCRIPTS}/consolidate_findings.py ${SRC_BASE}/${companyName}/submittable_reports/

3. 确认文件已移动:
   ls -la "${SRC_BASE}/${companyName}/submittable_reports/_invalid/"`,
        { label: '🗑️ 处理F判定报告', phase: '自审' }
      )
    }
  }

  markPhase(7, '✅')
  showProgress()
}

// ============================================================
// Phase 8: 提交准备
// ============================================================
phase('提交准备')
markPhase(8, '🔄')
log('[8/8] 提交准备')

const p7_final = await agent(
  `提交准备 — 执行以下6项最终检查:

**检查清单：**

1. 文件名规范检查:
   ls "${SRC_BASE}/${companyName}/submittable_reports/"*.md
   确认文件名格式: {等级}_{类型}_{公司}_{简述}.md

2. 完整HTTP请求/响应包确认:
   对每份报告，用Read工具读取md文件，确认包含:
   - HTTP请求包（请求行+请求头+请求体）
   - HTTP响应包（状态行+响应头+响应体）
   - curl可复现命令

3. 漏洞URL复测:
   提取每份报告中的漏洞URL，用 curl -sI -H 'User-Agent: Mozilla/5.0 ...' 确认当前仍可访问且返回200（必须带浏览器UA）

4. HTML版本确认:
   ls "${SRC_BASE}/${companyName}/submittable_reports/reports_html/"*.html
   确认每份.md都有对应的.html

5. 厂商合规检查:
   Read ${SRC_BASE}/${companyName}/VulnType.html 或 ${SRC_BASE}/${companyName}/*_Information.html
   确认漏洞类型在厂商接受范围内 + 不在忽略清单中

6. 敏感数据脱敏确认:
   对每份报告Read内容，检查是否包含未脱敏的:
   - 手机号/身份证号
   - 真实的Cookie/Token
   - 内网IP/域名（非必要的）

**输出要求：**
- 列出每份报告及其6项检查结果（✅/❌）
- 按 严重→高危→中危→低危 排序
- 给出最终提交建议`,
  { label: '✅ 最终检查', phase: '提交准备' }
)

markPhase(8, '✅')


// ============================================================
// 最终总结
// ============================================================
log('')
log('╔══════════════════════════════════════════════════════════════╗')
log('║              🎉  七阶段全流程执行完成                        ║')
log('╠══════════════════════════════════════════════════════════════╣')
log(`║  厂商     │ ${(progress.company || '').padEnd(36)} ║`)
log(`║  模式     │ ${String(mode).padEnd(36)} ║`)
log(`║  发现数   │ ${String(progress.findings_count).padEnd(36)} ║`)
log(`║  报告数   │ ${String(progress.reports_count).padEnd(36)} ║`)
log('╠══════════════════════════════════════════════════════════════╣')
log(`║  ① ${progress.phase1}   ② ${progress.phase2}   ③ ${progress.phase3}   ④ ${progress.phase4}   ⑤ ${progress.phase5}   ⑥ ${progress.phase6}   ⑦ ${progress.phase7}   ⑧ ${progress.phase8}   ║`)
log('╚══════════════════════════════════════════════════════════════╝')
showProgress()

// Final return
return { company: companyName, mode: mode, done: true }

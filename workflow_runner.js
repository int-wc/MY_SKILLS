// SRC_SKILLS_V1 - 八阶段全流程 Workflow 编排
// 使用: Workflow({scriptPath: '...', args: {company: '货讯通科技', mode: 'full'}})
// mode: 'full' | 'phase3' (跳过资产发现和深度分析，直接挖洞) | 'phase5' (直接出报告)

export const meta = {
  name: 'src-full-scan',
  description: '补天SRC全流程：资产发现→深度分析→漏洞挖掘→验证→资产标记→报告→自审→提交',
  phases: [
    { title: '资产发现', detail: '读取厂商信息 + 解析Hunter资产 + 目标分类标记' },
    { title: '深度分析', detail: 'JS逆向 + API枚举 + 组件审计' },
    { title: '漏洞挖掘', detail: '按优先级测试所有攻击面' },
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
const SKILL_SCRIPTS = '/home/my/.claude/skills/SRC_SKILLS_V1/scripts'

let companyName, mode
if (typeof args === 'string') {
  companyName = args
  mode = 'full'
} else if (typeof args === 'object' && args) {
  companyName = args.company || '货讯通科技'
  mode = args.mode || 'full'
} else {
  companyName = null
  mode = 'full'
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
// 适用维度: port_scan, http_probe, unauth_test, weak_pass
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
    const app = ['port_scan', 'http_probe', 'unauth_test', 'dir_enum']
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
    if (!e) return ['port_scan', 'http_probe', 'unauth_test', 'dir_enum']
    const app = ['port_scan', 'http_probe', 'unauth_test', 'dir_enum']
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
// p1_portscan 也在外层作用域声明，供Phase 3引用
let p1_portscan
if (mode.startsWith('phase5')) {
  log('[1/8] ⏭️ 跳过（用户指定报告模式）')
  markPhase(1, '⏭️')
  p1_assets = { company_name: companyName, priority_targets: [], all_urls: [] }
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
  log('  例: Workflow({scriptPath: "...", args: {company: "货讯通科技", mode: "full"}})')
  return { status: 'need_company', message: '请指定目标公司名' }
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

  3. 优先级排序输出
     - 最高: [全端口发现][管理后台][境外资产]
     - 高: [范围内][新发现]
     - 中: [非常见端口][组件指纹]

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
  return { error: '资产发现失败', progress }
}

// 过滤已测试资产（避免重复测试）
if (p0_testedUrls.size > 0 && p1_assets?.priority_targets) {
  const before = p1_assets.priority_targets.length
  p1_assets.priority_targets = p1_assets.priority_targets.filter(t => !p0_testedUrls.has(t.url))
  p1_assets.all_urls = (p1_assets.all_urls || []).filter(u => !p0_testedUrls.has(u))
  const filtered = before - p1_assets.priority_targets.length
  if (filtered > 0) log(`  已过滤 ${filtered} 个已测试资产，跳过重复测试`)
}

// 记录 Phase 1 资产维度（port_scan + http_probe）
;(p1_assets.priority_targets || []).forEach(t => {
  const isLogin = (t.tags || []).includes('[管理后台]')
  dimTracker.record(t.url, 'port_scan', 'done')
  dimTracker.record(t.url, 'http_probe', 'done', { title: t.title || '' })
  if (isLogin) dimTracker.record(t.url, 'weak_pass', 'pending')
})

// 尝试全端口扫描扩充
p1_portscan = await agent(
  `你是SRC资产扫描专家。负责对 ${companyName} 做资产扩充。

  1. 检查 ${SRC_BASE}/${companyName}/hunter_info/ 下是否有CSV文件
  2. 如果有，提取前3个IP用于测试
  3. 检查目录下是否已有 masscan_results.gnmap 等扫描结果文件
  4. 如果工具可用（masscan 或 nmap），对提取的IP执行快速端口扫描
     - 优先用 sudo_helper.sh "masscan --rate=500 ..."
     - 不可用时用 sudo_helper.sh "nmap -T4 --top-ports 100 ..."
     - sudo_helper.sh 路径: /home/my/.local/bin/sudo_helper.sh
     - 调用格式: sudo_helper.sh "要执行的完整命令"
  5. 将新发现的端口与域名映射并探活 (httpx)
  6. 输出结构化结果，包含新发现资产的URL/IP/端口/服务信息

  输出新发现的资产列表。`,
  { label: '🔍 端口扫描扩充', phase: '资产发现', schema: {
    type: 'object',
    properties: {
      new_assets: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            url: { type: 'string', description: '完整URL，如 https://1.2.3.4:8443' },
            ip: { type: 'string', description: 'IP地址' },
            port: { type: 'number', description: '端口号' },
            title: { type: 'string', description: '网站标题' },
            service: { type: 'string', description: '服务类型/组件' },
            tags: { type: 'array', items: { type: 'string' }, description: '标签，如 [全端口发现]' },
          },
          required: ['url', 'ip', 'port'],
        },
      },
      summary: { type: 'string', description: '扫描结果摘要' },
    },
    required: ['new_assets', 'summary'],
  } }
)


// 提取端口扫描发现的新资产URL，供后续阶段使用
const p1_portscan_new_urls = (p1_portscan?.new_assets || []).map(a => a.url).filter(Boolean)
if (p1_portscan_new_urls.length > 0) {
  log(`  端口扫描发现 ${p1_portscan_new_urls.length} 个新资产:`)
  p1_portscan_new_urls.slice(0, 5).forEach(u => log(`    ${u}`))
}

// 记录端口扫描资产维度
;(p1_portscan?.new_assets || []).forEach(a => {
  dimTracker.record(a.url, 'port_scan', 'done')
  dimTracker.record(a.url, 'http_probe', 'done', { title: a.title || a.service || '' })
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
let p3_unauth, p3_other, p3_quick, p4_dirscan, p4_verify
// 聚合发现数据，供 Phase 5 写入线索文件
let p3_findings_data = []

if (mode.startsWith('phase3') || mode.startsWith('phase5')) {
  log('[2/8] ⏭️ 跳过（用户指定模式）')
  markPhase(2, '⏭️')
} else {
  markPhase(2, '🔄')
  log(`[2/8] 深度分析 — ${companyName}`)

  const targets = (p1_assets.priority_targets || []).slice(0, 2)

  if (targets.length === 0) {
    log('  ⚠️ 无高优先级目标可分析')
    markPhase(2, '⏭️')
  } else {
    const analyses = await pipeline(
      targets,
      async (target) => {
        return await agent(
          `你是JS逆向和API发现专家，分析目标: ${target.url}

      执行四层分析：
      1. 第一层 - 定位API入口:
         curl -s 获取页面HTML，提取 <script src>
         对每个JS，查找 baseURL/API_HOST/API_BASE/gatewayUrl/serverUrl
         grep -oP '(baseURL|API_HOST|API_BASE)\\s*[:=]\\s*["'"'"'][^"'"'"]+["'"'"]'

      2. 第二层 - 路径模式提取:
         全量提取 "/xxx/yyy" 路径，按一级目录分组统计
         关注非标准前缀: /gateway/, /dwr/, /sys/, /manage/, /crm/, /erp/
         不要只找 /api/ — 真正的API常在自定义前缀下

      3. 第三层 - Source Map还原:
         检查 //# sourceMappingURL= 并尝试下载 .js.map
         Webpack chunk分析: chunks/ js/ 命名暴露功能模块

      4. 第四层 - 敏感信息提取:
         - AccessKey: AKID模式、AKIA模式、LTAI(阿里云)
         - OSS存储桶密钥: OBS_ACCESS_KEY / OSS_ACCESS_KEY / AWS_ACCESS_KEY
         - SecretKey/Token/密码硬编码
         - 拼接模式: accessKey分段存储在多个变量中(key_part + key_part2)
         - 编码检测: Base64(A-Za-z0-9+/=)、Hex(0x..)、Unicode(\u00xx)
         - JWT (eyJ...格式) → 解码看payload中user/role/exp
         - 数据库连接串 → mongodb/mysql/postgresql/redis://
         - 内网IP/域名 → 判断是哪个环境(dev/test/prod)
         - 测试账号硬编码

      5. 鉴权方式识别:
         - Authorization: Bearer / Basic
         - X-TOKEN / X-Auth-Token
         - Cookie + sessionId
         - localStorage Token存放

      ⚡ 6. 凭证反思（关键思维环节 — 找到凭证后必须思考）:
         找到accessKey+secretKey → 这是哪个云服务的？试列举 OBS/S3/OSS Bucket
         找到OSS连接信息 → endpoint + bucket → 直接测试 ListObjects
         找到账号密码 → 这是哪个系统的？钉钉/LDAP/数据库/邮件
         找到JWT → 解码看user/role，试调API看是否越权
         找到内网IP → 从命名判断服务名(k8s)、环境后缀(dev/test/ontest)
         找到API路径 → 功能命名可推断数据敏感度

      注意: 只做读取分析。遇到混淆JS尝试识别混淆类型(webpack/jscrambler/_0x)。`,
          { label: `🔬 JS分析: ${target.url}`, phase: '深度分析' }
        )
      },
      (result, target) => {
        // aggregate findings
        return result
      }
    )

    log(`  完成 ${analyses.filter(Boolean).length} 个目标的分析`)

    // 提取 JS 分析结果传给 Phase 3
    if (analyses && analyses.length > 0) {
      p2_discoveries_text = analyses.filter(Boolean)
        .map((a, i) => `【目标${i+1}JS分析结果】\n${a}`)
        .join('\n\n')
      // 记录JS分析维度
      targets.forEach(t => dimTracker.record(t.url, 'js_analysis', 'done'))
    }
  }

  markPhase(2, '✅')
  showProgress()
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

  // Tier 1: 高优目标（全量测试：未授权+弱口令+目录枚举）
  const targets = (p1_assets.priority_targets || []).slice(0, 5)
  const p1_portscan_targets = p1_portscan?.new_assets?.length
    ? p1_portscan.new_assets.slice(0, 5).map(a => ({
        url: a.url, ip: a.ip, port: a.port, title: a.title || '',
        tags: [...(a.tags || []), '[全端口发现]'],
        priority: '最高', reason: '端口扫描发现'
      }))
    : []
  if (p1_portscan_targets.length > 0) {
    targets.push(...p1_portscan_targets)
  }

  // Tier 2: 剩余资产快速探测（扩充维度覆盖，弥补仅2-3维度的缺口）
  const tier2_urls = [
    ...(p1_assets.priority_targets || []).slice(5).map(t => t.url),
    ...(p1_assets.all_urls || [])
  ].filter((v, i, a) => a.indexOf(v) === i)
   .filter(u => !targets.some(t => t.url === u))
   .slice(0, 30)

  const allUrls = [...targets.map(t => t.url), ...tier2_urls]
  const p1_scan_urls = (p1_portscan?.new_assets || []).map(a => a.url).filter(Boolean)

  if (targets.length === 0 && allUrls.length === 0) {
    log('  ⚠️ 无可用测试目标')
    markPhase(3, '⏭️')
  } else {
    // 3.1 未授权/信息泄露测试（遵循: 分析为底→第一性原理→扩散思维链）
    p3_unauth = await agent(
      `你是SRC漏洞挖掘专家，对 ${companyName} 执行未授权访问和信息泄露测试。

方法论指引：
1. 分析为底 — 所有判断基于实际HTTP响应，不做猜测
2. 第一性原理 — 每个端点问：这个请求发了什么？响应返回了什么？真的需要认证吗？
3. 扩散思维链 — 发现一个API后，思考关联系统（同域名其他端口、同IP其他服务、同框架其他路径）

高优目标列表:
${targets.map(t => `  ${t.priority} | ${t.url} | tags: ${(t.tags||[]).join(',')}`).join('\n')}

常规URL列表:
${allUrls.map(u => `  ${u}`).join('\n')}

第2阶段JS逆向发现的隐藏端点/API路径:
${p2_discoveries_text ? p2_discoveries_text.substring(0, 4000) : '（无 JS 分析数据）'}

测试矩阵（按优先级执行）:
1. 未授权访问 - 直接curl不带任何Cookie/Token
   - 从URL提取域名，构造常见API路径:
     /api/v1/user/info, /api/v1/order/list, /admin/user, /api/v1/config
   - 对管理后台: /admin/, /console/, /manager/
   - 对Spring Boot: /actuator, /actuator/env, /actuator/heapdump

2. API文档泄露:
   /swagger-ui.html, /v2/api-docs, /v3/api-docs, /doc.html

3. 配置文件泄露:
   /.env, /.git/config, /WEB-INF/web.xml, /phpinfo.php, /robots.txt

4. HTTP方法过度:
   对发现的端点尝试 OPTIONS、PUT、DELETE

5. 批量对比:
   对每个发现的API，对比 带Cookie vs 无Cookie 的响应差异
   响应大小相近 + 200 = 可能未授权

对每个潜在漏洞记录:
- 类型、端点、HTTP请求/响应摘要、状态码、置信度

只做读取探测。`,
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

    // 3.2 越权/弱口令/其他测试
    p3_other = await agent(
      `你是SRC漏洞挖掘专家，对 ${companyName} 执行越权/弱口令等测试。

高优目标:
${targets.map(t => `  ${t.url}`).join('\n')}

第2阶段JS逆向发现的隐藏端点/API路径:
${p2_discoveries_text ? p2_discoveries_text.substring(0, 4000) : '（无 JS 分析数据）'}

1. 越权测试:
   - 对含数字ID的路径，尝试替换ID值
   - 观察响应差异（是否返回不同用户数据）

2. 弱口令枚举:
   - 对登录接口尝试: admin/admin, admin/123456, admin/Admin@123, test/test
   - 从公司名 "${companyName}" 拼音/英文名衍生用户名
   - 测试JSON API登录

3. 信息泄露检查:
   - 响应体中是否包含多余字段（密码/身份证/手机号）
   - 错误信息是否泄露路径/版本

4. 目录/文件遍历:
   - 测试 ../ 路径穿越
   - 测试下载功能

只做读取探测。`,
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

    // Tier 2: 剩余资产快速未授权探测（批量curl常见路径，填补维度覆盖缺口）
    let p3_quick = null
    if (tier2_urls.length > 0) {
      p3_quick = await agent(
        `对 ${companyName} 的以下剩余资产做快速未授权探测。

剩余资产列表（${tier2_urls.length} 个）:
${tier2_urls.map(u => `  ${u}`).join('\n')}

执行快速探测（每个目标只做轻量探测）:
1. curl -sI 每个URL确认HTTP状态码
2. 对返回200/401/403的，尝试常见路径:
   - API: /api/v1/user, /api/v1/config, /swagger-ui.html, /v2/api-docs
   - 后台: /admin/, /console/, /login, /manager/
   - 配置: /.env, /robots.txt, /WEB-INF/web.xml
   - 组件: /actuator, /druid, /nacos
3. 有发现的才记录，无发现的不需输出
4. 每个发现附带 curl 命令`,
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
1. 先 curl -sI 获取 HTTP 状态码
2. 状态码 200/401/403 的，curl -s 获取响应体
3. 对比 带Cookie vs 无Cookie 的响应差异

**Step 3: 判定**
| 判定 | 条件 |
|------|------|
| confirmed | curl 返回 **200 + 响应体含实际敏感数据**（用户信息/订单列表/配置凭证/数据库内容），并且**不是**权限错误 |
| suspected | 返回 200/401 但响应体是权限错误（如 "没有接口访问权限"）, 或需要复杂利用条件 |
| needs_manual_test | 无法构造可测试 URL（如 JS 分析发现但无具体路径）|
| false_positive | URL 不可达 / 404 / 超时 / 返回无敏感数据 |

⚠️ **confirmed 的严格标准：**
1. 必须有 curl_command + http_status + evidence
2. **HTTP 200 + 权限错误（"没有接口访问权限" / "Unauthorized" / "需要登录"）= NOT confirmed**，这是认证在正常工作
3. **JS中找到的API路径 + curl未返回实际数据 = NOT confirmed**，这是SPA源码泄漏但不是未授权漏洞
4. 证据必须是实际的敏感数据片段，不是状态码本身
5. 三项条件缺一不可，不满足的降级为 suspected 或 needs_manual_test

输出时 confirmed_findings 只放 confirmed + suspected 的。false_positives 和 needs_manual_test 各自归位。`,
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
      const fp_count = p4_verify.false_positives?.length || 0
      const manual_count = p4_verify.needs_manual_test?.length || 0
      log(`  复测完成: ${p4_verify.confirmed_findings.length} 个确认有效${fp_count > 0 ? `, ${fp_count} 个 false_positive` : ''}${manual_count > 0 ? `, ${manual_count} 个需手动验证` : ''}`)
      // 记录各条验证的HTTP状态
      p4_verify.confirmed_findings.forEach(f => {
        const statusIcon = f.http_status === 200 ? '✅' : f.http_status === 401 ? '🔒' : f.http_status === 403 ? '🚫' : '❓'
        log(`  ${statusIcon} [${f.http_status}] ${f.title} → ${f.endpoint}`)
        if (f.curl_command) log(`     curl: ${f.curl_command.substring(0, 120)}`)
      })
      progress.findings_count = p4_verify.confirmed_findings.length
      // 更新发现状态（含 http_status + curl_command 要求检查）
      if (p3_findings_data.length > 0) {
        const confirmedEndpoints = new Set(
          p4_verify.confirmed_findings.filter(f => f.confidence === 'confirmed' && f.curl_command).map(f => f.endpoint)
        )
        const suspectedEndpoints = new Set(
          p4_verify.confirmed_findings.filter(f => f.confidence === 'suspected' || !f.curl_command).map(f => f.endpoint)
        )
        const fpEndpoints = new Set((p4_verify.false_positives || []).map(f => f.title))
        const manualTitles = new Set((p4_verify.needs_manual_test || []).map(f => f.title))
        p3_findings_data = p3_findings_data.map(f => {
          if (fpEndpoints.has(f.title)) return { ...f, status: 'false_positive', phase_discovered: 'phase4' }
          if (manualTitles.has(f.title)) return { ...f, status: 'needs_manual_test', phase_discovered: 'phase4' }
          if (confirmedEndpoints.has(f.endpoint)) return { ...f, status: 'confirmed', phase_discovered: 'phase4' }
          if (suspectedEndpoints.has(f.endpoint)) return { ...f, status: 'suspected', phase_discovered: 'phase4' }
          return f
        })
        // 从验证结果中补充 curl_command 和 http_status
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

  // 2. 如果有效发现仍然较少，尝试目录扫描兜底
  if (progress.findings_count < 3) {
    p4_dirscan = await agent(
      `对 ${companyName} 执行目录扫描兜底（因当前发现较少）。\n\n目标URL:\n${(p1_assets.priority_targets || []).slice(0, 3).map(t => t.url).join('\n')}\n\n使用 dirsearch 扫描常见路径:\n- 后台管理: /admin/, /manager/, /console/, /system/\n- 备份文件: /backup/, *.bak, *.zip, *.tar.gz\n- 文件上传: /uploads/, /files/\n- 配置泄露: /.git/, /.svn/, /.env, /WEB-INF/web.xml\n- 组件端点: /actuator/, /druid/, /nacos/\n\n如果 dirsearch 不可用，用 curl 手动探测以上路径。\n对新发现的端点做未授权测试。\n\n输出所有发现。`,
      { label: '📂 目录扫描兜底', schema: {
        type: 'object',
        properties: {
          findings: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                title: { type: 'string' },
                endpoint: { type: 'string' },
                severity: { type: 'string' },
                status_code: { type: 'number' },
                description: { type: 'string' },
              },
            },
          },
        },
      }, phase: '验证取证' }
    )
    const extra = p4_dirscan?.findings || []
    progress.findings_count += extra.length
    if (extra.length > 0) {
      log(`  目录扫描补充发现 ${extra.length} 个`)
      extra.forEach(f => log(`    [${f.severity}] ${f.endpoint} (${f.status_code})`))
      // 将目录扫描发现纳入线索追踪
      p3_findings_data.push(...extra.map(f => ({
        title: f.title, type: '目录枚举', severity: f.severity,
        target: (p1_assets.priority_targets || [])[0]?.url || '',
        endpoint: f.endpoint, confidence: 'exploratory',
        curl_command: '', phase_discovered: 'phase4_dirscan', status: 'confirmed'
      })))
    }
    // 记录目录枚举维度（手动探测 → dir_enum，dirsearch → dirsearch_scan）
    ;(p1_assets.priority_targets || []).slice(0, 3).forEach(t => {
      dimTracker.record(t.url, 'dir_enum', 'done')
      if (extra.length > 0) dimTracker.record(t.url, 'dirsearch_scan', 'done')
    })
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
    ...(typeof p1_portscan !== 'undefined' && p1_portscan?.new_assets ? p1_portscan.new_assets.map(a => ({ url: a.url, ip: a.ip, port: a.port, title: a.title || a.service || '', tags: a.tags || [] })) : []),
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
    const p5_findings_json = JSON.stringify(p3_findings_data, null, 2)

    const p5_mark = await agent(
      `你是SRC资产状态管理专家，对 ${companyName || ''} 的资产做测试状态标记并持久化存储。

===== 结构化测试维度数据 =====
${p5_dim_report}
==============================

===== 本批次发现的线索/漏洞 =====
${p3_findings_data.length > 0 ? p5_findings_json.substring(0, 4000) : '(无发现)'}
================================

=== 维度说明 ===
| 维度 | 说明 |
|------|------|
| port_scan | masscan/nmap端口扫描 |
| http_probe | HTTP探活，确认是否Web服务 |
| unauth_test | 无Cookie/Token的未授权端点探测 |
| dir_enum | 手动目录枚举（含自定义前缀，如 /gateway/ /dwr/ /sys/） |
| dirsearch_scan | 全量dirsearch目录扫描 |
| weak_pass | 弱口令/默认凭证测试 |
| js_analysis | JS逆向+API端点提取 |

=== 你的任务分为两部分 ===

**Part A: 资产状态标记（必做）**
对每个资产判断「已完全测试完毕 / 还未测试完毕 / 无法进行测试」。

自动判定仅供参考，请结合你的专家判断确认或修正：

- **「已完全测试完毕」** — 所有适用维度已完成 + 无发现或已出报告
- **「还未测试完毕」** — 存在缺漏维度（尤其是你判断仍可深入的维度）或发现了可疑点但未跟进
  - 即使「已完成」列表填满了，如果你认为某个维度测试不充分（如 dir_enum 只扫了通用路径，没试自定义前缀），可降级
- **「无法进行测试」** — 端口关闭/非HTTP/不在范围/已知第三方CDN

每次标记必须给出 reason 字段（不要用 notes 字段，必须用 reason ），例如：
- "已完成全部7维度测试，无新发现"
- "缺漏 dir_enum, dirsearch_scan 维度，仅做了端口扫描和未授权探测"
- "端口关闭，无法建立TCP连接"
- "仅做了 port_scan + http_probe，未授权检测和目录枚举均未执行"

**Part B: 线索/漏洞存档（如有发现）**
1. 读取已有线索文件 ${findingsPath}（Read工具），如不存在则新建
2. 合并本次发现的线索到已有记录中（按 endpoint 去重）
3. 用Write工具写入 ${findingsPath}

=== 操作要求 ===
1. 先用Read读取 ${trackerPath}，保留不在本次清单中的旧资产记录
2. 用Write写入 ${trackerPath}（合并写入）
3. 用Read/Write处理 ${findingsPath}（合并写入）
4. status字段必填，reason字段必填（不要用notes代替），phases_tested必填
5. last_tested 格式: 2026-06-19
6. ⚠️ 如果之前文件中有 notes 字段，请改为 reason 字段输出。不要保留 notes 字段。`,
      { label: '🏷️ 资产状态+线索存档', schema: {
        type: 'object',
        properties: {
          assets: {
            type: 'object',
            additionalProperties: {
              type: 'object',
              properties: {
                status: { type: 'string', enum: ['已完全测试完毕', '还未测试完毕', '无法进行测试'] },
                phases_tested: {
                  type: 'array',
                  items: {
                    type: 'string',
                    enum: ['port_scan', 'http_probe', 'unauth_test', 'dir_enum', 'dirsearch_scan', 'weak_pass', 'js_analysis'],
                  },
                  description: '该资产已完成的测试维度，agent可基于泛化判断增减'
                },
                last_tested: { type: 'string' },
                reason: { type: 'string', description: '标记理由，必须给出具体依据。如：缺漏哪些维度/端口关闭/全部完成。这是必填字段，不能为空。' },
              },
              required: ['status', 'phases_tested', 'last_tested', 'reason'],
            },
          },
        },
        required: ['assets'],
      }, phase: '资产标记' }
    )

    if (p5_mark && p5_mark.assets) {
      // 兼容处理：如果agent仍写了notes而非reason，自动转换
      Object.values(p5_mark.assets).forEach(a => {
        if (!a.reason && a.notes) { a.reason = a.notes; delete a.notes }
      })
      const counts = { '已完全测试完毕': 0, '还未测试完毕': 0, '无法进行测试': 0, '无reason': 0 }
      Object.values(p5_mark.assets).forEach(a => {
        if (counts[a.status] !== undefined) counts[a.status]++
        if (!a.reason) counts['无reason']++
      })
      log(`  📊 标记完成: 已完成 ${counts['已完全测试完毕']} | 未完成 ${counts['还未测试完毕']} | 无法测试 ${counts['无法进行测试']}`)
      if (counts['无reason'] > 0) log(`  ⚠️ 有 ${counts['无reason']} 个资产缺少 reason 字段`)
      // 线索已由agent写入文件
      if (p3_findings_data.length > 0) {
        log(`  📝 线索已存档至 asset_findings.json（${p3_findings_data.length} 条）`)
      }
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

  // 汇总所有阶段的结构化发现
  const allFindingsData = [
    ...(typeof p3_unauth !== 'undefined' && p3_unauth?.findings ? p3_unauth.findings : []),
    ...(typeof p3_other !== 'undefined' && p3_other?.findings ? p3_other.findings : []),
    ...(typeof p4_dirscan !== 'undefined' && p4_dirscan?.findings ? p4_dirscan.findings : []),
  ]
  const findingsJSON = JSON.stringify(allFindingsData, null, 2)

  // 用结构化schema让agent返回【报告规划】（仅分片规划，不生成内容）
  // content由后续write agent根据finding_indices各自生成，避免token爆炸
  const p5_plan = await agent(
    `你是SRC报告编写专家，为 ${companyName} 的漏洞编写标准报告。

你的任务：规划需要生成的报告清单，仅规划分片方案（不生成报告正文）。

⚠️ 重要规则：
1. 只对【确认有效】的漏洞写报告，不要虚构
2. 同类漏洞合并为一个综合报告
3. 文件名以中文开头：{严重等级}_{漏洞类型}_{公司简称}_{简述}.md
   例：高危_信息泄露_货讯通_DWR接口.md
4. 按严重等级分批：严重/高危一批、中危一批、低危/信息一批

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
1. 根据上述发现的原始数据，生成完整的Markdown格式报告
2. 调用Write工具写入文件 file_path: "${filePath}"
3. 执行 ls -la "${filePath}" 和 wc -l "${filePath}" 确认写入成功
4. 读取文件内容确认完整性

报告格式要求：
- 先用Read工具读取 ${SKILL_SCRIPTS}/../references/report-templates.md 了解标准模板结构
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

### 4. 最终判定 (F/R/T)
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
  `提交准备收尾工作:

1. 列出 ${SRC_BASE}/${companyName}/submittable_reports/ 下的所有报告
2. 按 严重→高危→中危→低危 排序
3. 确认HTMl版本已生成:
   ls ${SRC_BASE}/${companyName}/submittable_reports/reports_html/
4. 生成提交顺序清单
5. 如果 ${SRC_BASE}/${companyName}/VulnType.html 或 Information.html 中有厂商忽略清单，
   确认报告不在忽略清单中

输出提交建议。`,
  { label: '✅ 最终检查', phase: '提交准备' }
)

markPhase(8, '✅')

// ============================================================
// 最终总结
// ============================================================
log('')
log('╔══════════════════════════════════════════════════════════════╗')
log('║              🎉  八阶段全流程执行完成                        ║')
log('╠══════════════════════════════════════════════════════════════╣')
log(`║  厂商     │ ${(progress.company || '').padEnd(36)} ║`)
log(`║  模式     │ ${String(mode).padEnd(36)} ║`)
log(`║  发现数   │ ${String(progress.findings_count).padEnd(36)} ║`)
log(`║  报告数   │ ${String(progress.reports_count).padEnd(36)} ║`)
log('╠══════════════════════════════════════════════════════════════╣')
log(`║  ① ${progress.phase1}   ② ${progress.phase2}   ③ ${progress.phase3}   ④ ${progress.phase4}   ⑤ ${progress.phase5}   ⑥ ${progress.phase6}   ⑦ ${progress.phase7}   ⑧ ${progress.phase8}   ║`)
log('╚══════════════════════════════════════════════════════════════╝')
showProgress()

return {
  company: companyName,
  mode,
  progress: { ...progress },
  summary: {
    priority_targets: (p1_assets?.priority_targets || []).length,
    findings: progress.findings_count,
    reports: progress.reports_count,
  },
}

// ============================================================
// Domain Server — C/S 架构服务端
// 派发单域 Client workflow(并行,每批≤maxParallel) → 收集产出 →
// 聚焦分析(原语合理性/跨域链路/可利用性) → 只输出可提交链报告
//
// 使用: Workflow({scriptPath: '.../domain_server.js', args: {company:'抖音'}})
//   args: {company, domains?:[], maxParallel?:10, skipReport?:bool}
//
// 依赖: 同目录 workflow_runner.js 作为 Client(支持 mode:'domain' + work_dir)
// 每 Client 独立工作区: {SRC_BASE}/{company}/works/{domain}/
// ============================================================

export const meta = {
  name: 'src-domain-server',
  description: 'C/S架构服务端：单域Client派发→收集产出→聚焦分析(原语/链路/可利用性)→汇总报告',
  phases: [
    { title: '域清单', detail: '解析/提取待掘主域（用户传入或从 assets_info 提取）' },
    { title: 'Client派发', detail: '并行派发单域 Client workflow（每批≤maxParallel）' },
    { title: '产出收集', detail: '收集各 Client 工作区 findings' },
    { title: '聚焦分析', detail: '原语合理性 + 跨域链路 + 可利用性判定' },
    { title: '汇总上报', detail: '只输出可提交链报告' },
  ],
}

const SRC_BASE = '/home/my/butiansrc/Exclusive_SRC'
const SKILL_DIR = '/home/my/.claude/skills/SRC_SKILLS_V1'
const CLIENT_SCRIPT = `${SKILL_DIR}/workflow_runner.js`

// ============================================================
// 解析参数
// ============================================================
let opts = null
let companyName = null
let domains = []
let maxParallel = 0
if (typeof args === 'string') {
  try { opts = JSON.parse(args) } catch (_) { /* treat as company */ }
  if (!opts || typeof opts !== 'object') { opts = {}; companyName = args }
} else if (typeof args === 'object' && args) {
  opts = args
}
companyName = companyName || opts.company || null
domains = (opts.domains || []).map(d => String(d).trim().toLowerCase()).filter(Boolean)
maxParallel = Number(opts.maxParallel) > 0 ? Number(opts.maxParallel) : 10

if (!companyName) {
  log('⚠️ 需指定 company 参数，如: {company:"抖音"}')
  return { error: 'need_company', message: '请指定company' }
}

// ============================================================
// Phase 1: 域清单
// ============================================================
phase('域清单')
let resolved_domains = []
if (domains.length > 0) {
  resolved_domains = domains
  log(`[1/5] 使用用户指定 ${domains.length} 个域`)
} else {
  log('[1/5] 从 assets_info 提取主域清单...')
  const domList = await agent(
    `你是资产分析师。用 Bash/Read 读取 ${SRC_BASE}/${companyName}/assets_info/ 目录下所有 CSV，
    从 url 列提取每个资产的主域（去掉 scheme/端口/路径，只保留注册主域如 xxx.chehejia.com 的最后两级或完整子域）。
    输出每行一个唯一主域，去重，按出现次数降序。最后输出"共 N 个域"。`,
    { label: '🌐 提取主域清单', phase: '域清单' }
  )
  const lines = String(domList || '').split('\n').map(l => l.trim()).filter(Boolean)
  resolved_domains = lines
    .map(l => l.replace(/\s*共 \d+ 个域.*$/, '').trim())
    .filter(l => /\./.test(l) && !/^[0-9 ]+$/.test(l) && !l.startsWith('共'))
    .slice(0, 200)
  log(`  → 提取 ${resolved_domains.length} 个主域`)
}

if (resolved_domains.length === 0) {
  log('⚠️ 无可用域')
  return { error: 'no_domains', domains: 0 }
}

// ============================================================
// Phase 2: 派发 Client（并行，每批 maxParallel；每 Client 独立工作区）
// ============================================================
phase('Client派发')
log(`[2/5] 派发 ${resolved_domains.length} 个域名，单批 ${maxParallel} 并行`)
const results = []
for (let i = 0; i < resolved_domains.length; i += maxParallel) {
  const batch = resolved_domains.slice(i, i + maxParallel)
  log(`  ▶ 批次 ${Math.floor(i / maxParallel) + 1}/${Math.ceil(resolved_domains.length / maxParallel)}（${batch.length} 个域）`)
  const batchRes = await parallel(
    batch.map((d) => () => {
      const workDir = `${SRC_BASE}/${companyName}/works/${d.replace(/[^\w.-]/g, '_')}`
      return workflow({
        scriptPath: CLIENT_SCRIPT,
        args: { mode: 'domain', company: companyName, domain: d, work_dir: workDir },
      }).then((rv) => ({ domain: d, work_dir: workDir, client: rv || null }))
    })
  )
  const ok = batchRes.filter(Boolean)
  results.push(...ok)
  log(`  ✔ 批次完成 ${ok.length} 个 client`)
}
log(`  ✅ 全部 ${results.length} 个 client 派发完成`)

// ============================================================
// Phase 3: 产出收集（读各 work_dir 的 asset_findings.json）
// ============================================================
phase('产出收集')
const producer_doms = []
const collect = await agent(
  `读取以下 ${results.length} 个 Client 工作区的 asset_findings.json，汇总有产出的：
${results.map(r => `  ${r.domain}: ${r.work_dir}/asset_findings.json`).join('\n')}
对每个文件：若 findings 数组非空，列出每条的 {endpoint, type, severity, confidence, status}。
只输出【有 findings 的域】，每域一行: 域 | findings条数 | 各条摘要.
若全部为空输出"全部无产出"。`,
  { label: '📥 收集 Client 产出', phase: '产出收集' }
)
log(String(collect || '').substring(0, 2000))

// ============================================================
// Phase 4: 聚焦分析（原语合理性 + 跨域链路 + 可利用性）
// ============================================================
phase('聚焦分析')
const focusAnalysis = await agent(
  `你是 SRC 聚焦分析专家，对本次 C/S 多域挖掘的所有产出做**有效可利用性裁决**。

背景产出:
${String(collect || '（无产出）')}

任务(只对有产出的域/发现进行):
1.**原语合理性**: 每个发现的 business_attr/type 判定是否合理（是否真是该原语，还是误报）。
2.**跨域原语链**: 多个不同域的发现，其业务原语能否跨域串联成有效链
   （如 域A的SSRF + 域B的认证绕过 = 账户接管链）。对照原语链关系。
3.**可利用性**: 逐条判定 confirmed / 需测试账号 / 无法利用 / 误报。
   - 已严格 curl 确认且敏感数据回显 → confirmed
   - 需登录态/测试账号才能验证 → 标记需测试账号（红线: 自备账号）
   - 权限错误/无敏感数据 → 误报
4.**只输出可提交链**: 每条给出 结论+证据+原语链(若有)+建议等级。

输出 JSON: {findings:[{domain, endpoint, primitive, verdict: 可提交/需账号/误报, chain: 序号或null, reason}]}`,
  { label: '🔍 聚焦分析', phase: '聚焦分析', schema: {
    type: 'object',
    properties: {
      findings: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            domain: { type: 'string' },
            endpoint: { type: 'string' },
            primitive: { type: 'string' },
            verdict: { type: 'string', enum: ['可提交', '需测试账号', '需人工复核', '误报'] },
            chain: { type: 'string', description: '跨域原语链描述，无则null' },
            reason: { type: 'string' },
          },
          required: ['domain', 'endpoint', 'verdict'],
        },
      },
    },
    required: ['findings'],
  }, phase: '聚焦分析' }
)

// ============================================================
// Phase 5: 汇总上报
// ============================================================
phase('汇总上报')
const submittable = (focusAnalysis && focusAnalysis.findings || []).filter(f => f.verdict === '可提交')
const needAcct = (focusAnalysis && focusAnalysis.findings || []).filter(f => f.verdict === '需测试账号')
log(`[5/5] 汇总：可提交 ${submittable.length} | 需测试账号 ${needAcct.length} | 总计 ${(focusAnalysis && focusAnalysis.findings || []).length} 条结论`)

if (submittable.length > 0) {
  const report = await agent(
    `按 补天 报告规范，为以下【可提交】发现生成汇总报告（.md，含请求/响应证据、原语链标注）:
${JSON.stringify(submittable, null, 2)}
写入 ${SKILL_DIR}/reports/cs_${companyName}_report.md 或用户指定位置。`,
    { label: '📄 生成汇总报告', phase: '汇总上报' }
  )
  log(report || '报告已生成')
} else {
  log('无直接可提交项（多为需测试账号或误报）')
}

return {
  company: companyName,
  domains_total: resolved_domains.length,
  clients: results.length,
  submittable: submittable.map(f => ({ domain: f.domain, endpoint: f.endpoint, chain: f.chain })),
  need_account: needAcct.map(f => ({ domain: f.domain, endpoint: f.endpoint })),
  all_verdicts: (focusAnalysis && focusAnalysis.findings || []).length,
}
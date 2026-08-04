// ============================================================
// Domain Server — C/S 架构分析服务端
// 职责: 工作区登记 → 产出收集 → 聚焦分析(原语合理性/跨域链路/可利用性) → 只输出可提交链报告
//
// ⚠️ 引擎硬约束: 嵌套 workflow() 向子脚本传 args 会被丢弃（子 args 为 undefined）。
//   因此 **Client 派发由编排器(主循环)发起独立顶层 workflow**（见下第2步），
//   本服务端只负责收集各 Client 工作区产出并做聚焦分析。
//
// 用法（C/S 三步）:
//   1. [编排器] 域清单: Workflow({scriptPath:'.../domain_server.js', args:{company:'抖音', resolveOnly:true}})
//                       → 返回 {domains:[...]}
//   2. [编排器] 并行派发: 每域一个【独立顶层】Workflow({scriptPath:'.../workflow_runner.js',
//                       args:{mode:'domain', company:'抖音', domain:X, work_dir:'.../works/X/'}})
//                       并行度 ≤ maxParallel；每 Client 独立工作区，产出写 {work_dir}/asset_findings.json
//   3. [分析服务端] 本脚本: Workflow({scriptPath:'.../domain_server.js',
//                       args:{company:'抖音', domains:[...] 或 work_dirs:[...]}})
//                       → 收集 → 聚焦分析 → 汇总报告
// ============================================================

export const meta = {
  name: 'bsrc-domain-server',
  description: 'C/S架构分析服务端：登记工作区→收集产出→聚焦分析(原语/链路/可利用性)→汇总报告',
  phases: [
    { title: '域清单', detail: '解析待掘主域（用户传入或从 assets_info 提取）' },
    { title: '工作区登记', detail: '计算各域 Client 工作区（派发由编排器以独立顶层 workflow 并行发起）' },
    { title: '产出收集', detail: '收集各 Client 工作区 findings' },
    { title: '聚焦分析', detail: '原语合理性 + 跨域链路 + 可利用性判定' },
    { title: '汇总上报', detail: '只输出可提交链报告' },
  ],
}

const SRC_BASE = '/home/my/SRC/BSRC'
const SKILL_DIR = '/home/my/.claude/skills/BSRC_SKILLS_V1'

// ============================================================
// 解析参数
// ============================================================
let opts = null
let companyName = null
let domains = []
let workDirs = []
let resolveOnly = false
if (typeof args === 'string') {
  try { opts = JSON.parse(args) } catch (_) { /* treat as company */ }
  if (!opts || typeof opts !== 'object') { opts = {}; companyName = args }
} else if (typeof args === 'object' && args) {
  opts = args
}
companyName = companyName || opts.company || null
domains = (opts.domains || []).map(d => String(d).trim().toLowerCase()).filter(Boolean)
workDirs = (opts.work_dirs || []).map(String).filter(Boolean)
resolveOnly = !!opts.resolveOnly

if (!companyName) {
  log('⚠️ 需指定 company 参数，如: {company:"抖音"}')
  return { error: 'need_company', message: '请指定company' }
}

// ============================================================
// Phase 1: 域清单
// ============================================================
phase('域清单')
let resolved_domains = domains
if (domains.length > 0) {
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

if (resolved_domains.length === 0 && workDirs.length === 0) {
  log('⚠️ 无可用域')
  return { error: 'no_domains', domains: 0 }
}

// resolveOnly: 只返回域清单（供编排器发起顶层 client 派发）
if (resolveOnly) {
  log(`[resolve] 返回 ${resolved_domains.length} 个域，供编排器并行派发顶层 Client`)
  return { company: companyName, domains: resolved_domains }
}

// ============================================================
// Phase 2: 工作区登记（派发由编排器以独立顶层 workflow 并行发起）
// ============================================================
phase('工作区登记')
// 优先用显式 work_dirs；否则由 domains 推导 {SRC_BASE}/{company}/works/{domain}/
let workers = []
if (workDirs.length > 0) {
  workers = workDirs.map(wd => ({ work_dir: wd, domain: wd.split('/').filter(Boolean).pop() || '?' }))
} else {
  workers = resolved_domains.map(d => ({
    domain: d,
    work_dir: `${SRC_BASE}/${companyName}/works/${d.replace(/[^\w.-]/g, '_')}`,
  }))
}
log(`[2/5] 登记 ${workers.length} 个 Client 工作区（派发由编排器发起独立顶层 workflow，并行度≤maxParallel）`)
for (const w of workers) log(`  · ${w.domain} → ${w.work_dir}`)

// ============================================================
// Phase 3: 产出收集（读各 work_dir 的 asset_findings.json）
// ============================================================
phase('产出收集')
const collect = await agent(
  `读取以下 ${workers.length} 个 Client 工作区的 asset_findings.json，汇总有产出的：
${workers.map(w => `  ${w.domain}: ${w.work_dir}/asset_findings.json`).join('\n')}
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
    `按 ByteSRC 报告规范，为以下【可提交】发现生成汇总报告（.md，含请求/响应证据、原语链标注）:
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
  workers: workers.length,
  submittable: submittable.map(f => ({ domain: f.domain, endpoint: f.endpoint, chain: f.chain })),
  need_account: needAcct.map(f => ({ domain: f.domain, endpoint: f.endpoint })),
  all_verdicts: (focusAnalysis && focusAnalysis.findings || []).length,
}
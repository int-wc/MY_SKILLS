// ZC_SKILLS_V1 - 360众测八阶段全流程 Workflow 编排
// 使用: Workflow({scriptPath: '...', args: {project: '1516_中远海运', mode: 'full'}})
// 默认项目: 自动探测当前目录下的项目
// mode: 'full' | 'phase3' (跳过资产发现和深度分析，直接挖洞) | 'phase5' (直接出报告) | 'url' (指定单个URL)

export const meta = {
  name: 'zc-full-scan',
  description: '360众测全流程：项目信息→资产发现→深度分析→漏洞挖掘→验证→资产标记→报告→自审→提交',
  phases: [
    { title: '项目信息+资产发现', detail: '读取VulnType/NOTICE + 解析资产清单 + VPN检查' },
    { title: '深度分析', detail: 'JS逆向 + API枚举 + 组件审计 + 开源系统识别' },
    { title: '漏洞挖掘', detail: '按优先级测试所有攻击面 + 本地部署 + 源码审计' },
    { title: '验证取证', detail: '复现确认 + 证据收集' },
    { title: '资产标记', detail: '标记已测资产状态并存储' },
    { title: '报告编写', detail: 'MD+HTML双格式输出' },
    { title: '自审', detail: '格式检查 + 重复检测' },
    { title: '提交准备', detail: '最终清单 + 检查时间截图' },
  ],
}

// ============================================================
// 解析参数
// ============================================================
const ZC_BASE = '/home/my/360zc'
const SKILL_SCRIPTS = '/home/my/.claude/skills/ZC_SKILLS_V1/scripts'

const BUSINESS_ATTR_GUIDE = `
**【本质业务属性驱动 — harness强制（第一优先级，先于参数驱动）】**
不要只看API名字或参数名，先判定每个端点的**核心业务原语** business_attr（它"到底对什么东西做什么操作"），再选攻击基元。

**判定法（参照 OpenAI Agent 攻破 HuggingFace 案例）:**
HF 的数据集 loader 名字看似"数据加载"，本质原语是 **"把数据集配置变成文件读取"（read_file）**；攻击者又用 Jinja2 模板注入把同一表面改成 **"执行本地代码"（exec_code）**。同一表面 = read 原语 + exec 原语，只看名字会同时漏掉"任意文件读取"和"SSTI→RCE"。
- 从调用链/后端语义问: 这个功能"把什么变成什么"？
- read_file=会读取并回显文件/配置/数据；write_file=会写入/保存/上传/生成文件；exec_code=会渲染模板/执行命令/求值表达式/加载运行代码；modify_state=会增删改记录/审批/下单/改配置；query_data=纯查询；transfer=代理/转发/拉取外部URL；auth=登录/会话/token。
- 每个端点输出: \`- /xxx POST business_attr=read_file attr_target=local_fs attr_reason=... params={...} risk=路径遍历,任意文件读取\`
- attr_target（原语作用对象）∈ {local_fs, remote_url, db, template, user_input, worker}

**攻击基元集（按原语选，不按名字）:**
- **read_file** → 路径遍历/任意文件读取；HDF5外部存储声明本地路径(/proc/self/environ、源码路径)；XML外部实体；配置外部引用；符号链接；响应体必须回显文件内容才算 confirmed
- **write_file** → 任意文件写入；上传绕过（双扩展名/Content-Type/文件名路径穿越）；覆盖配置文件→提权
- **exec_code** → SSTI（Jinja2/Velocity/FreeMarker/Thymeleaf: \${7*7}/#{7*7}/{{7*7}}）；表达式注入；反序列化；**模板/配置字段注入→对象链→exec()**（HF案例: 应填数值的字段填入Jinja2模板，渲染器未做类型校验即执行）
- **modify_state** → IDOR写越权（改他人资源）；逻辑缺陷（负金额/数量/状态翻转/审批绕过）；未授权增删改
- **query_data** → IDOR遍历；分页批量；未授权敏感数据
- **transfer** → SSRF（含 **remote→local 原语切换**: 远程URL被白名单拦时，改让服务端读本地路径——读本地不是URL fetch，白名单看不见）；开放重定向
- **auth** → 认证绕过/JWT伪造/弱口令

**HF案例强制规则:**
1. 名字含 load/parse/import/sync/render/convert/transform/download/upload 等"数据处理"语义的端点，**必须强制判定真实原语**——同一表面常同时是 read 原语与 exec 原语。
2. 每个端点至少自问三连: "如果我让它读本地文件 / 执行我给的代码 / 写入任意路径，业务上它会不会照做？" → 对应 read/exec/write 三个原语测试，各做一遍。
3. 执行结果可通过**死信投递/数据集回传**等正常平台接口回读（HF 把命令输出写进公开数据集再经公开API读回），不要只盯直接响应。
`

const SAFETY_API_GUARDRAIL = `
**【安全护栏 — harness强制（只读探测，禁止对删除/修改类API发送请求）】**
以下护栏为硬性要求，测试全程必须遵守，违反任何一条即违规:
1. **禁止写方法**: 严禁使用 curl -X DELETE / -X PUT / -X PATCH / -X MERGE / -X TRACE 或 --request DELETE/PUT/PATCH 发送任何请求。
2. **禁止对写语义端点发送任何请求**: 对路径含 /delete /remove /drop /clear /truncate /update /edit /modify /save /write /upload /import /move /copy /publish /approve /reject /submit /close 等删除/修改语义的端点，即使只读 GET 也禁止探测——此类端点本身即高危写面，任何探测都可能触发数据修改。
3. **禁止在请求体/参数中携带写指令**: 参数/数据中不得含 delete:true、action=delete、method=DELETE、op=remove 等删除/修改指令。
4. **发现疑似写漏洞（文件写入/数据篡改/删除类）时，只记录不验证**: 若从 JS/源码/接口文档推断出 write_file 或 modify_state 型漏洞，在 findings 中记录证据并标注"未实际发送写请求，需人工复核"；严禁用写请求复现。
5. **允许的测试面**: 仅只读探测——GET 与只读 POST（查询/搜索/登录/越权读取类）。一切"读"侧验证（IDOR读取、路径遍历读取、配置泄露读取）均可正常执行。
6. **写/改请求三要素判定（参数 + 整体请求 + 前端对返回的解析）**: 对每个非纯GET请求（尤其 POST 到含数字ID的条目路径 /api/order/999、/api/user/123、/api/order/999/status），发送前必须完成三要素判定，任一命中"写"信号即禁止发送并记录为疑似漏洞（evidence="未实际发送写请求，需人工复核"）:
   - **① 参数信号（看参数是"赋值"还是"筛选"）**: body/query 携带赋值型字段（status/role/config/password/enabled/approved/settings/score/price/title/remark/description/content 等"设置值"字段）→ 写；只有 id/page/keyword/sort/type 等筛选字段 → 读
   - **② 整体请求信号**: 方法为 POST 且路径指向具体资源/子资源（/api/order/999、/user/123/status、/order/999/pay、/user/123/avatar）+ 携带会话凭证 → 状态修改签名；路径是集合（/api/orders、/api/user/list）或子集合读端点（/999/detail、/999/items、/999/download、/999/info）→ 读
   - **③ 前端对返回的解析（最高权威，优先回查 Phase 2 call-site 与 JS 还原源码）**: 找到该接口的 caller_files 与 response_param_hints，看响应被前端如何消费:
     - 响应按数据渲染（res.data.list 填表格 / 详情字段展示 / JSON 拼接到页面）→ 读，可发送
     - 响应只取 code/success 后触发 UI 副作用（toast"保存/修改成功"、location.reload()、列表刷新、路由跳转、按钮状态切换）→ 写，禁止发送
   三要素判定为"写"→ 禁止发送；判定为"读"→ 可正常发送。IDOR 越权读取一律用 GET 对比响应差异。若 hook 拦截了你认为只读的请求，说明参数或路径触发了写判定，请改用 GET 对比差异或记录"需人工复核"，不要绕过 hook。
`

let projectName, mode, singleUrl

if (typeof args === 'string') {
  let parsed = null
  try { parsed = JSON.parse(args) } catch (_) {}
  if (parsed && typeof parsed === 'object') {
    projectName = parsed.project || null
    mode = parsed.mode || 'full'
    singleUrl = parsed.url || null
  } else {
    projectName = args
    mode = 'full'
  }
} else if (typeof args === 'object' && args) {
  projectName = args.project || null
  mode = args.mode || 'full'
  singleUrl = args.url || null
  if (mode === 'url' && !singleUrl) {
    log('⚠️ 单URL模式需指定 url 参数，如: {mode: "url", url: "https://target:8080"}')
    return { error: 'need_url', message: '请指定url参数' }
  }
} else {
  projectName = null
  mode = 'full'
}

// 自动探测项目目录 — 以当前工作目录为准
const CWD = '/home/my/360zc/1516_中远海运'

// 未指定项目名时从URL自动提取
let _isAutoCompany = false
if (!projectName && singleUrl) {
  _isAutoCompany = true
  try {
    const u = new URL(singleUrl)
    projectName = u.hostname
  } catch (_) {
    projectName = singleUrl.replace(/^https?:\/\//, '').replace(/[:\/?#].*$/, '')
  }
  // IP/localhost作为项目名会导致目录创建异常、报告文件名含IP等
  // 统一替换为 _CLI_TARGET_ 作为路径标识
  if (/^\d+\.\d+\.\d+\.\d+$/.test(projectName) || projectName === 'localhost') {
    projectName = '_CLI_TARGET_'
    log(`ℹ️ URL域名解析为IP/本地地址，统一使用 "_CLI_TARGET_" 作为目录标识`)
  } else {
    log(`ℹ️ 未指定项目名，自动使用URL域名作为项目标识`)
  }
}

// 如果未指定project，尝试从CWD推断
const resolvedProject = projectName || '1516_中远海运'
const PROJECT_DIR = `${ZC_BASE}/${resolvedProject}`

log(`📂 项目目录: ${PROJECT_DIR}`)
log(`📋 模式: ${mode}`)

// 默认跳过 dirsearch（目录枚举统一用智能fuzz smart_fuzz.py），仅当显式指定 dirsearch:true/runDirsearch 时才执行
const parseWorkflowBool_zc = (v) => v === true || v === 1 || v === '1' || String(v).toLowerCase() === 'true' || String(v).toLowerCase() === 'yes'
const skipDirsearch = parseWorkflowBool_zc(args?.dirsearch) || parseWorkflowBool_zc(args?.runDirsearch) ? false : true

// ============================================================
// VPN 自动启动（渗透隔离 — 仅探测流量走 VPN）
// ============================================================
await agent(
  `检查并启动 VPN（渗透隔离模式）。

项目: ${resolvedProject}
VPN 脚本: ${PROJECT_DIR}/OPENVPN/vpn-split.sh

请执行以下步骤:
1. 执行 bash 命令检查 VPN 脚本是否存在: ls -la ${PROJECT_DIR}/OPENVPN/vpn-split.sh
2. 检查 VPN 当前状态: sudo ${PROJECT_DIR}/OPENVPN/vpn-split.sh status
3. 如果 VPN 未运行，启动它: sudo ${PROJECT_DIR}/OPENVPN/vpn-split.sh up ${PROJECT_DIR}
4. 如果已运行，跳过启动
5. 确认双通道可用：curl -sk https://zhongce.360.net/（VPN） + curl -sk https://www.baidu.com（直连） 均应返回 200
6. 输出 VPN IP 和 tun0 路由表

注意：sudoers 已配置免密，sudo 命令可直接执行。`,
  { label: '🔒 VPN 自动启动', phase: '项目信息+资产发现' }
)

// 目标进度追踪
// P2: 共享字典 — SRC↔ZC 互相复制
try {
  const fs = require('fs')
  const skillsRoot = '/home/my/.claude/skills'
  for (const [from, to] of [['ZC_SKILLS_V1','SRC_SKILLS_V1'], ['SRC_SKILLS_V1','ZC_SKILLS_V1']]) {
    const src = `${skillsRoot}/${from}/references/api_patterns.json`
    const dst = `${skillsRoot}/${to}/references/api_patterns.json`
    if (fs.existsSync(src)) { fs.copyFileSync(src, dst); log(`  📚 字典共享: ${from} → ${to}`) }
  }
} catch(e) {}

const progress = {
  project: resolvedProject,
  phase1: '⬜', phase2: '⬜', phase3: '⬜', phase4: '⬜',
  phase5: '⬜', phase6: '⬜', phase7: '⬜', phase8: '⬜',
  findings_count: 0,
  reports_count: 0,
}

function showProgress() {
  log('')
  log('╔══════════════════════════════════════════════════════════════╗')
  log(`║  目标进度表 — ${(progress.project || '').padEnd(30)} ║`)
  log('╠══════════════════════════════════════════════════════════════╣')
  log('║  ①项目资产  ②深度分析  ③挖洞     ④验证     ⑤标记     ⑥报告     ⑦自审     ⑧提交  ║')
  log(`║    ${progress.phase1}       ${progress.phase2}       ${progress.phase3}       ${progress.phase4}       ${progress.phase5}       ${progress.phase6}       ${progress.phase7}       ${progress.phase8}    ║`)
  log(`║  发现: ${String(progress.findings_count).padEnd(4)}  |  报告: ${String(progress.reports_count).padEnd(4)}                            ║`)
  log('╚══════════════════════════════════════════════════════════════╝')
  log('')
}

function markPhase(n, status) {
  progress[`phase${n}`] = status
}
// ============================================================
// VPN 保活检查 — 每阶段前调用
// ============================================================
async function checkVPN(label) {
  const vpnScript = `${PROJECT_DIR}/OPENVPN/vpn-split.sh`
  const status = await agent(
    `检查VPN状态 (${label}):
if sudo ${vpnScript} status 2>/dev/null | grep -q "tun0"; then
  echo "vpn_alive"
else
  echo "vpn_dead"
  # 尝试重连
  sudo ${vpnScript} up ${PROJECT_DIR} 2>&1 | tail -3
  sleep 2
  if sudo ${vpnScript} status 2>/dev/null | grep -q "tun0"; then
    echo "vpn_reconnected"
  else
    echo "vpn_failed"
  fi
fi`,
    {label: `🔒 VPN检查: ${label}`, phase: '项目信息+资产发现'}
  )
  if (status && status.includes('vpn_dead')) log('  ⚠️ VPN断开，已尝试重连')
  if (status && status.includes('vpn_failed')) log('  ❌ VPN重连失败，检查网络')
  return status
}


// ============================================================
// 资产测试状态加载（避免重复测试）
// ============================================================
const trackerPath = `${PROJECT_DIR}/asset_test_status.json`
const findingsPath = `${PROJECT_DIR}/asset_findings.json`
const frameworksCachePath = `${PROJECT_DIR}/frameworks_audited.json`
let p0_tracker = null

if (!mode.startsWith('phase5')) {
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
              reason: { type: 'string' },
            },
          },
        },
      },
      required: ['exists'],
    }, label: '📋 加载资产测试状态' }
  )
}

// E: TTL 过期检查 — 降级过期资产（基于字符串日期比较，避免new Date()被Workflow禁用）
if (p0_tracker?.exists && p0_tracker?.assets) {
  const _todayStr = '2026-07-09'
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
// 测试维度跟踪器
// ============================================================
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
// 阶段变量声明（全局作用域，供后续阶段使用）
// ============================================================
let p1_assets
let p2_discoveries_text = ''
let p3_unauth, p3_other, p3_quick, p4_dirscan, p4_verify
let p3_findings_data = []

// ============================================================
// Phase 1: 项目信息读取 + 资产发现
// ============================================================
phase('项目信息+资产发现')

if (mode.startsWith('phase5')) {
  log('[1/8] ⏭️ 跳过（用户指定报告模式）')
  markPhase(1, '⏭️')
  p1_assets = { project_name: resolvedProject, priority_targets: [], all_urls: [] }
} else if (mode === 'url' && singleUrl) {
  log('[1/8] 🔗 单URL模式 — 跳过资产发现')
  markPhase(1, '⏭️')
  p1_assets = {
    project_name: singleUrl,
    summary: '用户指定URL',
    priority_targets: [{
      url: singleUrl, ip: '', port: 443, title: '',
      tags: ['[用户指定]'], priority: '最高', reason: '用户指定目标'
    }],
    all_urls: [singleUrl],
  }
  dimTracker.record(singleUrl, 'http_probe', 'done', { title: '' })
  progress.findings_count = 1
  showProgress()
} else {
  markPhase(1, '🔄')
  log(`[1/8] 项目信息读取 + 资产发现 — ${resolvedProject}`)

  // 检查项目目录是否存在
  const dirCheck = await agent(
    `检查项目目录是否存在:
    ls -la ${PROJECT_DIR}/
    ls -la ${PROJECT_DIR}/assets/ 2>/dev/null || echo "assets/目录不存在"
    ls -la ${PROJECT_DIR}/NOTICE/ 2>/dev/null || echo "NOTICE/目录不存在"
    ls -la ${PROJECT_DIR}/OPENVPN/ 2>/dev/null || echo "OPENVPN/目录不存在"
    输出检查结果。`,
    { label: '📁 检查项目目录结构', phase: '项目信息+资产发现' }
  )
  log(`  ${dirCheck || '（无法读取项目目录）'}`)

  p1_assets = await agent(
    `你是360众测项目专家，负责 "项目信息读取 + 资产发现" 阶段。
    项目名称: ${resolvedProject}
    项目路径: ${PROJECT_DIR}

    请依次执行:

    1. **读取 VULN_TYPE.html**（项目漏洞类型定义）
       - 文件: ${PROJECT_DIR}/VULN_TYPE.html
       - 提取：接受哪些漏洞类型、忽略清单、严重等级定义

    2. **读取 NOTICE 规则**
       - 目录: ${PROJECT_DIR}/NOTICE/
       - 读取 NOTICE1（项目公告：测试范围、行为约束、去重规则、报告要求）
       - 读取 NOTICE2（VPN账号信息）

    3. **解析资产列表**
       - 目录: ${PROJECT_DIR}/assets/
       - 查找 *资产列表.xlsx 文件
       - 用 python3 + openpyxl 库读取 xlsx 文件，提取列: URL/IP/域名/端口/标题/备注
       - 按以下方式给资产打标签:
         · [范围内] — 域名/IP 在资产列表收录范围内
         · [新发现] — 从 xlsx/页面解析发现的额外子域名
         · [非常见端口] — 非80/443端口
         · [高优先级] — 明确标记为重要的资产
         · [管理后台] — 标题含"登录/管理/后台/admin/dashboard/运维"
         · [非常见端口] — 非80/443端口
       - 如果 xlsx 无法读取或不存在，输出空列表并说明

    4. **VPN 隔离状态确认（已在启动时自动拉起）**
       - 检查 ${PROJECT_DIR}/OPENVPN/vpn-split.sh 是否存在
       - 执行 sudo ${PROJECT_DIR}/OPENVPN/vpn-split.sh status 确认 VPN 运行中
       - 确认：众测平台(走VPN) + 百度(走外网) 双通道均可达
       - 记录 VPN IP 和路由表供后续参考
    5. **优先级排序输出**
       - 最高: [管理后台]
       - 高: [高优先级]
       - 中: [非常见端口]

    6. **读取 NOTICE 去重规则** — 特别注意：
       - 同一漏洞源产生的多个漏洞算同一个漏洞
       - 全局函数、全局配置导致的问题算同源
       - 同一配置影响的多个文件算同源
       - 同一漏洞的不同利用方式算同源
       - 同一函数导致的漏洞算同源
       - 同一功能模块下的不同接口算同源
       - 同一文件的不同参数算同源
       - 泛域名解析产生的多个安全漏洞算同源
    JSON输出格式:
    {
      "project_name": "项目名",
      "vulntype_summary": "接受的漏洞类型摘要",
      "prohibited_types": "不接收/忽略的类型",
      "scope_summary": "测试范围简述",
      "rules": "NOTICE中的关键规则",
      "dedup_rules": "去重规则摘要",
      "report_requirements": "报告提交要求",
      "category_breakdown": {
        "management": N, "high_priority": N, "uncommon_port": N
      },
      "priority_targets": [
        {"url": "https://xxx", "ip": "x.x.x.x", "port": 443, "title": "xx",
         "tags": ["[管理后台]"], "priority": "最高", "reason": "xxx"}
      ],
      "all_urls": ["url1", "url2", ...]
    }`,
    {
      label: `📡 ${resolvedProject} 项目信息+资产分析`,
      schema: {
        type: 'object',
        properties: {
          project_name: { type: 'string' },
          vulntype_summary: { type: 'string' },
          prohibited_types: { type: 'string' },
          scope_summary: { type: 'string' },
          rules: { type: 'string' },
          dedup_rules: { type: 'string' },
          report_requirements: { type: 'string' },
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
        required: ['project_name', 'priority_targets'],
      },
      phase: '项目信息+资产发现',
    }
  )

  if (!p1_assets) {
    log('⚠️ 资产发现无返回，请检查项目目录')
    markPhase(1, '❌')
    showProgress()
    return { error: '资产发现失败', progress }
  }

  // ============================================================
  // 🔧 URL 合法性检查（剔除异常格式的资产）
  // ============================================================
  const ZC_ILLEGAL_PATTERNS = [
    '_',              // 下划线域名（扫描陷阱）
    '.domain.name',   // 域名停放
    '.internet.com', '.com.com', '.itotolink.com',
  ]
  function isUrlValid(url) {
    try {
      const domain = url.split('://')[1].split(':')[0].toLowerCase()
      for (const pat of ZC_ILLEGAL_PATTERNS) {
        if (domain.includes(pat)) return false
      }
      return true
    } catch (_) { return false }
  }
  if (p1_assets?.priority_targets) {
    const before = p1_assets.priority_targets.length
    p1_assets.priority_targets = p1_assets.priority_targets.filter(t => isUrlValid(t.url))
    const filtered = before - p1_assets.priority_targets.length
    if (filtered > 0) log(`  🛡️ 已剔除 ${filtered} 个异常格式资产`)
  }
  if (p1_assets?.all_urls) {
    p1_assets.all_urls = p1_assets.all_urls.filter(u => isUrlValid(u))
  }
  // ============================================================

  // 输出项目信息摘要
  log(`  📋 项目: ${p1_assets.project_name}`)
  log(`  📐 范围: ${p1_assets.scope_summary || '未知'}`)
  log(`  🚫 禁止类型: ${p1_assets.prohibited_types || '未知'}`)
  log(`  📝 报告要求: ${(p1_assets.report_requirements || '').substring(0, 200)}...`)

  // 过滤已测试资产
  if (p0_testedUrls.size > 0 && p1_assets?.priority_targets) {
    const before = p1_assets.priority_targets.length
    p1_assets.priority_targets = p1_assets.priority_targets.filter(t => !p0_testedUrls.has(t.url))
    p1_assets.all_urls = (p1_assets.all_urls || []).filter(u => !p0_testedUrls.has(u))
    const filtered = before - p1_assets.priority_targets.length
    if (filtered > 0) log(`  已过滤 ${filtered} 个已测试资产`)
  }

  // 记录维度
  ;(p1_assets.priority_targets || []).forEach(t => {
    const isLogin = (t.tags || []).includes('[管理后台]')
    dimTracker.record(t.url, 'http_probe', 'done', { title: t.title || '' })
    if (isLogin) dimTracker.record(t.url, 'weak_pass', 'pending')
  })

  markPhase(1, '✅')
  progress.findings_count = p1_assets.priority_targets?.length || 0
  showProgress()

  const top3 = (p1_assets.priority_targets || []).slice(0, 3)
  log(`  高优目标: ${p1_assets.priority_targets?.length || 0} 个`)
  top3.forEach(t => log(`    ${t.priority} ${t.url} — ${t.reason || ''}`))
}

// ============================================================
// Phase 2: 深度分析
// ============================================================
phase('深度分析')

if (mode.startsWith('phase3') || mode.startsWith('phase5')) {
  log('[2/8] ⏭️ 跳过（用户指定模式）')
  markPhase(2, '⏭️')
} else {
  markPhase(2, '🔄')
  log(`[2/8] 深度分析 — ${resolvedProject}`)

  const p2_priority_urls = (p1_assets.priority_targets || []).map(t => t.url).filter(Boolean)
  const p2_all_urls = (p1_assets.all_urls || []).filter(u => !p2_priority_urls.includes(u))
  const targets = [...p2_priority_urls, ...p2_all_urls].slice(0, 10)

  if (targets.length === 0) {
    log('  ⚠️ 无高优先级目标可分析')
    markPhase(2, '⏭️')
  } else {
    let analyses = []
    try {
      // === 防冻结修复：Phase2 并发 agent 风暴 ===
      // 原 pipeline(10目标) 一次性并发 10×2≈20个满血agent，曾打爆内存导致系统冻结。
      // 改为每批 P2_BATCH 个目标串行处理，把同时运行的 agent 数压到 ≤ 2×P2_BATCH。
      const P2_BATCH = 2
      for (let _bi = 0; _bi < targets.length; _bi += P2_BATCH) {
        const _batch = targets.slice(_bi, _bi + P2_BATCH)
        log(`  🔄 深度分析批次 ${Math.floor(_bi/P2_BATCH)+1}/${Math.ceil(targets.length/P2_BATCH)}（${_batch.length}目标·小并发防冻结）`)
        const _batchResults = await pipeline(
        _batch,
        async (target) => {
        // === 合并机械操作:下载JS+枚举chunk+提取凭证（含自动重试） ===
        let mechResult = ''
        for (let _retry = 0; _retry < 2; _retry++) {
          mechResult = await agent(
          `执行以下命令串行:
# 1. 下载JS(VPN)
python3 ${SKILL_SCRIPTS}/download_js.py "${target}" "${PROJECT_DIR}/js_dumps" --ua "${REAL_UA}" --interface tun0
# 2. 枚举chunk补下
python3 ${SKILL_SCRIPTS}/enumerate_chunks.py "<从下载结果提取的dump_dir>" "${target}" --ua "${REAL_UA}" --interface tun0
# 3. 提取凭证
python3 ${SKILL_SCRIPTS}/extract_creds.py "\${dump_dir}" 2>&1

输出格式: ---DOWNLOAD_RESULT---{...}---CHUNK_RESULT---{...}---CREDS_RESULT---{...}`,
          { label: `🤖 机械操作: ${target}`, phase: '深度分析' }
        )

        let dl_dump_dir = "${PROJECT_DIR}/js_dumps"
        let dl_file_count = 0
        let target_hash = ""
        try {
          const dlPart = (mechResult || '').split('---DOWNLOAD_RESULT---')[1] || ''
          const dlMatch = dlPart.match(/{[^}]+}/)
          if (dlMatch) {
            const dl = JSON.parse(dlMatch[0])
            if (dl.dump_dir) dl_dump_dir = dl.dump_dir
            if (dl.file_count) dl_file_count = dl.file_count
            if (dl.target_hash) target_hash = dl.target_hash
          }
        } catch(e) {}
        if (dl_file_count > 0) log(`  📥 ${target}: 下载 ${dl_file_count} 个文件`)
        if (dl_file_count === 0) log(`  ⚠️ ${target}: JS下载可能失败（0文件），检查VPN或target是否可达`)

        try {
          const credsPart = (mechResult || '').split('---CREDS_RESULT---')[1] || ''
          const credsMatch = credsPart.match(/{[^}]+}/)
          if (credsMatch) {
            const credsData = JSON.parse(credsMatch[0])
            const creds = credsData.credentials || []
            if (creds.length > 0) {
              if (!globalThis.__zc_creds_json) globalThis.__zc_creds_json = '[]'
              const existing = JSON.parse(globalThis.__zc_creds_json)
              existing.push(...creds)
              globalThis.__zc_creds_json = JSON.stringify(existing)
              log(`  🔐 ${target}: 提取 ${creds.length} 条凭证`)
            }
          }
        } catch(e) {}

        if (dl_file_count > 0) break
          if (_retry === 0) log(`  🔄 ${target}: 下载结果为0文件，等待2秒后重试...`)
        }  // end retry loop

        if (target_hash) {
          if (!globalThis.__zc_js_dirs_json) globalThis.__zc_js_dirs_json = '[]'
          const dirs = JSON.parse(globalThis.__zc_js_dirs_json)
          dirs.push({ target_hash, dump_dir: dl_dump_dir, js_count: dl_file_count })
          globalThis.__zc_js_dirs_json = JSON.stringify(dirs)
        }

        // === Step C: Agent 创造性分析 ===
        return await agent(
          `你是JS逆向和API发现专家，分析已下载到本地的JS文件: ${target}

    已下载文件目录: ${dl_dump_dir}
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

    **Step 5: 本质业务属性判定（最高优先级思维 — 从数据流推断原语，不要看API名字）**
    对每个端点输出 business_attr（核心业务原语）∈ {read_file, write_file, exec_code, modify_state, query_data, transfer, auth}、attr_target（原语作用对象 ∈ {local_fs, remote_url, db, template, user_input, worker}）、attr_reason（推导依据）。
    - 参照 OpenAI Agent 攻破 HuggingFace 案例: 数据集 loader 名字看似"数据加载"，本质原语是"把数据集配置变成文件读取"（read_file），又能被 Jinja2 模板注入改成"执行本地代码"（exec_code）——同一表面既是 read 原语又是 exec 原语。
    - read_file=读取并回显文件/配置；write_file=写入/保存/上传/生成文件；exec_code=渲染模板/执行命令/求值表达式/加载运行代码；modify_state=增删改记录/审批/下单/改配置；query_data=纯查询；transfer=代理/转发/拉取外部URL；auth=登录/会话/token。
    - 输出格式: - /xxx POST business_attr=read_file attr_target=local_fs attr_reason=... params={...} risk=路径遍历,任意文件读取
    - bypass 预判（HF案例）: read 原语的远端目标若被 URL 白名单拦截，则把 attr_target 从 remote 切到 local（读 /proc/self/environ、源码路径），"读本地文件"不是 URL fetch，白名单看不见。

    ${UA_INSTR}`,
          { label: `🔬 分析: ${target}`, phase: '深度分析' }
        )
      },
      (result, target) => {
        return result
      }
      )
      analyses.push(...(_batchResults || []))
    }
    } catch(e) {
      log(`  ⚠️ Pipeline部分失败: ${e.message}`)
    }

    log(`  完成 ${analyses.filter(Boolean).length} 个目标的分析`)
    if (analyses && analyses.length > 0) {
      p2_discoveries_text = analyses.filter(Boolean)
        .map((a, i) => `【目标${i+1}JS分析结果】\n${a}`)
        .join('\n\n')
      targets.forEach(t => dimTracker.record(t, 'js_analysis', 'done'))
    }

    // ============================================================
    // Fix A+C: 提取鉴权凭证(结构化) + JS缓存目录捕获
    // ============================================================
    log('  🔐 提取JS中的鉴权凭证...')
    const p2_js_dump_base = "${PROJECT_DIR}/js_dumps"
    let p2_js_dirs = []
    let p2_credentials = []

    try {
      const findDirsResult = await agent(
        `python3 ${SKILL_SCRIPTS}/find_js_dumps.py "${p2_js_dump_base}"
输出最后一行为JSON结果。提取 dumps 数组。`,
        { label: '📂 查找JS缓存目录', phase: '深度分析' }
      )
      const dirLines = (findDirsResult || '').split('\\n').filter(l => l.trim().startsWith('{'))
      if (dirLines.length > 0) {
        const dirData = JSON.parse(dirLines[dirLines.length-1])
        p2_js_dirs = dirData.dumps || []
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
              if (creds.length > 0) p2_credentials.push(...creds)
            } catch(e) {}
          }
        }
      }
    } catch(e) {}

    if (p2_credentials.length > 0) {
      globalThis.__zc_creds_json = JSON.stringify(p2_credentials)
      // 凭证已存入结构化变量，不再注入p2_discoveries_text
      log(`  🔐 共 ${p2_credentials.length} 条结构化凭证已提取`)
    }
    if (p2_js_dirs.length > 0) {
      globalThis.__zc_js_dirs_json = JSON.stringify(p2_js_dirs)
      p2_discoveries_text += '\n【JS缓存目录】\n' + p2_js_dirs.map(d => d.dump_dir).join('\n') + '\n'
    }

    // 【开源系统识别】— 识别快速开发框架/低代码平台（JeecgBoot, RuoYi, JeeSite 等）
    log('  🔍 执行开源系统识别（快速开发框架/低代码平台）...')
    const p2_oss = await agent(
      `你是快速开发框架识别专家，对 ${resolvedProject} 的以下目标执行开源系统识别。
🔒 VPN: 所有 curl 探测必须加 --interface tun0
${SAFETY_API_GUARDRAIL}
重点识别：JeecgBoot、RuoYi（若依）、JeeSite、Guns、TeaWeb、BladeX、低代码平台等。

目标列表（前 20 个）:
${targets.slice(0, 20).map(function(t) { return '  ' + t }).join(String.fromCharCode(10))}

**Step 1: 指纹采集**
对每个目标执行 curl -sI + curl -s 首页 + curl -sk /swagger-ui.html /doc.html

**Step 2: 快速开发框架识别**

1. **JeecgBoot**:
   - 特征: X-Powered-By: JeecgBoot, /jeecg-boot/ 前缀, /sys/dict, Knife4j /doc.html
   - 默认口令: admin/admin123, jeecg/jeecg123
   - 攻击面: /sys/oss minio泄露, /sys/file/upload, 代码生成器 /code

2. **RuoYi (若依)**:
   - 特征: RuoYi 版权, /prod-api/, /common/captcha, Shiro+Thymeleaf
   - 默认口令: admin/admin123
   - 攻击面: Shiro反序列化, /prod-api/system/user/list 未授权

3. **JeeSite**:
   - 特征: JeeSite Cookie, /js/a/login
   - 默认口令: admin/admin123
   - 攻击面: Beelt模板注入, $._csrf 伪造, /sys/

4. **Guns/BladeX/TeaWeb**:
   - Guns: /guns-api/, Beetl模板
   - BladeX: /blade- 前缀, blade-auth
   - TeaWeb: Go编写, TeaWeb响应头

5. **低代码平台 / iPaas**:
   - 特征: /designer/, /form/, /workflow/, /code/generate
   - 攻击面: 代码生成器未授权, 表单设计器RCE

6. **Pear Admin / Vue Admin / 企业系统**:
   - 前端框架/全栈判断, 版权特征

**Step 2.5: 自主识别（不匹配已知框架时的通用检测 — 关键）**
如果以上预定义列表都不匹配，**不要直接返回"未发现"**。用以下通用线索自主判断：

1. **路径结构探针** — curl 探测:
   - 包管理: /vendor/, /node_modules/, /bower_components/
   - CMS特征: /plugins/, /modules/, /themes/, /uploads/, /install/
   - 源码: /src/, /app/, /config/, /routes/, /resource/
   - 多个命中 → 高度疑似开源

2. **文件特征分析**:
   - /robots.txt — Disallow路径推断目录结构
   - /sitemap.xml — URL模式推断模块结构
   - /package.json, /composer.json — 依赖推断框架
   - /.env — 环境配置泄露

3. **响应特征**:
   - X-Powered-By / Server / Set-Cookie 特征值
   - 默认404/403错误页风格推断框架
   - 注释泄露路径

4. **Cookie 模式**: PHPSESSID(PHP), JSESSIONID(Java), ASP.NET_SessionId(.NET), laravel_session(Laravel)

5. **前端框架**: Vue/React/Angular 全局变量, AntD/ElementUI UI库

6. **综合判定**:
   - ≥3条路径特征 + Cookie匹配 → **高度疑似开源**
   - 1-2条 + 前端匹配 → **部分疑似**
   - 完全无特征 → **大概率自研**
   - 「疑似开源」本身就值得标记供 Phase 3 参考

**Step 3: 特有攻击面检测**
对每个已识别框架输出：
- 默认口令、Swagger泄露(/doc.html /v2/api-docs)
- 代码生成器接口、文件上传、Minio/OSS配置
- Shiro 绕过、定时任务、数据字典未授权

只做读取探测。`,
      { label: '🔍 快速开发框架识别', schema: {
        type: 'object',
        properties: {
          findings: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                target: { type: 'string' },
                framework_name: { type: 'string', description: '已知框架写具体名，自主识别则为"疑似开源系统"' },
                version: { type: 'string' },
                confidence: { type: 'string', enum: ['高', '中', '低'] },
                evidence: { type: 'string' },
                is_suspected_oss: { type: 'boolean', description: '是否通过自主识别判断为疑似开源系统' },
                oss_clues: { type: 'array', items: { type: 'string' }, description: '自主识别线索' },
                oss_verdict: { type: 'string', enum: ['高度疑似开源', '部分疑似', '大概率自研', '无法判断'] },
                default_credentials: { type: 'array', items: { type: 'string' } },
                attack_surface: { type: 'array', items: { type: 'string' } },
                notes: { type: 'string' },
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

    // Fix B: 结构化框架指纹
    if (p2_oss && p2_oss.findings && p2_oss.findings.length > 0) {
      const fwInfo = p2_oss.findings.map(f => ({
        target: f.target,
        framework_name: f.framework_name || '未知',
        confidence: f.confidence || '低',
        default_credentials: f.default_credentials || [],
        attack_surface: f.attack_surface || [],
      }))
      globalThis.__zc_fw_info = JSON.stringify(fwInfo)
    }

    // ============================================================
    // 2.5 dir_enum — 基于系统特征的智能路径枚举（智能fuzz）
    // ============================================================
    log('  🔍 执行智能路径枚举（基于系统特征自动泛化fuzz）...')
    const P2_DICT_PATH_ZC = "${SKILL_SCRIPTS}/../references/api_patterns.json"

    // 对每个目标执行 smart_fuzz.py（VPN）
    const fuzz_targets_zc = targets.slice(0, 15)
    for (const ft of fuzz_targets_zc) {
      const fuzz_out_zc = "/tmp/zc_smart_fuzz_" + resolvedProject.replace(/[^a-zA-Z0-9]/g,'_') + "_" + ft.replace(/[^a-zA-Z0-9]/g,'_') + ".json"
      const fuzz_cmd_zc = `python3 ${SKILL_SCRIPTS}/smart_fuzz.py "${ft}" --dict ${P2_DICT_PATH_ZC} --output ${fuzz_out_zc} --ua "${REAL_UA}" --interface tun0`
      
      let fuzz_raw_zc
      try {
        fuzz_raw_zc = await agent(
        `执行fuzz(VPN):
${fuzz_cmd_zc}
echo "---RESULT_JSON---"
cat ${fuzz_out_zc}`,
        { label: `🤖 fuzz: ${ft}`, phase: '深度分析' }
      )
      } catch(e) {
        log(`  ⚠️ fuzz ${ft} 失败: ${e.message}`)
        continue
      }

      try {
        const jsonPart = (fuzz_raw_zc || '').split('---RESULT_JSON---').pop()
        const fuzzData = JSON.parse(jsonPart.trim())
        const findings = fuzzData.findings || []
        if (!globalThis.__zc_fuzz_findings) globalThis.__zc_fuzz_findings = []
        globalThis.__zc_fuzz_findings.push(...findings.map(f => ({...f, source_target: ft})))
        if (findings.length > 0) log(`  ${ft}: 发现 ${findings.length} 个端点`)
        if (fuzzData.extracted_patterns || (fuzzData.new_endpoints && fuzzData.new_endpoints.length > 0)) {
          await agent(
            `python3 ${SKILL_SCRIPTS}/update_dict.py ${P2_DICT_PATH_ZC} --add ${fuzz_out_zc}`,
            { label: '📚 更新字典', phase: '深度分析' }
          )
        }
      } catch(e) {}
    }
    if (globalThis.__zc_fuzz_findings && globalThis.__zc_fuzz_findings.length > 0) {
      const fuzzSum = globalThis.__zc_fuzz_findings.filter(f => [200,401,403].includes(f.status_code))
        .map(f => `  [${f.status_code}] ${f.endpoint}`).join('\n')
      p2_discoveries_text += `\n\n【智能fuzz发现端点】\n${fuzzSum}\n`
    }
    targets.forEach(t => dimTracker.record(t, 'dir_enum', 'done'))
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

  // ============================================================
  // Phase 2.5: 新发现目标加入 VPN 路由（确保后续探测全走 VPN）
  // ============================================================
  const VPN_SCRIPT = `${PROJECT_DIR}/OPENVPN/vpn-split.sh`
  const ALL_TARGETS = [
    ...(p1_assets?.priority_targets || []).map(t => t.url || t.ip || t),
    ...(p1_assets?.all_urls || []),
  ]
  // 去重提取域名和 IP
  const TARGET_IPS = [...new Set(ALL_TARGETS.map(t => {
    try { return new URL(t).hostname } catch { return t.split(':')[0] }
  }).filter(t => t && !t.startsWith('{')))]

  if (TARGET_IPS.length > 0) {
    await agent(
      `将已知目标 + Phase 2 新发现目标的 IP 全部加入 VPN 路由表，确保后续探测全走 VPN。

VPN 脚本: ${VPN_SCRIPT}

已知目标（${TARGET_IPS.length} 个）:
${TARGET_IPS.map(t => `  - ${t}`).join('\n')}

执行步骤:
1. 确认 VPN 运行中: sudo ${VPN_SCRIPT} status
2. 先添加已知目标: sudo ${VPN_SCRIPT} add-target ${TARGET_IPS.join(' ')}

3. **关键 — 从 Phase 2 分析结果中提取新发现的目标域名/IP**:
   - 本次 JS 逆向分析中发现的新 API 域名、子域名、第三方接口
   - 开源系统识别中发现的新后端地址
   - 组件审计中发现的新端点
   - 提取出来后执行: sudo ${VPN_SCRIPT} add-target <新IP或域名>

4. 验证路由已添加: ip route show dev tun0
5. 验证众测平台可达（走VPN）: curl -sk --max-time 5 https://zhongce.360.net/

注意: sudo 已配置免密，所有 ip route / curl 命令均可直接执行。`,
      { label: '🔒 更新 VPN 路由表', phase: '项目信息+资产发现' }
    )
  } else {
    log('  ℹ️ 无目标需加入 VPN 路由')
  }
  }
}

// ============================================================
// Phase 3: 漏洞挖掘
// ============================================================
phase('漏洞挖掘')

if (mode.startsWith('phase5')) {
  log('[3/8] ⏭️ 跳过（用户指定报告模式）')
  markPhase(3, '⏭️')
  markPhase(4, '⏭️')
} else {
  markPhase(3, '🔄')
  log(`[3/8] 漏洞挖掘 — ${resolvedProject}`)

  // ⚡ VPN 强制指令：所有 curl/HTTP 请求必须走 VPN 接口
  const VPN_CURL = 'curl --interface tun0 -sk'

  // 防冻结：单 agent 上下文爆炸会拖垮系统，Tier 上限从 50 降至 10
  const P3_TIER1_MAX = 10
  const targets = (p1_assets.priority_targets || []).slice(0, P3_TIER1_MAX)
  const allUrls = [ ...(p1_assets.all_urls || []) ]

  if (targets.length === 0 && allUrls.length === 0) {
    log('  ⚠️ 无可用测试目标')
    markPhase(3, '⏭️')
  } else {
    // ============================================================
    // 3.0 dirsearch — 基于字典的标准目录扫描（默认跳过，用智能fuzz smart_fuzz.py）
    // ============================================================
    let p3_dirsearch; const P3_DICT_PATH = "${SKILL_SCRIPTS}/../references/api_patterns.json"

    if (skipDirsearch) {
      log('  ⏭️ 默认跳过 dirsearch（目录枚举已由智能fuzz smart_fuzz.py 覆盖，除非显式传 dirsearch:true）')
      p3_dirsearch = { findings: [], new_endpoints: [] }
    } else {
    log('  📂 执行字典目录扫描 (dirsearch)...')

        p3_dirsearch = await agent(
      `对 ${resolvedProject} 执行 dirsearch 目录扫描（使用 dirsearch 内置字典 + 积累字典）。
🔒 VPN: 所有 dirsearch 和 curl 命令必须加 --interface tun0
${SAFETY_API_GUARDRAIL}

===== 目标列表（前20个） =====
${targets.slice(0, 20).map(function(t) { return '  ' + t.url + ' — ' + (t.tags||[]).join(',') }).join(String.fromCharCode(10))}
============================

**操作方法（必须按顺序执行）：**

**Step 1: 准备积累字典扩展词表**
先Read ${P3_DICT_PATH} 获取积累的API模式。
从JSON提取: framework_patterns 路径, api_prefixes+path_segments 组合, common_endpoints。
写入临时文件: /tmp/zc_dirsearch_custom.txt（每行一个路径，无前导/）

**Step 2: 对每个目标执行 dirsearch 命令**
dirsearch 内置字典: /home/my/.local/lib/python3.14/site-packages/dirsearch/db/dicc.txt（9482条）

对每个目标URL依次执行:
\`\`\`bash
cat /home/my/.local/lib/python3.14/site-packages/dirsearch/db/dicc.txt /tmp/zc_dirsearch_custom.txt | sort -u > /tmp/zc_merged_dict.txt
dirsearch -u "<target_url>" \
  -w /tmp/zc_merged_dict.txt \
  --interface tun0 \
  -e php,asp,aspx,jsp,html,js,json,xml,txt,sql,conf,zip,tar.gz,bak,old,log \
  -t 10 --timeout=5 \
  -o /tmp/zc_dirsearch_results.txt --format plain 2>&1 | tail -50
\`\`\`

**Step 3: 解析结果**
读取 /tmp/zc_dirsearch_results.txt，提取 200/301/401/403 的端点。
对200端点用 curl --interface tun0 -s 确认非空。

**输出要求：**
只记录确认有效的端点。new_endpoints 输出本次新发现的可积累端点。`,
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
                response_preview: { type: 'string' },
                severity: { type: 'string', enum: ['高危', '中危', '低危', '信息'] },
              },
              required: ['target', 'endpoint', 'status_code', 'source'],
            },
          },
          new_endpoints: {
            type: 'array',
            items: { type: 'string' },
          },
        },
        required: ['findings'],
      }, phase: '漏洞挖掘' }
    )
    }  // end skipDirsearch else block

    if (p3_dirsearch && p3_dirsearch.findings && p3_dirsearch.findings.length > 0) {
      log(`  目录扫描发现 ${p3_dirsearch.findings.length} 个端点`)
      ;(targets || []).forEach(t => dimTracker.record(t.url, 'dirsearch_scan', 'done'))
    }

    // dirsearch结果回注到unauth_test
    let zc_dirsearch_ctx = `\n\n\t**Phase 2提取的结构化凭证（优先级高，优先于下方文本）**:\n\t${typeof globalThis.__zc_creds_json !== 'undefined' ? JSON.stringify(JSON.parse(globalThis.__zc_creds_json).slice(0, 10), null, 2) : '（无）'}\n\n\t**JS缓存目录（可回查本地JS及还原源码）**:\n\t${typeof globalThis.__zc_js_dirs_json !== 'undefined' ? JSON.parse(globalThis.__zc_js_dirs_json).map(d => d.dump_dir + (d.has_reconstructed ? ' (含还原源码)' : '')).join('\n') : '（无）'}\n`
    if (typeof p3_dirsearch !== 'undefined' && p3_dirsearch?.findings && p3_dirsearch.findings.length > 0) {
      const deps = p3_dirsearch.findings.filter(f => [200,401,403].includes(f.status_code)).map(f => `  ${f.endpoint} [${f.status_code}]`)
      if (deps.length > 0) {
        zc_dirsearch_ctx = `\n【dirsearch发现的端点 — 需做未授权测试】\n${deps.join('\n')}\n`
      }
    }

    // 3.1 未授权/信息泄露测试
    p3_unauth = await agent(
      `你是360众测项目漏洞挖掘专家，对 ${resolvedProject} 执行未授权访问和信息泄露测试。

🔒 VPN 强制要求: 所有 curl/HTTP 请求必须使用 --interface tun0 参数走 VPN 隧道（如: curl --interface tun0 -sk https://target）

高优目标列表:
${targets.map(function(t) { return '  ' + t.priority + ' | ' + t.url + ' | tags: ' + (t.tags||[]).join(',') }).join('\\n')}

常规URL列表:
${allUrls.map(function(u) { return '  ' + u }).join('\\n')}

第2阶段JS逆向发现的隐藏端点:
${p2_discoveries_text ? p2_discoveries_text.substring(0, 10000) : '（无 JS 分析数据）'}\n\n\t${zc_dirsearch_ctx}
\n	**Phase 2提取的结构化凭证（优先级高，优先于下方文本）**:
	${typeof globalThis.__zc_creds_json !== 'undefined' ? JSON.stringify(JSON.parse(globalThis.__zc_creds_json).slice(0, 10), null, 2) : '（无）'}

	**JS缓存目录（可回查本地JS及还原源码）**:
	${typeof globalThis.__zc_js_dirs_json !== 'undefined' ? JSON.parse(globalThis.__zc_js_dirs_json).map(d => d.dump_dir + (d.has_reconstructed ? ' (含还原源码)' : '')).join('\n') : '（无）'}

${BUSINESS_ATTR_GUIDE}

${SAFETY_API_GUARDRAIL}

**【核心策略 — 🎯 Agent 发散思维 + 靶标定制】**
1. 分析 API 命名 → 推断功能 → 对应攻击:
   upload/file/import        → **文件上传绕过**
   download/export/backup    → **路径遍历/任意文件读取**
   order/payment/account     → **IDOR越权（替换id/userId）**
   login/auth/token          → **认证绕过/弱口令/JWT伪造**
   admin/manager/console     → **垂直越权/权限提升**
   config/settings/env       → **配置泄露/敏感信息**
   sql/search/query          → **SQL注入/SSTI**

   ssrf/redirect/fetch/proxy → **SSRF（替换URL为内网地址/云元数据）**

2. **SSRF 专项测试**（参数含 url/path/redirect/domain/host/target）:
   - 替换为内网地址: http://127.0.0.1:8080, http://10.0.0.1, http://172.16.0.1
   - 云元数据: http://169.254.169.254/latest/meta-data/（AWS/阿里云）
   - 华为云元数据: http://169.254.169.254/openstack/latest/
   - 内部服务探测: http://localhost:6379(Redis), http://localhost:3306(MySQL)
   - 观察响应差异: 超时vs拒绝vs返回数据 = 内网服务存活

3. **RCE 测试**（参数含 exec/cmd/command/shell/action）:
   - 表达式注入: \${7*7}, #{7*7}, \${{7*7}} 模板语法测试
   - 命令注入: ;id, |id, 'id', \$(id) 参数值注入
   - 反序列化: 检查 Content-Type 为 application/x-java-serialized-object 的请求
   - 文件上传: 尝试上传 jsp/php/jspx 文件（仅上传普通文件证明存在即可）

4. HTTP200 + 空JSON容器(data:[]/data:{}/data:null) → **不是漏洞**

5. 通用路径兜底:
   API文档: /swagger-ui.html, /v3/api-docs, /doc.html
   配置:   /.env, /actuator, /actuator/heapdump

⚠️ **硬性过滤规则:**
- JSON data 为空数组/空对象/null → 不视为信息泄露
- HTTP 200 + {"code":"1","msg":"成功","data":[]} → 不是漏洞
- confirmed 必须有实际业务数据

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
                business_attr: { type: 'string', description: '本质业务原语: read_file/write_file/exec_code/modify_state/query_data/transfer/auth' },
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
      `对 ${resolvedProject} 执行越权/弱口令等测试。

🔒 VPN 强制要求: 所有 curl/HTTP 请求必须使用 --interface tun0 参数走 VPN 隧道

高优目标:
${targets.map(function(t) { return '  ' + t.url }).join('\\n')}

第2阶段JS逆向发现的隐藏端点:
${p2_discoveries_text ? p2_discoveries_text.substring(0, 10000) : '（无 JS 分析数据）'}

${BUSINESS_ATTR_GUIDE}

${SAFETY_API_GUARDRAIL}

1. 越权测试:
   - 对含数字ID的路径，尝试替换ID值
   - 观察响应差异

2. 弱口令枚举（🎯 Agent 发散构造，不要机械列表）:
   - **Phase 2 识别的框架默认口令（结构化提取，优先级最高）**:
     ${typeof globalThis.__zc_fw_info !== 'undefined' ? (() => {
       const fw = JSON.parse(globalThis.__zc_fw_info)
       return fw.filter(f => f.default_credentials.length > 0).map(f =>
         `   · ${f.framework_name} [${f.confidence}]: ${f.default_credentials.join(', ')}`
       ).join('\n') || '   （无）'
     })() : '   （无框架识别）'}
   - **通用字典暴力枚举**（按优先级排列）:
     · 组合1: admin/admin, admin/123456, admin/Admin@123
     · 组合2: admin/Admin@123456, admin/password, admin/12345678
     · 组合3: 从项目名/公司名衍生: ${resolvedProject}/123456, cosco/123456, zhongyuan/123456
     · 组合4: 框架默认口令（JeecgBoot: jeecg/jeecg123, RuoYi: admin/admin123, JeeSite: admin/admin123）
     · 组合5: 从 JS 配置/注释中发现硬编码凭证
   - 测试 JSON API 登录（Content-Type: application/json）

3. 信息泄露检查:
   - 响应体中是否包含多余字段（密码/身份证/手机号）
   - 错误信息是否泄露路径/版本

4. 逻辑漏洞测试:
   - 金额/数量篡改: 修改 POST body 中的 amount/price/quantity
   - 流程绕过: 跳过支付步骤
   - 并发竞态: 同时请求多次

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

    // 3.3 本地部署实现 + 源码审计（对 Phase 2 识别的开源系统进行深度审计）
    let p3_codeaudit = null
    const p3_has_oss = p2_discoveries_text && p2_discoveries_text.includes('【快速开发框架识别结果】')

    // 读取框架审计缓存，避免重复审计同一框架
    let p3_framework_cache = { audited: {} }
    try {
      const fs = require('fs')
      if (fs.existsSync(frameworksCachePath)) {
        p3_framework_cache = JSON.parse(fs.readFileSync(frameworksCachePath, 'utf8'))
        log(`  📚 框架审计缓存: ${Object.keys(p3_framework_cache.audited).length} 个框架已审计`)
      }
    } catch (e) { /* 忽略缓存读取错误 */ }

    if (p3_has_oss) {
      const ossText = p2_discoveries_text.substring(p2_discoveries_text.indexOf('【快速开发框架识别结果】'), p2_discoveries_text.length).substring(0, 4000)
      const cacheNote = Object.keys(p3_framework_cache.audited).length > 0
        ? `

	**凭证**:
	${typeof globalThis.__zc_creds_json !== 'undefined' ? JSON.stringify(JSON.parse(globalThis.__zc_creds_json).slice(0, 8), null, 2) : '（无）'}
	**JS目录**: ${typeof globalThis.__zc_js_dirs_json !== 'undefined' ? JSON.parse(globalThis.__zc_js_dirs_json).map(d => d.dump_dir).join(', ') : '（无）'}\n\n注意：下表中的框架已审计过，请跳过不要重复审计:\n${Object.entries(p3_framework_cache.audited).map(([k,v]) => `  - ${k} (${v.last_audited}, ${v.findings_count}条发现)`).join('\n')}`
        : ''
      p3_codeaudit = await agent(
        `你是快速开发框架审计专家，对 ${resolvedProject} 的已识别框架执行本地部署实现和源码审计。

===== Phase 2 快速开发框架识别结果 =====
${ossText}${cacheNote}
==========================================

**【Part A: 本地部署实现】**
1. **源码获取** — 根据框架名+版本从GitHub下载（JeecgBoot/RuoYi/JeeSite/Guns/BladeX等）
2. **本地环境搭建** — 在 /tmp/zc_local_audit/ 下用 Docker/mvn/java -jar 搭建
3. **漏洞复现分析** — 在本地验证 Phase 2 识别的特有攻击面（默认口令、Shiro绕过、代码生成器、文件上传），记录 POC

**【Part B: 源码审计 — 三大审计维度】**

**维度一：权限审计（未授权探查）**
核心目标：找到无需任何凭证即可访问的接口。
1. Shiro/Spring Security 过滤链 audit — filterChainDefinitionMap 中 /anon 端点遗漏
2. Controller 鉴权注解审计 — @RequiresPermissions/@PreAuthorize 缺失的方法
3. Swagger 接口逐条测试 — 从 /doc.html /v2/api-docs 提取所有 API，无 Token 测试
4. 路由表遍历 — 关注代码生成器/文件上传/定时任务/系统配置控制器

**维度二：控制审计**
核心目标：找到可被利用的命令执行/文件读写/SQL注入。
1. 文件上传 — 后缀校验绕过(大小写/双写/截断/MIME)、路径穿越
2. 文件下载/导出 — 路径遍历(../)、XXE
3. **命令执行 — Runtime.exec/shell_exec/system/ProcessBuilder 参数可控性**
   ⚠️ **必须追溯参数来源，按场景分类:**
   **A. 业务设计（非漏洞）→ 标注 \`is_business_feature: true\` + \`reasoning_code\`:**
      - ProcessBuilder 命令硬编码（如 ffmpeg/edge-tts/git），非用户输入
      - Class.forName 有包名白名单（如 startsWith("org.jeecg.")）+ 接口校验
      - 参数来自系统配置，非 HTTP 参数
   **B. 确认为漏洞 → 正常标 severity:**
      - @RequestParam/@RequestBody 直接拼接到命令
      - Class.forName 无白名单/白名单可绕过
      - 无 @RequiresPermissions/@PreAuthorize 保护
   **每个发现必须附带:** \`is_business_feature\`, \`reasoning_code\`(代码片段), \`user_controllable\`

4. **SQL注入 — MyBatis \${} 拼接(orderBy)、@Select/@Query 原生 SQL**
5. 反序列化 — readObject/fromJson/Fastjson 输入可控、AutoType
6. SSTI — SpEL/PEL/OGNL/TemplateExpress/eval/Jinja2
7. XXE — DocumentBuilderFactory/SAXParser 配置检查

**维度三：零凭据获取 Admin Token 路径**
核心目标：找到无需用户名密码即可获取管理员令牌的路径。
1. login/auth/token 控制器 — 不校验密码即返回 Token 的特殊路径
2. 硬编码超级凭证 — adminKey/jwt.secret/token.secret 静态密钥→伪造JWT
3. 密码重置/验证码逻辑 — 重置Token可预测、验证码仅前端校验
4. OAuth/SSO — state 校验缺失、redirect_uri 任意指向、callback 无鉴权
5. Session — Token 生成可预测、Session Fixation
6. 搜索贯穿: 硬编码凭证/Shrio.key默认密钥/测试接口/后门/补丁对比

**输出**: 每发现：文件路径+行号+审计维度+类型+等级；零凭据 AdminToken 最高优先标记；CVE 给 POC；0day 标 potentially_0day

只做本地分析，不在目标系统执行破坏性操作。`,
        { label: '📦 本地部署+源码审计', schema: {
          type: 'object',
          properties: {
            local_setups: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  system_name: { type: 'string' },
                  version: { type: 'string' },
                  setup_method: { type: 'string' },
                  status: { type: 'string', enum: ['成功', '部分成功', '失败'] },
                  notes: { type: 'string' },
                },
              },
            },
            audit_findings: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  title: { type: 'string' },
                  type: { type: 'string', enum: ['硬编码凭证', 'SQL注入', '文件操作', '反序列化', '命令执行', '鉴权绕过', '表达式注入', 'XXE', '后门', '测试接口', '未授权接口', 'AdminToken绕过', '其他'] },
                  severity: { type: 'string', enum: ['严重', '高危', '中危', '低危'] },
                  audit_dimension: { type: 'string', enum: ['权限审计', '控制审计', '零凭据AdminToken'], description: '所属审计维度' },
                  file_path: { type: 'string' },
                  line_number: { type: 'number' },
                  description: { type: 'string' },
                  poc: { type: 'string' },
                  is_known_cve: { type: 'boolean' },
                  cve_id: { type: 'string' },
                  is_potential_0day: { type: 'boolean' },
                },
                required: ['title', 'type', 'severity', 'description'],
              },
            },
          },
        }, phase: '漏洞挖掘' }
      )

      if (p3_codeaudit) {
        const setupCount = p3_codeaudit.local_setups?.length || 0
        const auditCount = p3_codeaudit.audit_findings?.length || 0
        log(`  本地部署: ${setupCount} 个环境 | 源码审计: ${auditCount} 个发现`)
        if (auditCount > 0) {
          p3_codeaudit.audit_findings.forEach(f => {
            const dimIcon = f.audit_dimension === '权限审计' ? '🔓' : f.audit_dimension === '控制审计' ? '🎮' : f.audit_dimension === '零凭据AdminToken' ? '👑' : ''
            const icon = f.severity === '严重' ? '🔥' : f.severity === '高危' ? '🔴' : '🟡'
            const extra = f.is_potential_0day ? ' [⚠️ 潜在0day]' : f.is_known_cve ? ` [CVE:${f.cve_id}]` : ''
            const dim = f.audit_dimension ? ` [${f.audit_dimension}]` : ''
            log(`    ${dimIcon}${icon} [${f.severity}] ${f.title}${dim}${extra}`)
            if (f.file_path) log(`       → ${f.file_path}:${f.line_number || '?'}`)
          })
          p3_findings_data.push(...p3_codeaudit.audit_findings.map(f => ({
            title: f.title, type: f.type, severity: f.severity,
            target: p1_assets?.priority_targets?.[0]?.url || resolvedProject,
            endpoint: f.file_path || f.title,
            confidence: f.is_potential_0day ? 'exploratory' : 'suspected',
            curl_command: f.poc || '',
            phase_discovered: 'phase3_codeaudit', status: 'unverified'
          })))
          // 保存框架审计缓存
          if (p3_codeaudit.audit_findings.length > 0) {
            const frameworkSet = new Set()
            p3_codeaudit.audit_findings.forEach(f => {
              if (f.framework_name) frameworkSet.add(f.framework_name)
            })
            frameworkSet.forEach(fw => {
              p3_framework_cache.audited[fw] = {
                last_audited: '2026-07-09',
                findings_count: p3_codeaudit.audit_findings.filter(f => f.framework_name === fw).length
              }
            })
            try {
              const fs = require('fs')
              fs.writeFileSync(frameworksCachePath, JSON.stringify(p3_framework_cache, null, 2))
              log(`  💾 框架审计缓存已保存 (${frameworkSet.size} 个框架)`)
            } catch (e) { /* 忽略写入错误 */ }
          }
        }
      }
    } else {
      log('  源码审计: ⏭️ 无开源系统识别结果，跳过本地部署和源码审计')
    }
    // == 本地部署+源码审计结束 ==

    // Tier 2: 剩余资产全量测试
    const tier2_urls = allUrls.slice(0, 10)
    if (tier2_urls.length > 0) {
      p3_quick = await agent(
        `对 ${resolvedProject} 的以下剩余资产做全量漏洞测试。

${SAFETY_API_GUARDRAIL}
剩余资产列表（${tier2_urls.length} 个）:
${tier2_urls.map(function(u) { return '  ' + u }).join('\n')}

执行全量测试:
1. curl -sI 每个URL确认HTTP状态码
2. 对返回200/401/403的，探测:
   - 未授权API: /api/v1/user, /api/v1/config, /swagger-ui.html
   - 后台管理: /admin/, /console/, /login, /manager/
   - 配置泄露: /.env, /robots.txt, /WEB-INF/web.xml
   - 组件端点: /actuator, /druid, /nacos
   - 备份文件: *.bak, *.zip, *.tar.gz
3. 每个发现附带 curl 命令`,
        { label: '⚡ 剩余资产测试', schema: {
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

    // 记录维度
    ;(targets || []).forEach(t => {
      dimTracker.record(t.url, 'unauth_test', 'done')
      if ((t.tags || []).includes('[管理后台]')) {
        dimTracker.record(t.url, 'weak_pass', 'done')
      }
    })
    ;(allUrls || []).forEach(u => dimTracker.record(u, 'unauth_test', 'done', { note: 'from allUrls' }))

    // 合并发现
    const allFindings = [
      ...(p3_unauth?.findings || []),
      ...(p3_other?.findings || []),
      ...(p3_quick?.findings || []),
    ]
    progress.findings_count = allFindings.length

    log(`  发现 ${allFindings.length} 个潜在漏洞:`)
    allFindings.forEach(f => {
      const icon = f.severity === '严重' ? '🔥' : f.severity === '高危' ? '🔴' : f.severity === '中危' ? '🟡' : '⚪'
      log(`    ${icon} [${f.severity}] ${f.title} → ${f.endpoint} (${f.confidence})`)
    })
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

  const p4_all_findings = [
    ...(p3_unauth?.findings || []),
    ...(p3_other?.findings || []),
    ...(p3_quick?.findings || []),
  ]
  const p4_findings_json = JSON.stringify(p4_all_findings, null, 2)

  if (p4_all_findings.length > 0) {
    p4_verify = await agent(
      `你是360众测漏洞验证专家，对 ${resolvedProject} 的发现做严格 curl 验证。

🔒 VPN 强制要求: 所有 curl 命令必须加 --interface tun0（如: curl --interface tun0 -sk ...）
${SAFETY_API_GUARDRAIL}

====== Phase 3 传入的发现列表 ======
${p4_findings_json.substring(0, 6000)}
==================================

### 验证规则
对每个发现，必须执行以下流程：

**Step 1: 提取可测试的 URL**
- 如果 endpoint 是具体 URL → 直接测试
- 如果 endpoint 是 "前端JS包" 或 "JS文件" → 从 target 提取域名，从描述中提取 API 路径

**Step 2: 用 curl 测试**
1. 先 \`curl -sk -o /dev/null -w "%{http_code}"\` 获取数字HTTP状态码
2. 状态码 200/401/403 的，\`curl -sk\` 获取响应体

**Step 3: 判定**
| 判定 | 条件 |
|------|------|
| confirmed | curl 返回 **200 + 响应体含实际敏感数据**（用户信息/订单/配置/凭证/业务记录），且**不是**权限错误 |
| suspected | 返回 200/401 但响应体是权限错误，或需复杂利用条件 |
| needs_manual_test | 无法构造可测试 URL |
| false_positive | 404/403/超时/返回无敏感数据/仅状态码无业务数据 |

⚠️ **confirmed 的严格标准：**
1. 必须有 curl_command + http_status(数字) + evidence
2. **HTTP 200 + 权限错误（"没有接口访问权限"/"Unauthorized"/"需要登录"）= NOT confirmed**，这是认证在正常工作
3. **HTTP 403 + 任何响应体 = NOT confirmed**，403 表示服务端拒绝了请求，不等于存在漏洞
4. **\`{"success":false}\`、\`{"code":xxx,"msg":"xxx"}\` 等纯元数据响应 = NOT confirmed**，无实际业务数据泄露
5. **JS/Actuator 中找到的端点 + curl 返回 403 或空数据 = NOT confirmed**，端点存在不等于可未授权利用
6. **证据必须是实际敏感数据片段，不是状态码本身或 HTTP 头信息**
7. 三项条件缺一不可，不满足的降级为 suspected 或 false_positive

**🔥 JSON空响应检测规则（必须硬性遵守）：**
- 对每个 JSON 响应体，提取 data/records/rows/list/content/items 等业务数据字段：
- **[data] 字段为 []（空数组）或 {}（空对象）或 null → false_positive**，理由: data_empty
- **响应只含 code/msg/timestamp/success 等元数据但无业务数据 → false_positive**
- **data 字段长度 < 30 字符 → false_positive**
- **不要因为 HTTP 200 + JSON 包含"成功"字样就认为是真数据，必须检查 data 字段是否包含有意义的业务记录**
- **检测步骤（按顺序执行）:**
  Step A: curl -sk -o /tmp/zc_verify.json -w "%{http_code}" "<URL>"
  Step B: python3 -c "import json; d=json.load(open('/tmp/zc_verify.json')); print(json.dumps(d,ensure_ascii=False)[:300])"
  Step C: 提取 d.get('data') 或 d.get('rows') 或 d.get('records') 判断是否含业务数据

**360众测特殊要求：**
- 每个发现的证据需附带时间截图或时间信息
- **高危和复杂漏洞需录屏保存**（避免后续产生争议）
- **数据类漏洞需说明数量及泄露了哪些数据**（如：泄露 1000 条用户信息，包含姓名/手机号/身份证号）

---
### 🎯 Step 4: Agent 发散扩展（验证一个点时思考变种，不要只机械复述）

发散方向（对每个确认有效的发现依次思考）:
- **参数发散**: /api/user?id=1 → 试 /api/user?orderId=2, /api/user?page=1&size=100
- **方法发散**: GET → 试 PUT（修改）/ DELETE（删除）/ POST（创建）
- **路径发散**: /api/v1/user → 试 /api/v1/admin, /api/v1/config, /api/v2/user
- **鉴权发散**: 无Cookie→空Bearer→伪造Token→X-Admin:true header
- **内容类型发散**: JSON→XML（XXE测试）
- **利用链思考**: 能否与其他发现串联升级为更高危

对发散出的变种用 curl --interface tun0 快速验证。
有实际数据返回的追加到 new_variants 字段。
无新发现正常结束，不要虚构。

`,
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
                http_status: { type: 'number' },
                evidence: { type: 'string' },
                curl_command: { type: 'string' },
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
            },
          },
          new_variants: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                title: { type: 'string' },
                endpoint: { type: 'string' },
                http_status: { type: 'number' },
                curl_command: { type: 'string' },
                evidence: { type: 'string' },
                confidence: { type: 'string', enum: ['confirmed', 'suspected'] },
                divergence_type: { type: 'string', enum: ['参数发散', '方法发散', '路径发散', '鉴权发散', '内容类型发散', '利用链'] },
                parent_finding: { type: 'string' },
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
                reason: { type: 'string' },
              },
            },
          },
        },
        required: ['confirmed_findings'],
      }, phase: '验证取证' }
    )

    if (p4_verify && p4_verify.confirmed_findings) {
      // 程序化证据检查（多层过滤）
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
          log(`  🔧 化验货: [${f.severity}] ${f.title} -> ${reason}，降级`)
          p4_verify.false_positives = p4_verify.false_positives || []
          p4_verify.false_positives.push({
            title: f.title, endpoint: f.endpoint,
            reason: `自动证据检查: ${reason}`
          })
        } else {
          audited.push(f)
        }
      }
      const downgraded = p4_verify.confirmed_findings.length - audited.length
      if (downgraded > 0) log(`  🔧 已自动降级 ${downgraded} 条空证据发现`)
      p4_verify.confirmed_findings = audited

      const fp_count = p4_verify.false_positives?.length || 0
      const manual_count = p4_verify.needs_manual_test?.length || 0
      log(`  复测完成: ${p4_verify.confirmed_findings.length} 个确认有效` +
        (fp_count > 0 ? `, ${fp_count} false_positive` : '') +
        (manual_count > 0 ? `, ${manual_count} 需手动验证` : ''))

      p4_verify.confirmed_findings.forEach(f => {
        const st = f.http_status || 0
        log(`  ${st === 200 ? '✅' : '❓'} [${st}] ${f.title} → ${f.endpoint}`)
      })
      progress.findings_count = p4_verify.confirmed_findings.length

      
      // P2: 验证通过端点 → 更新字典本
      if (p4_verify && p4_verify.confirmed_findings && p4_verify.confirmed_findings.length > 0) {
        const confirmed_eps = p4_verify.confirmed_findings.filter(f => f.http_status === 200).map(f => f.endpoint)
        if (confirmed_eps.length > 0) {
          await agent(
            `python3 ${SKILL_SCRIPTS}/update_dict.py ${SKILL_SCRIPTS}/../references/api_patterns.json --endpoints '${JSON.stringify(confirmed_eps)}'`,
            { label: '📚 验证端点到字典', phase: '验证取证' }
          )
        }
      }
// 更新发现状态
      if (p3_findings_data.length > 0) {
        const confirmedEndpoints = new Set(
          p4_verify.confirmed_findings.filter(f => f.confidence === 'confirmed' && f.curl_command).map(f => f.endpoint)
        )
        const fpEndpoints = new Set((p4_verify.false_positives || []).map(f => f.title))
        const manualTitles = new Set((p4_verify.needs_manual_test || []).map(f => f.title))
        p3_findings_data = p3_findings_data.map(f => {
          if (fpEndpoints.has(f.title)) return { ...f, status: 'false_positive', phase_discovered: 'phase4' }
          if (manualTitles.has(f.title)) return { ...f, status: 'needs_manual_test', phase_discovered: 'phase4' }
          if (confirmedEndpoints.has(f.endpoint)) return { ...f, status: 'confirmed', phase_discovered: 'phase4' }
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

if (mode.startsWith('phase5') || !p1_assets || !p1_assets.priority_targets || p1_assets.priority_targets.length === 0) {
  log('[5/8] ⏭️ 跳过（无资产需标记）')
  markPhase(5, '⏭️')
} else {
  markPhase(5, '🔄')
  log('[5/8] 资产标记与状态存储')

  const p5_all_assets = (p1_assets.priority_targets || []).map(t => ({
    url: t.url, ip: t.ip, port: t.port, title: t.title || '', tags: t.tags || []
  }))

  if (p5_all_assets.length === 0) {
    log('  ⏭️ 无具体资产需标记')
    markPhase(5, '⏭️')
  } else {
    const p5_dim_rows = p5_all_assets.map(a => {
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
`).join('\n')

    const p5_findings_json = JSON.stringify(p3_findings_data, null, 2)

    // ============================================================
    // 🔧 程序化合并写入 — asset_test_status.json + asset_findings.json 追加/合并
    // ============================================================
    log('  🔧 程序化合并 asset 状态文件...')
    const p5_merge = await agent(
      `严格按以下步骤合并 ${resolvedProject} 的资产状态文件。
🔒 文件操作用Read/Write工具完成。

**任务A: 合并 asset_test_status.json（只追加合并，不覆盖）**

文件: ${PROJECT_DIR}/asset_test_status.json

操作:
1. Read读取 ${PROJECT_DIR}/asset_test_status.json → 不存在则初始化为 {"assets":{}}
2. 将本次新资产记录**追加/更新**到 assets 中
   - 新url → 追加
   - 已有url → 合并 phases_tested 去重，更新 last_tested
   - **绝对不能删除**旧记录
3. Write写回

本次需追加的维度数据:
${JSON.stringify(dimTracker.toJSON(), null, 2)}

资产详情:
${p5_dim_rows.map(function(a) { return '  ' + a.url + ': completed=[' + a.completed.join(',') + '] missing=[' + a.missing.join(',') + ']' }).join(String.fromCharCode(10))}

**任务B: 合并 asset_findings.json（按 endpoint 去重追加）**

文件: ${PROJECT_DIR}/asset_findings.json

操作:
1. Read读取 → 不存在则初始化为 {"findings":[]}
2. 追加本次发现（${p3_findings_data.length}条）到findings中
   - endpoint已存在 → 更新 status
   - endpoint不存在 → 追加
3. Write写回

本次发现:
${JSON.stringify(p3_findings_data, null, 2).substring(0, 10000)}

**硬性规则：** 不能覆盖已有文件，不能删除旧记录，按endpoint去重，
写入后执行 ls -la 确认文件大小正常。`,
      { label: '🔧 程序化合并 asset 文件', phase: '资产标记' }
    )

    const p5_mark = await agent(
      `你是360众测资产状态管理专家，对 ${resolvedProject} 的资产做测试状态标记并持久化存储。

===== 结构化测试维度数据 =====
${p5_dim_report}
==============================

===== 本批次发现的线索/漏洞 =====
${p3_findings_data.length > 0 ? p5_findings_json.substring(0, 15000) : '(无发现)'}
================================

=== 维度说明 ===
| 维度 | 说明 |
|------|------|
| http_probe | HTTP探活 |
| unauth_test | 无Cookie未授权探测 |
| dir_enum | 手动目录枚举 |
| dirsearch_scan | 全量目录扫描 |
| weak_pass | 弱口令测试 |
| js_analysis | JS逆向分析 |

=== 任务 ===
**Part A: 资产状态标记**
对每个资产判断「已完全测试完毕 / 还未测试完毕 / 无法进行测试」。
每次标记必须给出 reason 字段。

**Part B: 线索/漏洞存档**
1. 读取已有线索文件 ${findingsPath}（Read工具），如不存在则新建
2. 合并本次发现的线索（按 endpoint 去重）
3. 用Write工具写入 ${findingsPath}

=== 操作要求 ===
1. 先用Read读取 ${trackerPath}，保留旧记录
2. 用Write写入 ${trackerPath}（合并写入）
3. 用Read/Write处理 ${findingsPath}（合并写入）
4. status+reason+phases_tested+last_tested 必填`,
      { label: '🏷️ 资产状态+线索存档', schema: {
        type: 'object',
        properties: {
          assets: {
            type: 'object',
            additionalProperties: {
              type: 'object',
              properties: {
                status: { type: 'string', enum: ['已完全测试完毕', '还未测试完毕', '无法进行测试'] },
                phases_tested: { type: 'array', items: { type: 'string' } },
                last_tested: { type: 'string' },
                reason: { type: 'string' },
              },
              required: ['status', 'phases_tested', 'last_tested', 'reason'],
            },
          },
        },
        required: ['assets'],
      }, phase: '资产标记' }
    )

    if (p5_mark && p5_mark.assets) {
      // 兼容处理：如果 agent 仍写了 notes 而非 reason，自动转换
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
  log(`[6/8] 报告编写 — ${resolvedProject}`)

  // 准备输出目录
  const reportDir = `${PROJECT_DIR}/submittable_reports/`
  await agent(
    `执行命令创建报告输出目录:
    mkdir -p ${reportDir}
    确认目录已创建。`,
    { label: '📁 准备输出目录', phase: '报告编写' }
  )

  // 列出已有报告
  const existingReports = await agent(
    `列出 ${reportDir} 下所有 .md 文件的文件名，每行一个。无文件则返回空。`,
    { label: '📋 检查已有报告', phase: '报告编写' }
  )
  log(`  已有 ${(existingReports || '').split('\n').filter(Boolean).length} 个报告`)

  // 汇总发现
  const allFindingsData = [
    ...(p3_unauth?.findings || []),
    ...(p3_other?.findings || []),
    ...(p3_quick?.findings || []),
    ...(typeof p3_dirsearch !== 'undefined' && p3_dirsearch?.findings ? p3_dirsearch.findings : []),
    ...(typeof p3_codeaudit !== 'undefined' && p3_codeaudit?.audit_findings ? p3_codeaudit.audit_findings : []),
  ]
  const findingsJSON = JSON.stringify(allFindingsData, null, 2)

  // 规划报告分片
  const p5_plan = await agent(
    `你是360众测报告编写专家，为 ${resolvedProject} 的漏洞编写标准报告。

任务：规划需要生成的报告清单（仅规划分片方案，不生成正文）。

🎯 **发散思考（规划前必须执行）：**
① **发现间关系** — 存在依赖链的（A泄露→B获取→C扩大）→ 合成利用链报告
② **同源推断** — 同一API前缀/模块/框架的漏洞可能同源，合并为1份报告描述根因
③ **上下文重估** — 结合目标系统类型，低危+中危串联可升级为高危利用链

⚠️ 规则：
1. 只对确认有效的漏洞写报告
2. 同类漏洞合并，利用链用利用链格式
3. 文件名: {等级}_{类型}_{项目}_{简述}.md
4. 低危默认不生成
5. 360众测要求：报告需包含时间截图信息

====== 发现数据 ======
${findingsJSON}
========================

先检查 ${reportDir} 下已有报告避免重复。

${existingReports ? `已有报告:\n${existingReports}` : ''}

输出规划：file_name, severity, title, finding_indices`,
    { label: '📝 规划报告分片', schema: {
      type: 'object',
      properties: {
        reports: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              file_name: { type: 'string' },
              severity: { type: 'string', enum: ['严重', '高危', '中危', '低危', '信息'] },
              title: { type: 'string' },
              finding_indices: { type: 'array', items: { type: 'number' } },
            },
            required: ['file_name', 'severity', 'title', 'finding_indices'],
          },
        },
      },
      required: ['reports'],
    }, phase: '报告编写' }
  )

  if (p5_plan && p5_plan.reports && p5_plan.reports.length > 0) {
    log(`  规划写入 ${p5_plan.reports.length} 份报告...`)
    progress.reports_count = p5_plan.reports.length

    const writeResults = []
    const _REPORT_BATCH = 2
    for (let _ri = 0; _ri < p5_plan.reports.length; _ri += _REPORT_BATCH) {
      const _rBatch = p5_plan.reports.slice(_ri, _ri + _REPORT_BATCH)
      log(`  📄 报告写入批次 ${Math.floor(_ri/_REPORT_BATCH)+1}/${Math.ceil(p5_plan.reports.length/_REPORT_BATCH)}（${_rBatch.length}份·防冻结）`)
      const _rResults = await parallel(
      _rBatch.map((rpt) => () => {
        const myFindings = (rpt.finding_indices || []).map(i => allFindingsData[i])
        const myFindingsJSON = JSON.stringify(myFindings, null, 2)
        const filePath = `${reportDir}${rpt.file_name}`

        // 带重试机制的写入（最多2次）
        const tryWrite = async (attempt = 1) => {
          return await agent(
          `【必须实际调用Write工具】你正在为360众测项目写入漏洞报告。

报告信息:
- 文件名: ${rpt.file_name}
- 标题: ${rpt.title}
- 严重等级: ${rpt.severity}
- 项目: ${resolvedProject}
- 目录: ${reportDir}

====== 该报告包含的发现 ======
${myFindingsJSON}
==============================

你的任务：
1. 根据上述发现的原始数据，生成完整的Markdown格式报告
2. 调用Write工具写入 ${filePath}
3. 执行 ls -la 和 wc -l 确认写入成功

报告格式要求：
- 包含漏洞信息表（名称、等级、类型、影响范围、发现时间）
- 包含漏洞描述 + 复现步骤 + HTTP请求/响应包 + curl命令
- **360众测要求：需包含时间截图或时间信息**
- 包含修复建议
- 敏感数据脱敏

注意：必须实际调用Write工具。`,
          { label: `📄 ${rpt.file_name}`, phase: '报告编写' }
        )}

        return tryWrite(1).catch(err => {
          log(`  ⚠️ 第1次写入失败: ${rpt.file_name} — ${err.message}`)
          return tryWrite(2).catch(err2 => {
            log(`  ❌ 重试也失败: ${rpt.file_name} — ${err2.message}`)
            return { rpt, result: null, success: false }
          })
        })
      })
    )

    const successCount = writeResults.filter(Boolean).length
    log(`  ✅ 完成 ${successCount}/${p5_plan.reports.length} 份报告`)
  }

  // 生成HTML版本
  const p6_html = await agent(
    `运行HTML报告生成脚本:
    python3 ${SKILL_SCRIPTS}/generate_html.py ${reportDir}

    检查输出目录 ${reportDir}reports_html/ 是否生成了对应的 .html 文件。
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

  const reportDir = `${PROJECT_DIR}/submittable_reports/`

  const p6_rules = await agent(
    `读取以下两个文件内容（用Read工具）:
1. 判定规则: /home/my/.claude/skills/ZC_SKILLS_V1/references/judgment-rules.md
2. 项目VulnType: ${PROJECT_DIR}/VULN_TYPE.html（如果不存在，查看目录下 *_Information.html 类似文件）

输出读取结果摘要。`,
    { label: '📖 读取判定规则 + VulnType', phase: '自审' }
  )

  const p6_audit = await agent(
    `你是360众测报告审计专家，对 ${resolvedProject} 的报告做最终判定 (F/R/T)。

判定规则:
${(p6_rules || '(读取失败)').substring(0, 2500)}

报告目录: ${reportDir}

任务 — 对每份报告逐项判定：

1. 文件格式检查:
   - 命名规范: {等级}_{类型}_{项目}_{简述}.md
   - 包含HTTP请求/响应包 + curl命令
   - 敏感数据已脱敏
   - **包含时间截图或时间信息（360众测要求）**

2. 等级准确性: 对照judgment-rules判定

3. 厂商接受度: 对照VulnType（接受类型？忽略清单？）

4. 重复检测: 端点重叠检查

5. 最终判定:
   - T (属实) — 可提交
   - R (保留) — 需进一步观察
   - F (不符) — 移入 _invalid/

输出JSON格式。`,
    { label: '🔍 最终判定 (F/R/T)', schema: {
      type: 'object',
      properties: {
        reports: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              file_name: { type: 'string' },
              verdict: { type: 'string', enum: ['T', 'R', 'F', 'skip_duplicate'] },
              severity_accurate: { type: 'boolean' },
              type_accepted: { type: 'boolean' },
              has_timestamp: { type: 'boolean', description: '是否包含时间截图/时间信息' },
              issues: { type: 'array', items: { type: 'string' } },
              suggestion: { type: 'string' },
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
    log(`  📊 结果: T(可提交) ${tCount} | R(保留) ${rCount} | F(不符) ${fCount}`)
    p6_audit.reports.filter(r => r.verdict === 'F').forEach(r => {
      log(`    🗑️ ${r.file_name}: ${(r.issues || []).join('; ')}`)
    })
    // F判定报告 → 移入 _invalid/ → 运行整合脚本
    if (fCount > 0) {
      const fNames = p6_audit.reports.filter(r => r.verdict === 'F').map(r => r.file_name)
      await agent(
        `执行以下命令处理F判定的报告（${fCount} 份）:

1. 创建 _invalid/ 目录:
   mkdir -p ${reportDir}_invalid/

2. 将以下报告移入 _invalid/ 目录:
${fNames.map(n => '   mv "' + reportDir + n + '" "' + reportDir + '_invalid/' + n + '"').join('\n')}

3. 运行整合脚本:
   python3 ${SKILL_SCRIPTS}/consolidate_findings.py ${reportDir}

4. 确认文件已移动:
   ls -la "${reportDir}_invalid/"`,
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

const reportDir_final = `${PROJECT_DIR}/submittable_reports/`

await agent(
  `提交准备 — 执行最终检查:

**检查清单：**
1. 文件名规范: ls "${reportDir_final}"*.md

2. 完整HTTP请求/响应包确认:
   Read每份md文件，确认包含HTTP请求/响应包 + curl命令

3. **漏洞URL仍可访问**（复测要求）:
   提取漏洞URL用 curl -sI 确认

4. **时间截图检查**（360众测特殊要求）:
   确认每份报告含 "时间截图" 或 "时间信息"

5. 厂商合规: 类型在VulnType接受范围内

    6. 敏感数据脱敏确认:
       - 手机号/身份证号/真实Cookie/Token

    7. **URL来源检查**（360众测特殊要求）:
       确认每份报告包含了漏洞URL是从哪里发现的（如：从Hunter资产发现 / 从JS中发现的API / 从目录扫描发现等）

    8. **弱口令来源检查**（360众测特殊要求）:
       如果是弱口令/默认口令类漏洞，需确认报告说明了用户名密码的获取来源（如：框架默认口令库 / 从JS配置文件中发现 / 通用字典爆破等）

    **输出：** 列出每份报告及检查结果（✅/❌），按严重→高危排序`,
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
log(`║  项目     │ ${(progress.project || '').padEnd(36)} ║`)
log(`║  模式     │ ${String(mode).padEnd(36)} ║`)
log(`║  发现数   │ ${String(progress.findings_count).padEnd(36)} ║`)
log(`║  报告数   │ ${String(progress.reports_count).padEnd(36)} ║`)
log('╠══════════════════════════════════════════════════════════════╣')
log(`║  ① ${progress.phase1}   ② ${progress.phase2}   ③ ${progress.phase3}   ④ ${progress.phase4}   ⑤ ${progress.phase5}   ⑥ ${progress.phase6}   ⑦ ${progress.phase7}   ⑧ ${progress.phase8}   ║`)
log('╚══════════════════════════════════════════════════════════════╝')
showProgress()

return {
  project: resolvedProject,
  mode,
  progress: { ...progress },
  summary: {
    priority_targets: (p1_assets?.priority_targets || []).length,
    findings: progress.findings_count,
    reports: progress.reports_count,
  },
}

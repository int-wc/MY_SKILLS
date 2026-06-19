---
name: butian-src-mining
description: >
  补天(Butian)专属SRC漏洞挖掘全流程技能。当用户请求涉及以下任一场景时激活：
  
  **核心场景：**
  1. SRC漏洞挖掘：挖掘补天专属SRC漏洞、渗透测试、众测、打补天、挖洞
  2. Hunter资产分析：粘贴或指定Hunter CSV/JSON数据进行资产分析、攻击面识别、子域名发现
  3. 报告编写：生成漏洞报告、格式转换(.md/.html)、按模板写报告、报告规范化
  4. JS逆向/API发现：分析JavaScript文件、寻找隐藏API端点、前后端源码审计
  5. 组件/系统审计：审计开源组件源码、识别开源系统/框架、CVE匹配、版本指纹
  6. 漏洞复现与验证：验证漏洞是否有效、复测端点、确认漏洞存在性
  7. 报告自审/质量检查：检查报告格式合规性、判断是否达到提交标准、运行audit脚本
  8. 深度利用/利用链：分析多漏洞组合、权限提升链、长利用链构建
  9. 目标选择/范围确认：推荐挖掘目标、查看厂商Information/VulnType、确认资产范围
  10. 漏洞等级判定：分类严重/高危/中危/低危、判断是否忽略、对标准则

  **触发关键词：**
  补天、butian、SRC、漏洞挖掘、渗透测试、众测、Hunter、资产分析、JS逆向、API发现、
  组件审计、报告生成、漏洞验证、复测、自审、利用链、专属SRC、赏金、漏洞报告、
  Information.html、VulnType、hunter_info、hunter_assets、submittable_reports、
  深度挖掘、扩散思维链、第一性原理、多链路API漏洞联动、隐藏API、长利用链
---

# 补天专属SRC漏洞挖掘技能

**注意：挖掘过程，不能实行删除、修改、覆盖操作，仅可说明有此功能存在。**

## 技能结构

```
SRC_SKILLS_V1/
├── SKILL.md                    ← 本文件：核心流程指令（≤500行）
├── workflow_runner.js          ← 全自动8阶段workflow编排
├── scripts/                    ← 自动化脚本
│   ├── generate_html.py        # MD→HTML 批量转换
│   ├── audit_reports.py        # 报告质量审计
│   ├── consolidate_findings.py # 报告整合/无效归档
│   ├── fetch_hunter.py         # Hunter API 资产采集
│   ├── probe.sh                # 路径探测脚本
│   ├── probe2.sh               # 批量API路径探测
│   └── probe_actuator.sh       # Actuator端点探测
├── references/                 ← 详细参考文档
│   ├── judgment-rules.md       # F/R/T 三级判定规则 ⬅ 必读
│   ├── vulntype-matrix.md      # 各厂商VulnType速查
│   ├── deep-mining-methodology.md # 深度挖掘方法论
│   ├── hunter-reference.md     # Hunter语法与探测命令
│   ├── phase-cmd-reference.md  # 各阶段bash命令/字典/CVE表
│   └── report-templates.md     # 报告模板(标准+利用链)
└── assets/
    ├── report-template.html    # 报告HTML样式模板
    └── 报告导航.html           # 报告导航面板
```

## 启动检查

```bash
for tool in curl jq nmap masscan httpx dirsearch hydra python3 awk sed grep; do
  command -v $tool &>/dev/null && echo "[✓] $tool" || echo "[✗] $tool 缺失"
done
python3 -c "import requests, bs4, lxml" 2>/dev/null || echo "pip install requests bs4 lxml"
```

**缺工具策略：** 缺 masscan → nmap 替代；缺 dirsearch → ffuf/手动curl；缺 httpx → `curl -sI`

---

## 八阶段工作流

```
阶段1: 资产发现与目标识别  →  目标清单 + 范围确认
阶段2: 深度分析              →  隐藏端点 + 攻击面清单
阶段3: 漏洞挖掘              →  原始发现列表
阶段4: 验证与证据            →  可复现POC/EXP
阶段5: 资产标记              →  已测资产状态存储（避免重复测试）
阶段6: 报告编写              →  .md + .html 双格式报告
阶段7: 自审                  →  判定结果(可提交/保留/不符)
阶段8: 提交准备              →  最终可提交报告包
```

---

## 阶段1：资产发现与目标识别

1. **读取厂商信息**：`{公司}/*_Information.html`（范围/赏金/域名/禁止事项）+ `VulnType.html`（接受类型/忽略清单）
2. **解析Hunter资产**：CSV列—IP,端口,域名,url,标题,状态码,组件,备案。按维度打标签：
   - `[管理后台]` 最高 | `[新发现][范围内][境外资产]` 高 | `[非常见端口][组件指纹]` 中
3. **URL聚合去重**：同域名不同端口→保留HTTP+HTTPS各一；同IP不同域名→独立保留
4. **全端口扫描扩充**（最高优先级）：masscan/nmap → 域名-IP映射 → httpx探活 → `[全端口发现]`标签
5. **目标优先级**: RCE > 大量敏感数据 > 文件读写 > SSRF > 越权 > 信息泄露 > XSS > 弱口令
6. 详细命令 → `references/phase-cmd-reference.md#阶段1-资产发现命令`

**单URL模式：** 指定 `mode: "url"` 跳过资产发现和深度分析，直接对单个URL执行漏洞挖掘全流程。
```
Workflow({scriptPath: "...", args: {mode: "url", url: "https://target.com:8080"}})
```

---

## 阶段2：深度分析

**四层JS分析**（不用固定API命名模式，以实际代码为准）：
1. **定位API入口**：查找 baseURL/API_HOST/gatewayUrl 等配置
2. **路径模式提取**：全量提取路径，按一级目录分组统计（非标准前缀如 `/gateway/` `/dwr/` 更常见）
3. **Source Map还原**：`//# sourceMappingURL=` → 下载 `.js.map` → 还原源码
4. **敏感信息提取**：AccessKey/SecretKey/JWT/数据库连接串/硬编码测试账号

**鉴权方式识别**：先找鉴权方式再测试（Authorization: Bearer/Basic/X-TOKEN/Cookie/localStorage）

**组件审计**：指纹识别 → 源码获取(GitHub/官方) → 本地审计(路由表/硬编码凭证/鉴权白名单) → 回测目标

详细命令 → `references/phase-cmd-reference.md#阶段2-js逆向命令`

---

## 阶段3：漏洞挖掘

以**反思为主、迁跃为辅、分析为底、扩展为路**的原则执行。Agent 提示词中嵌入了"分析为底→第一性原理→扩散思维链"的方法论引导。
详细方法论（含思维模型、第一性原理、扩散链示例） → `references/deep-mining-methodology.md`

| 类型 | 测试要点 |
|------|---------|
| 未授权/信息泄露 | 批量不带Cookie重放，对比响应差异 |
| API文档/配置泄露 | swagger-ui / actuator / .env / .git |
| 越权(IDOR) | 替换user_id/order_id/company_id |
| RCE | 反序列化/文件上传/表达式注入/已知CVE |
| SSRF | URL参数 → 内网地址 + 云元数据 |
| 弱口令 | 通用字典 + JS发现的默认凭证 |
| 逻辑漏洞 | 金额修改/优惠券叠加/流程绕过 |

批量测试脚本、弱口令字典、框架定制路径 → `references/phase-cmd-reference.md#阶段3-漏洞挖掘命令`

---

## 阶段4：验证与证据

**不允许虚构漏洞或伪造证明。** 详细判定规则 → `references/judgment-rules.md`

- [必需] 完整HTTP请求包 + 响应包 + 200 OK + curl可复现命令
- [必需] 漏洞当前仍可访问且返回200（curl重放确认）
- [推荐] 敏感数据脱敏
- 每个发现做确认性复测，true_positive / false_positive 分类

**有效性判定速查：**
- **F(不符)**: 资产不符/无复现/漏洞不成立/明确不收
- **R(保留)**: 非敏感泄露/利用门槛高/暴露未深入/利用价值低
- **T(属实)**: 完整攻击链/高敏感数据未授权获取
- **401/403 ≠ 未授权漏洞**（除非有绕过或响应体含敏感数据）

**严格 curl 验证（Phase 4）：**
每个发现必须经过以下流程：
1. 提取可测试 URL（JS 类发现从描述拼装具体路径）
2. `curl -sI` 获取 HTTP 状态码
3. 状态码 200/401/403 的，`curl -s` 获取响应体
4. 记录 `http_status` + `curl_command` + `evidence`

| 判定 | 条件 |
|------|------|
| confirmed | curl 200 + 响应体含**实际敏感数据**（非权限错误）|
| suspected | 200 但返回 `"没有接口访问权限"` / `"Unauthorized"` / `"需要登录"` |
| needs_manual_test | 无法构造可测试 URL |
| false_positive | 404/超时/返回无敏感数据 |

**confirmed 的严格标准：**
1. 必须有 http_status + curl_command + evidence
2. **HTTP 200 + 权限错误 ≠ confirmed**（说明认证正常，只是端点暴露）
3. **JS 路径 + curl 无实际数据 ≠ confirmed**（SPA 源码泄漏不是未授权漏洞）
4. 证据必须是敏感数据片段（用户信息/订单/配置/凭证），不能只是状态码

---

## 阶段5：资产标记与状态存储

**目的：** 标记每个已测资产的测试状态并持久化存储，避免后续重复测试。

**三种标记状态（必填 reason 字段说明依据）：**
- **「已完全测试完毕」** — 所有适用测试维度已完成 + 无漏洞发现或已出报告
- **「还未测试完毕」** — 部分维度未完成，或存在更深挖掘价值的方向
- **「无法进行测试」** — 端口关闭/无法连接/非Web服务/非本厂商范围

每次标记必须附带 `reason` 字段，例如：
- `"已完成全部7维度测试，无新发现"`
- `"缺漏 dir_enum, dirsearch_scan 维度，仅做了端口扫描和未授权探测"`
- `"端口关闭，无法建立TCP连接"`

### 线索/漏洞存储

Phase 5 同时将发现写回 `asset_findings.json`：

| 字段 | 说明 |
|------|------|
| `title` | 漏洞标题 |
| `type` | 漏洞类型 |
| `severity` | 严重/高危/中危/低危/信息 |
| `target` | 目标URL |
| `endpoint` | 具体端点 |
| `status` | unverified / confirmed / false_positive |
| `phase_discovered` | 发现阶段 |
| `curl_command` | 复现命令 |

### 多层级漏洞挖掘（Phase 3 覆盖策略）

为了解决维度覆盖不足（如 62 个资产仅前 5 个做了全量测试），Phase 3 采用两层策略：

| 层级 | 目标 | 测试深度 | 维度 |
|------|------|---------|------|
| Tier 1 高优 | 前 5 个 priority_targets | 全量 | unauth + weak_pass + dir_enum + js_analysis |
| Tier 2 快速 | 剩余全部资产（≈30 个） | 轻量 | 仅 unauth（curl 常见路径） |

Tier 2 快速探测确保每个资产至少完成 unauthtest，弥补"44 个资产仅 3 维度"的缺口。

### 测试维度矩阵

| 维度 | 编码 | 判定条件 | 适用场景 |
|------|------|---------|---------|
| 端口扫描 | `port_scan` | masscan/nmap 已执行 | 所有 IP 资产 |
| HTTP探活 | `http_probe` | curl/httpx 返回了 HTTP 响应 | 开放了 Web 端口 |
| 未授权测试 | `unauth_test` | 无 Cookie/Token 探测了至少 5 个 API 路径 | 有 HTTP 响应 |
| 目录枚举(手动) | `dir_enum` | curl 手动探测了常见/自定义前缀路径 | Web 应用 |
| dirsearch全量扫描 | `dirsearch_scan` | dirsearch 或等效工具进行了全量扫描 | Web 应用（发现较少时触发） |
| 弱口令测试 | `weak_pass` | 对登录口尝试了通用字典 | 识别出登录/后台表单 |
| JS/API分析 | `js_analysis` | JS 逆向提取了 API 路径和鉴权方式 | 有 HTML + JS 的 SPA 应用 |

### 自动判定规则

系统基于 `dimTracker` 记录的实际完成维度自动判定，**agent 可基于泛化判断覆盖**：

| 自动判定 | 条件 | agent可覆盖的场景 |
|---------|------|-----------------|
| 已完全测试完毕 | 适用维度全部完成 + 无发现或已出报告 | 认为某个维度（如 dir_enum）测试不充分，用了默认路径但没试自定义前缀 |
| 还未测试完毕 | ≥1 个适用维度没做，或发现可疑点未跟进 | 确认某个维度确实不适用（如静态CDN无需dirsearch） |
| 无法进行测试 | 0 个维度完成（端口全关/超时/非HTTP） | 发现资产其实可访问但之前记录有误 |

**关键设计：** `dir_enum` 维度依赖 agent 的泛化能力——系统只记录「是否做了目录枚举」，但 agent 判断时会评估使用了哪些路径和前缀。如果只扫了 `/admin/` 但没试 `/gateway/` `/dwr/` `/sys/` 等自定义前缀，agent 可降级为「还未测试完毕」。

### 存储位置

- **资产状态：** `{公司}/asset_test_status.json`
- **线索存档：** `{公司}/asset_findings.json`

### 工作流行为

1. **启动时**读取 `asset_test_status.json`，已标记「已完全测试完毕」或「无法进行测试」的资产自动跳过
2. **Phase 1-4** 执行过程中，`dimTracker` 实时记录每个资产完成了哪些维度
3. **Phase 3** 分两层（Tier 1 全量 + Tier 2 快速）尽可能覆盖更多资产
4. **Phase 5** 根据记录自动判定 + agent 校准，统一写入文件（只更新本次资产，保留旧记录）

### 避免重复测试机制

- Phase 1 加载已测试资产列表，从 `priority_targets` 和 `all_urls` 中剔除
- 已过滤资产不会进入 Phase 2-4 的任何测试环节
- Phase 5 写入的 `phases_tested` 数组作为下次运行的维度恢复依据

---

## 阶段6：报告编写

**文件命名：** `{等级}_{漏洞类型}_{公司简称}_{简述}.md`

**编写顺序：** 严重 → 高危 → 中危 → 低危（低危仅在严重/高危/中危全部完成后才考虑）

**默认过滤规则：**
- **低危漏洞默认不生成报告**（除非用户明确要求包含低危）
- **CORS同源配置缺陷默认不生成报告**（如 `Access-Control-Allow-Origin: *` 或任意源反射，除非用户明确要求）

**结构要求：** 漏洞信息表 → 漏洞描述 → 复现步骤(HTTP请求/响应包+curl) → 影响 → 修复建议 → 验证记录

**组合利用链：** 多漏洞串联时使用攻击链路图格式，最终等级以链路中最高的单步危害+可达性综合判定

详细模板 → `references/report-templates.md`

**双格式输出：** 写`.md` → `python3 scripts/generate_html.py` → 生成`.html`到 `reports_html/`

---

## 阶段7：自审

1. **读取判定规则**：`references/judgment-rules.md`（F/R/T规则+等级判定表）
2. **读取厂商VulnType**：`{公司}/VulnType.html` → 接受类型+忽略清单
3. **逐报告判定**：
   - 格式合规（命名/请求包/curl/脱敏）
   - 等级准确性（对照等级判定表）
   - 厂商接受度（类型在范围内？非忽略清单？）
   - **最终判定：T(可提交) / R(保留) / F(不符)**
4. **重复检测**：同厂商报告间检查端点重叠（同API前缀同类漏洞→合并；不同前缀但同类→确认非同一修复方案再独立）
5. **无效处理**：F判定 → 移入 `_invalid/` → 运行 `python3 scripts/consolidate_findings.py`

---

## 阶段8：提交准备

**最终检查清单：**
- [ ] 文件名 `{等级}_{类型}_{公司}_{简述}.md` 规范
- [ ] 完整HTTP请求/响应包 + 200 OK + curl可复现
- [ ] 漏洞URL当前仍可访问（复测通过）
- [ ] 类型在VulnType接受范围内 + 不在忽略清单
- [ ] 等级与危害匹配 + 敏感数据已脱敏
- [ ] HTML版本已生成

**提交顺序：** 严重→高危→中危→低危。同类合并。每个报告独立提交，证据链完整。

---

## 关键路径速查

| 用途 | 路径 |
|------|------|
| 所有专属SRC公司 | `/home/my/butiansrc/Exclusive_SRC/` |
| 公司信息+规则 | `{公司}/*_Information.html` |
| 漏洞类型定义 | `{公司}/VulnType.html` |
| 可提交报告 | `{公司}/submittable_reports/` |
| HTML报告 | `{公司}/submittable_reports/reports_html/` |
| 无效报告归档 | `{公司}/submittable_reports/_invalid/` |
| Hunter资产数据 | `{公司}/hunter_info/` |
| 报告导航面板 | `/home/my/butiansrc/Exclusive_SRC/报告导航.html` |
| 阶段命令参考 | `references/phase-cmd-reference.md` |
| 报告模板 | `references/report-templates.md` |
| 判定规则 | `references/judgment-rules.md` |
| 厂商VulnType | `references/vulntype-matrix.md` |

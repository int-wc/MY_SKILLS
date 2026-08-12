---
name: bsrc-mining
description: >
  字节跳动安全响应中心(ByteSRC, src.bytedance.com)专属SRC漏洞挖掘全流程技能。当用户请求涉及以下任一场景时激活：
  
  **核心场景：**
  1. SRC漏洞挖掘：挖掘字节跳动（中国区）全线产品漏洞、渗透测试、挖洞、BSRC
  2. Hunter资产分析：粘贴或指定Hunter CSV/JSON数据进行字节资产分析、攻击面识别、子域名发现
  3. 报告编写：生成ByteSRC漏洞报告、格式转换(.md/.html)、按模板写报告、报告规范化
  4. JS逆向/API发现：分析JavaScript文件、寻找隐藏API端点、前后端源码审计
  5. 组件/系统审计：审计字节业务开源组件、识别字节自研系统/框架、CVE匹配、版本指纹
  6. 漏洞复现与验证：验证漏洞是否有效、复测端点、确认漏洞存在性
  7. 报告自审/质量检查：检查报告格式合规性、判断是否达到ByteSRC提交标准、运行audit脚本
  8. 深度利用/利用链：分析多漏洞组合、权限提升链、长利用链构建
  9. 目标选择/范围确认：推荐字节业务挖掘目标、查看业务系数/等级标准、确认资产范围
  10. 漏洞等级判定：分类重大/严重/高危/中危/低危/忽略、判定业务系数档位、对标准则

  **触发关键词：**
  字节跳动、ByteSRC、BSRC、抖音、抖音电商、飞书、火山引擎、豆包、财经、西瓜视频、今日头条、
  番茄小说、剪映、懂车帝、巨量引擎、扣子、coze、Trae、bytedance.com、douyin.com、volcengine.com、
  feishu.cn、larkoffice.com、oceanengine.com、src.bytedance.com、字节、漏洞挖掘、渗透测试、
  Hunter、资产分析、JS逆向、API发现、组件审计、报告生成、漏洞验证、复测、自审、利用链、
  专属SRC、赏金、漏洞报告、深度挖掘、扩散思维链、第一性原理、多链路API漏洞联动、隐藏API、长利用链
---

# ByteSRC 专属SRC漏洞挖掘技能

**注意：挖掘过程不能实行删除、修改、覆盖操作，仅可说明有此功能存在。**

> **ByteSRC 测试红线（必须遵守，违反将被取消奖励/封号）：**
> 1. 仅允许**手工测试**，禁止用扫描器或其他自动化工具、禁止产生大量数据流量
> 2. 禁止任何形式的 DoS/DDoS 测试；禁止内网渗透、横向移动、上传 webshell、反弹 shell
> 3. 越权读取时**证明读取数量即可，真实数据不超过 5 组**，严禁批量读取；自备测试账号，敏感增删改不得涉及线上真实用户
> 4. 所有敏感测试行为（反弹shell/容器逃逸/改密/删改数据/文件上传等）**必须提前报备**，未经报备的测试结果不予以奖励
> 5. AK/SK 泄露类报告**直接提交平台即可**（含 AK/SK），由审核验证影响范围与等级，严禁自行深入业务验证危害
> 6. 注入漏洞严禁读取表内数据，UPDATE/DELETE/INSERT 类注入不允许自动化工具测试
> 7. 禁止下载、保存、传播业务敏感数据（源码/运营数据/用户资料/登录凭证），SRC确认后立即删除
> 8. 禁止使用任何违反平台规定或法律法规的文字、图片、视频作为测试素材

## 技能结构

```
BSRC_SKILLS_V1/
├── SKILL.md                    ← 本文件：核心流程指令
├── workflow_runner.js          ← 全自动8阶段workflow主流程（BSRC定制版）
├── scripts/                    ← 自动化脚本
│   ├── download_js.py          # JS下载到本地
│   ├── enumerate_chunks.py     # Webpack chunk枚举补下载
│   ├── extract_creds.py        # 从JS提取鉴权凭证
│   ├── find_js_dumps.py        # 查找JS缓存/还原目录
│   ├── smart_fuzz.py           # 基于系统特征的智能路径枚举
│   ├── merge_assets.py         # 程序化合并asset文件
│   ├── update_dict.py          # 更新API模式字典(LRU裁剪)
│   ├── generate_html.py        # MD→HTML 批量转换
│   ├── audit_reports.py        # 报告质量审计
│   ├── consolidate_findings.py # 报告整合/无效归档
│   ├── fetch_hunter.py         # Hunter API 资产采集
│   ├── probe.sh                # 路径探测脚本
│   ├── probe2.sh               # 批量API路径探测
│   ├── attack_surface_match.py  # 攻击面前匹配（Phase2→3）
│   └── chain_linking.py        # 原语链联动推理（Phase3→4）
├── references/                 # 详细参考文档
│   ├── judgment-rules.md      # ByteSRC F/R/T判定 + 六级等级 + 业务系数 ⬅ 必读
│   ├── vulntype-matrix.md     # ByteSRC等级/业务系数速查矩阵
│   ├── deep-mining-methodology.md # 深度挖掘方法论
│   ├── hunter-reference.md    # Hunter语法与探测命令
│   ├── phase-cmd-reference.md # 各阶段bash命令/字典/CVE表
│   ├── report-templates.md    # 报告模板(标准+利用链)
│   ├── api_patterns.json      # 跨SRC积累的API模式字典（自动增长）
│   ├── attack_surfaces.json    # 攻击面模式库（signals前匹配 + 实例积累）
│   └── primitive-chains.json    # 业务原语链库（原语组合→有效危害 + 实例积累）
└── assets/
    ├── report-template.html    # 报告HTML样式模板
    └── 报告导航.html           # 报告导航面板
```

## 启动检查

```bash
for tool in curl jq httpx python3 awk sed grep; do
  command -v $tool &>/dev/null && echo "[✓] $tool" || echo "[✗] $tool 缺失"
done
python3 -c "import requests, bs4, lxml" 2>/dev/null || echo "pip install requests bs4 lxml"
```

**缺工具策略：** 缺 dirsearch → ffuf/手动curl；缺 httpx → `curl -sI`。默认只用手工 curl（ByteSRC 禁扫描器，dirsearch 仅用于自建靶机/离线本地环境，不用于线上）。

---

## 八阶段工作流

```
阶段1: 资产发现与目标识别  →  目标清单 + 范围确认（对照ByteSRC业务系数表）
阶段2: 深度分析           →  隐藏端点 + 开源系统识别 + 攻击面清单
阶段3: 漏洞挖掘           →  原始发现列表 + 本地部署实现 + 源码审计发现
阶段4: 验证与证据         →  可复现POC/EXP（真实数据≤5组）
阶段5: 资产标记           →  已测资产状态存储（避免重复测试）
阶段6: 报告编写           →  .md + .html 双格式报告
阶段7: 自审               →  判定结果(可提交/保留/不符) + 业务系数 + 忽略清单
阶段8: 提交准备           →  最终可提交报告包
```

---

## 阶段1：资产发现与目标识别

1. **读取 ByteSRC 统一规则**：`/home/my/SRC/BSRC/markdown/ByteSRC安全报告处置规则V6.0.md`（业务系数表/六级等级/收录范围/忽略清单/测试红线）
2. **解析Hunter资产**：CSV列—IP,端口,域名,url,标题,状态码,组件,备案。按维度打标签：
   - `[特权资产]` 最高 | `[管理后台]` High | `[范围内][新发现]` Med | `[非常见端口][组件指纹]` Low
3. **URL聚合去重**：同域名多端口→保留HTTP+HTTPS各一；同IP不同域名→独立保留
4. **严格域名过滤**：只保留字节跳动（中国区）业务域（douyin.com/jinritemai.com/ixigua.com/toutiao.com/bytedance.com/feishu.cn/volcengine.com/coze.cn/oceanengine.com/trae.cn 等系数表内业务）；第三方供应商/外包/ISV/非中区产品/火山·BytePlus外部客户域名全部剔除
5. **特权资产识别（核心策略）**：SRC 太多人挖，真正的洞在**别人挖不了的特权资产**里。逐个资产识别付费/企业版/认证白名单/开放平台AppKey/管理运营内部/新业务冷门/敏感数据等特权信号，命中即标 `[特权资产]` priority=最高，reason 注明"为什么别人挖不到"。category_breakdown 统计 privileged。
6. **目标优先级**: [特权资产] 优先 → 高危RCE> 大量敏感数据> 文件读写> SSRF(统一高系数) > 越权> 信息泄露> XSS > 弱口令
7. 详细命令 → `references/phase-cmd-reference.md#阶段1-资产发现命令`


**split-horizon DNS / hosts 碰撞（目标不可达处理）:** 目标域名 curl 超时/连接失败时，**先判断 split-horizon DNS 再 hosts 碰撞**，禁止因 DNS 超时直接放弃资产。
- 本地解析出内网IP（10.x/172.16-31.x/192.168.x/100.64.x/169.254.x）→ split-horizon → 用 FOFA资产CSV / 同域其他主机名（minio.xx.com/xx-dev.xx.com）溯源公网IP → curl 加 `--resolve <host>:<port>:<公网IP>` 直连（保持Host头），验证 HTTP 200 后该域名后续所有 curl 一律带 `--resolve`
- hosts 碰撞：对资产CSV全部公网IP批量 `timeout 2 nc -zv -w 2 <ip> <port>` 探测目标端口，找到同端口开放的其他IP后用目标Host头请求验证服务指纹（S3 XML/MinIO/应用标题）
- 判定 IP 白名单门禁（TCP 可连但发数据即 RST，`write:errno=104`）→ 服务公网暴露但 IP 受限，改走平台侧可达面（API/导出/SSRF）间接验证，报告中如实标注网络边界
- zsh 注意：`--resolve` 参数必须内联写在 curl 命令里，不能放变量（未引号变量不 word-split）
- 详细命令 → `references/dns-hosts-collision.md`

**单URL模式：** 指定 `mode: "url"` 跳过资产发现和深度分析，直接对单个URL执行漏洞挖掘全流程。
```
Workflow({scriptPath: "...", args: {mode: "url", url: "https://target.com:8080"}})
```

**C/S 并行挖掘（按域粒度，引擎约束适配）：** 引擎**嵌套 workflow() 无法向子脚本传 args**（子 `args` 为 undefined），因此派发必须由编排器（主循环）发**独立顶层 workflow**，每域一个 Client，并行度 ≤10。`domain_server.js` 充当**分析服务端**（工作区登记→产出收集→聚焦分析→汇总上报），只输出可提交链。

**三步法：**
1. **域清单解析**（可选，或直接用域）
```
Workflow({scriptPath: ".../domain_server.js", args: {company: "抖音", resolveOnly: true}})   # → {domains:[...]}
```
2. **并行派发 Client**（编排器→每个域名一个独立顶层 workflow，≤10 并行，各自独立工作区 `{业务线}/works/{域名}/`，避免共享文件冲突与上下文溃散）
```
Workflow({scriptPath: ".../workflow_runner.js", args: {mode: "domain", company: "抖音", domain: "www.douyin.com", work_dir: ".../works/www.douyin.com/"}})
```
3. **收集 + 聚焦分析**（分析服务端）
```
Workflow({scriptPath: ".../domain_server.js", args: {company: "抖音", domains: ["www.douyin.com", "xxx.jinritemai.com"]}})
# 或按工作区: args: {company: "抖音", work_dirs: [".../works/www.douyin.com/"]}
```

---

## 阶段2：深度分析

## 阶段2：深度分析

**JS源码本地审计**（下载到本地→再审计，靠近F12完整度）：
1. **下载JS到本地**：`curl -s` 获取HTML → 提取 `<script src>` → `curl -s -o` 逐个下载到 `js_dumps/<target>/`
2. **Source Map 还原源码**：下载 `.js.map` → `python3` 解析 `sourcesContent` 字段 → 写出原始源码 → 对未混淆的源码做API/路由/鉴权审计
3. **敏感信息提取**：`grep -ohP` 提取 AccessKey/SecretKey/JWT/数据库连接串/内网IP/硬编码凭证
4. **路径模式提取**：`grep -ohP` 提取所有 `"/xxx/yyy"` 路径，按一级目录分组统计
5. **Webpack chunk 枚举**：提取 `chunk-`、`assets/`、`_nuxt/` 等引用 → 补下载lazy JS
6. **登录态补下载**：找到登录API后尝试获取Cookie → 下载需要认证的页面JS
7. **参数加密/签名/编码逆向（关键能力）**：请求参数是加密/编码后的不透明值（data=hex/base64 长串）时，必须逆向出加密流程才能构造正确请求体：定位加密函数（CryptoJS/AES/RSA/`.encrypt(`）→ 追踪 key/IV 来源（函数调用/模块导入/构建配置对象 `VITE_APP_*`/字符串变换 shift-char·atob·base64）→ Python(pycryptodome)/openssl 复现算法 → 发请求验证（返回业务错误而非"解密失败"即成功）。前端加密密钥必然可从前端恢复，"加密=安全"是假象。

**鉴权方式识别**：先找鉴权再测试（Authorization: Bearer/Basic/X-TOKEN/Cookie/localStorage）

**组件审计**：指纹识别 → 源码获取(GitHub/官方) → 本地审计(路由表/硬编码凭证/鉴权白名单) → 回测目标

**【开源系统识别】**（字节业务常见技术栈：自研Go/Rust高并发网关 + Vue/React前端 + 大量开源组件）：
1. **指纹采集**：响应头、Cookie特征名、页面版权声明、静态资源路径特征
2. **快速开发框架识别**：JeecgBoot / RuoYi / JeeSite / Guns / BladeX / Spring Boot Actuator / 低代码平台等
3. **自主识别（不依赖预定义）**：路径结构（/vendor/ /node_modules/ /plugins/ /install/）、响应特征（错误页泄露文件路径）、资源特征（favicon哈希/CSS类/JS全局变量）、Cookie模式（XSRF-TOKEN/laravel_session）、管理层前缀等
4. **分析结论**：汇总线索 → `高度疑似开源系统 / 部分疑似 / 大概率自研 / 无法判断`；「疑似开源」本身值得深入

**dir_enum — 基于系统特征的智能路径枚举：**
- 从JS的API前缀 + 框架识别路径 → 自动组合泛化fuzz（使用 `api_patterns.json`）
- 对每个组合执行 curl 探测（200/401/403 即发现）
- **注意 ByteSRC 红线：使用轻量 curl 探测而非 dirsearch 全量爆破，避免大流量**

**API模式字典积累：**
- 每次运行后自动追加新发现的API前缀/路径段/端点到 `api_patterns.json`（跨SRC积累，越用越准）

详细命令 → `references/phase-cmd-reference.md#阶段2-js逆向命令`

---

## 阶段3：漏洞挖掘

以**反思为主、迁跃为辅、分析为底、扩展为路**的原则执行。详细方法论（含思维模型、第一性原理、扩散链示例） → `references/deep-mining-methodology.md`

| 类型 | 测试要点 |
|------|---------|
| **业务原语判定** | 先判定端点**核心业务原语** business_attr（read_file/write_file/exec_code/modify_state/query_data/transfer/auth），再按原语选攻击基元，不看API名字 |
| 未授权/信息泄露 | 批量不带Cookie重放，对比响应差异（手工少量） |
| API文档/配置泄露 | swagger-ui / actuator / .env / .git |
| 越权(IDOR) | 替换user_id/order_id/company_id；**读取证明≤5组**，严禁批量 |
| RCE | 反序列化/文件上传/表达式注入/已知CVE |
| SSRF | URL参数 → 内网地址 + 云元数据；**回显即止，禁止深入内网** |
| 逻辑漏洞 | 金额修改/优惠券叠加/流程绕过/支付绕过（抖音支付/月付/放心借等财经业务重点） |
| 弱口令 | 通用字典 + JS发现的默认凭证（仅少量尝试） |
| **本地部署实现** | 对已识别的开源框架下载对应版本源码 → Docker/本地搭建复现 → 验证默认口令/触发条件/绕过 → 将本地POC适配迁移到目标验证差异 |
| **源码审计** | ①**权限审计** — 过滤链 `/anon` 端点遗漏、`@RequiresPermissions`/`@PreAuthorize` 注解缺失、无Token可调用接口、Swagger暴露接口逐一测试鉴权 ②**控制审计** — 上传后缀绕过/下载路径穿越/命令执行函数可控/SQL参数拼接（尤其orderBy）/反序列化/MIME/模板注入/XXE。③**零凭据获取Token路径** — 无认证仅IP白名单/仅Referer/时间戳签名；硬编码 adminKey/secret 派生Token；密码重置验证码/OAuth回调逻辑缺陷 |

**ByteSRC 高价值方向（高系数资产优先）：**
- 抖音：账号接管、无交互获取用户手机号/身份证、内容/订单越权
- 抖音电商：订单金额篡改、**零元购**、商家后台越权、ISV开放平台API
- 飞书：文档/通讯录越权、0-click RCE、租户隔离绕过
- 财经：支付金额篡改、支付绕过、提现漏洞
- 豆包：账号接管、模型/对话数据越权
- 火山引擎：租户隔离绕过、管控系统权限、云资源越权

**AK/SK/密钥泄露发现后：直接记录待提交，不深入验证。**

批量测试脚本、弱口令字典、框架定制路径 → `references/phase-cmd-reference.md#阶段3-漏洞挖掘命令`

---

## 阶段4：验证与证据

**不允许虚构漏洞或伪造证明。** 详细判定规则 → `references/judgment-rules.md`

- [必需] 完整HTTP请求包 + 响应包 + 200 OK + curl可复现命令
- [必需] 漏洞当前仍可访问且返回200（curl重放确认）
- [推荐] 敏感数据脱敏；**越权读取仅展示≤5组真实数据**
- 每个发现做确认性检测，true_positive / false_positive 分类

**有效性判定速查（ByteSRC）：**
- **F(不符)**: 不在收录/无复现/漏洞不成立/忽略清单内
- **R(保留)**: 非敏感泄露/利用门槛高/暴露未深入/利用价值低
- **T(属实)**: 完整攻击链/高敏感数据未授权获取/任意账号操作
- **401/403 ≠ 未授权漏洞**

**严格 curl 验证（Phase 4）：**
1. 提取可测试 URL（JS 类发现从描述拼装路径）
2. `curl -sI` 获取 HTTP 状态码
3. 状态码 200/401/403 的，`curl -s` 获取响应体
4. 记录 `http_status` + `curl_command` + `evidence`

| 判定 | 条件 |
|------|------|
| confirmed | curl 200 + 响应体含**实际敏感数据**（非权限错误）|
| suspected | 200 但返回 `"没有接口访问权限"` / `"Unauthorized"` / `"需要登录"` |
| needs_manual_test | 无法构造可测试 URL |
| false_positive | 404/超时/返回无敏感数据 |

---

## 阶段5：资产标记与状态存储

**目的：** 标记每项资产的测试状态并持久化，避免重复测试。

**三种标记状态（必填 reason）：**
- **「已完全测试完毕」** — 所有适用维度完成 + 无漏洞或已出报告
- **「还未测试完毕」** — 部分维度未完成，或存在更深挖掘价值
- **「无法进行测试」** — 端口关闭/无法连接/非Web/非字节业务范围

### 线索/漏洞存储

Phase 5 同时将发现写回 `asset_findings.json`（title/type/severity/target/endpoint/status/phase_discovered/curl_command）

### 测试维度矩阵

| 维度 | 编码 | 判定条件 |
|------|------|---------|
| HTTP探活 | `http_probe` | curl 返回 HTTP 响应 |
| 未授权测试 | `unauth_test` | 无 Cookie/Token 探测至少 5 个API路径 |
| 智能路径枚举 | `dir_enum` | 基于框架特征+JS路径泛化fuzz |
| 组件审计 | `component_audit` | 指纹识别 + 源码审计 |
| JS/API分析 | `js_analysis` | JS 下载到本地后审计（含Source Map还原） |
| 逻辑测试 | `logic_test` | 支付/流程/越权逻辑验证 |

### 存储位置

- **资产状态：** `/home/my/SRC/BSRC/{业务线}/asset_test_status.json`
- **线索存档：** `/home/my/SRC/BSRC/{业务线}/asset_findings.json`
- **API模式字典：** `references/api_patterns.json`（跨SRC积累）

### 工作流行为

1. **启动时**读取 `asset_test_status.json`，已标记「已完全测试」或「无法进行测试」自动跳过
2. **Phase 1-4** 执行，`dimTracker` 实时记录已完成维度
3. **Phase 5** 根据记录自动判定 + agent 校准，统一写入文件（只更新本次资产，保留旧记录）

---

## 阶段6：报告编写

**文件命名：** `{等级}_{漏洞类型}_{业务线简称}_{简述}.md`（例：`高危_信息泄露_飞书_未授权接口.md`）

**编写顺序：** 重大 → 严重 → 高危 → 中危 → 低危（低危仅在更高级完成后才考虑）

**默认过滤规则：**
- **低危漏洞默认不生成报告**（除非用户明确要求包含低危）
- **CORS同源配置缺陷默认不生成报告**（除非用户明确要求）

**结构要求：** 漏洞信息表 → 漏洞描述 → 复现步骤（HTTP请求/响应 + curl）→ 影响 → 修复建议 → 验证记录
（ByteSRC 要求：漏洞标题[题目+影响域名+类型]、漏洞描述[入口+URL+参数+版本]、复现过程[步骤+影响+工具名]、修复方案）

**组合利用链：** 多漏洞串联用攻击链路图，最终等级取链路最高 + 可达性综合

详细模板 → `references/report-templates.md`

**双格式输出：** 写`.md` → `python3 scripts/generate_html.py` → 生成`.html`到 `reports_html/`

---

## 阶段7：自审

1. **读取判定规则**：`references/judgment-rules.md`
2. **读取ByteSRC规则**：`/home/my/SRC/BSRC/markdown/ByteSRC安全报告处置规则V6.0.md`
3. **逐报告判定**：
   - 格式合规（命名/包/curl/脱敏）
   - 等级准确性（六级体系，自评虚高会扣分）
   - 业务系数档位（高/中/低系数判定准确？SSRF统一高系数？）
   - 收录范围（字节中国区业务？非第三方/ISV/外部客户？）
   - **最终判定：T(可提交) / R(保留) / F(不符)**
4. **重复检测**：同业务间端点重叠匹配程度（同API前缀同类→合并；不同前缀同类→非同一修复方案则独立）
5. **无效处理**：F判定 → 移入 `_invalid/` → `python3 scripts/consolidate_findings.py`

---

## 阶段8：提交准备

**最终检查清单：**
- [ ] 文件名 `{等级}_{类型}_{业务线}_{简述}.md` 规范
- [ ] 完整HTTP请求/响应 + 200 OK + curl可复现
- [ ] 漏洞URL当前仍可访问（复测通过）
- [ ] 在收录范围内 + 业务系数正确 + 不在忽略清单
- [ ] 等级与危害匹配 + 数据已脱敏（越权证据≤5组）
- [ ] HTML版本已生成

**提交顺序：** 重大→严重→高危→中危→低危。同类合并。每个报告独立提交，证据链完整。

---

## 关键路径速查

| 用途 | 路径 |
|------|------|
| ByteSRC 数据根 | `/home/my/SRC/BSRC/` |
| ByteSRC 规则文档 | `/home/my/SRC/BSRC/markdown/ByteSRC安全报告处置规则V6.0.md` |
| 业务线报告目录 | `{业务线}/submittable_reports/` |
| HTML报告 | `{业务线}/submittable_reports/reports_html/` |
| 无效报告归档 | `{业务线}/submittable_reports/_invalid/` |
| Hunter资产数据 | `{业务线}/assets_info/` |
| 阶段命令参考 | `references/phase-cmd-reference.md` |
| 报告模板 | `references/report-templates.md` |
| 判定规则 | `references/judgment-rules.md` |
| 等级/系数矩阵 | `references/vulntype-matrix.md` |
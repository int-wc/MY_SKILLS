---
name: tsrc-mining
description: >
  TSRC (Tencent Security Response Center) 腾讯安全应急响应中心专属漏洞挖掘技能。当用户请求涉及以下任一场景时激活：

  **核心场景：**
  1. TSRC漏洞挖掘：挖掘腾讯产品漏洞、渗透测试、安全研究
  2. 资产分析：解析腾讯资产清单、攻击面识别、子域名发现
  3. 报告编写：生成TSRC漏洞报告、格式转换(.md/.html)、按模板写报告
  4. JS逆向/API发现：分析JavaScript文件、寻找隐藏API端点、前后端源码审计
  5. 组件/系统审计：审计开源组件源码、识别开源系统/框架、CVE匹配
  6. 漏洞复现与验证：验证漏洞是否有效、复测端点、确认漏洞存在性
  7. 报告自审/质量检查：检查报告格式合规性、判断是否符合TSRC提交标准
  8. 深度利用/利用链：分析多漏洞组合、权限提升链、长利用链构建
  9. 目标选择/范围确认：推荐挖掘目标、查看TSRC产品范围/评分标准
  10. 漏洞等级判定：分类严重/高危/中危/低危/无、对照TSRC V4.2标准

  **触发关键词：**
  TSRC、腾讯、tencent、腾讯安全、漏洞挖掘、渗透测试、微信、QQ、企业微信、
  腾讯云、王者荣耀、腾讯视频、腾讯会议、吐司、toast、TDream、Craft、
  元宝、混元、安全币、腾讯SRC、security.tencent.com、挖洞、资产分析、JS逆向、
  API发现、报告生成、漏洞验证、复测、自审、利用链、深度挖掘、思维链、V4.2
---

# TSRC 腾讯安全应急响应中心专属漏洞挖掘技能

**注意：挖掘过程严格遵守 TSRC 安全测试规范，不能实行删除、修改、覆盖操作，仅可说明有此功能存在。**

## 技能结构

```
TSRC_SKILLS_V1/
├── SKILL.md                    ← 本文件：核心流程指令（≤500行）
├── scripts/                    ← 自动化脚本
│   ├── toast_capture.py       # mitmproxy 吐司App流量抓取
│   ├── toast_idor_test.py     # mitmproxy 吐司越权测试脚本
│   ├── download_js.py         # JS下载到本地
│   ├── enumerate_chunks.py    # Webpack chunk枚举补下载
│   ├── extract_creds.py       # 从JS提取鉴权凭证
│   ├── find_js_dumps.py       # 查找JS缓存/还原目录
│   ├── smart_fuzz.py          # 基于系统特征的智能路径枚举
│   ├── merge_assets.py        # 程序化合并asset文件
│   ├── update_dict.py         # 更新API模式字典(LRU裁剪)
│   ├── generate_html.py       # MD→HTML 批量转换
│   ├── audit_reports.py       # 报告质量审计
│   ├── consolidate_findings.py# 报告整合/无效归档
│   ├── fetch_hunter.py        # Hunter API 资产采集
│   ├── probe.sh               # 路径探测脚本
│   ├── probe2.sh              # 批量API路径探测
│   └── probe_actuator.sh      # Actuator端点探测
├── references/                ← 详细参考文档
│   ├── judgment-rules.md      # TSRC F/R/T 三级判定规则 ⬅ 必读
│   ├── vulntype-matrix.md     # TSRC 漏洞类型/等级判定速查
│   ├── deep-mining-methodology.md # 深度挖掘方法论
│   ├── phase-cmd-reference.md # 各阶段bash命令/字典
│   └── report-templates.md    # 报告模板(标准+利用链)
└── assets/
    ├── report-template.html   # 报告HTML样式模板
    └── 报告导航.html          # 报告导航面板
```

## 项目目录结构（TSRC 工作区）

```
/home/my/SRC/TSRC/              ← TSRC 项目根目录
├── 资产收集/
│   ├── 腾讯资产清单.md         ← 资产清单（域名/IP/App/新产品）
│   └── mht_fofa.csv            ← FOFA/Hunter 导出的原始资产数据
├── 漏洞处理和评分标准/
│   ├── markdown/TSRC漏洞处理和评分标准.md  ← V4.2完整评分标准
│   └── html/TSRC漏洞处理和评分标准.html
├── 安全测试规范/
│   ├── markdown/TSRC安全测试规范.md        ← TSRC测试行为规范
│   ├── markdown/SRC行业安全测试规范.md
│   └── html/TSRC安全测试规范.html
└── scripts/
    ├── README.md               ← 抓包说明
    ├── toast_capture.py        ← 吐司App流量抓取
    ├── toast_idor_test.py      ← 吐司越权测试
    └── captured/               ← 捕获的HTTP流量JSON
```

## 启动检查

```bash
for tool in curl jq httpx dirsearch python3 awk sed grep mitmproxy; do
  command -v $tool &>/dev/null && echo "[✓] $tool" || echo "[✗] $tool 缺失"
done
python3 -c "import requests, bs4, lxml" 2>/dev/null || echo "pip install requests bs4 lxml"
pip install mitmproxy 2>/dev/null || echo "mitmproxy 可选用于流量抓取"
```

**缺工具策略：** 缺 dirsearch → ffuf/手动curl；缺 httpx → `curl -sI`

---

## 八阶段工作流

```
阶段1: 资产发现与目标识别  →  目标清单 + 范围确认
阶段2: 深度分析              →  隐藏端点 + 开源系统识别 + 攻击面清单
阶段3: 漏洞挖掘              →  原始发现列表 + 本地部署实现 + 源码审计发现
阶段4: 验证与证据            →  可复现POC/EXP
阶段5: 资产标记              →  已测资产状态存储（避免重复测试）
阶段6: 报告编写              →  .md + .html 双格式报告
阶段7: 自审                  →  判定结果(可提交/保留/不符)
阶段8: 提交准备              →  最终可提交报告包
```

---

## 阶段1：资产发现与目标识别

1. **读取腾讯资产清单**：`/home/my/SRC/TSRC/资产收集/腾讯资产清单.md`
2. **读取TSRC评分标准V4.2**：`/home/my/SRC/TSRC/漏洞处理和评分标准/markdown/TSRC漏洞处理和评分标准.md`
3. **读取TSRC安全测试规范**：`/home/my/SRC/TSRC/安全测试规范/markdown/TSRC安全测试规范.md`
4. **解析FOFA/Hunter资产**：`/home/my/SRC/TSRC/资产收集/mht_fofa.csv`
5. **URL聚合去重**：同域名不同端口→保留HTTP+HTTPS各一；同IP不同域名→独立保留
6. **目标优先级**：核心产品 > 重点产品 > 其他产品；RCE > 大量敏感数据 > 文件读写 > SSRF > 越权 > 信息泄露 > XSS > 弱口令

**TSRC 核心产品（最高奖励）：**
- 微信、QQ、企业微信、QQ邮箱、企业邮箱
- 腾讯视频、腾讯会议、腾讯文档、腾讯云
- 王者荣耀、和平精英、电脑管家、手机管家
- 腾讯元宝、腾讯元器、微信支付/财付通
- → 严重漏洞最高 2574 安全币 + 税后 1~6 万现金奖励

**TSRC 重点产品：**
- 腾讯新闻、腾讯地图、视频号/直播/搜一搜/看一看、腾讯微汇款
- → 严重漏洞最高 1728 安全币 + 税后 1~3 万现金奖励

**2025-2026 新产品热点（建议重点关注）：**
- 吐司(Toast) — AI应用生成平台，2026.05上线
- TDream — AI视频创作，2026.06上线
- TenPayGo — 独立支付App（内测阶段）
- 微信小薇 — AI助手（即将公测）
- 元宝派 — AI社交
- 造化工坊/Craft — AI游戏创作平台

详细命令 → `references/phase-cmd-reference.md#阶段1-资产发现命令`

---

## 阶段2：深度分析

**JS源码本地审计**：
1. **下载JS到本地**：`curl -s` 获取HTML → 提取 `<script src>` → `curl -s -o` 逐个下载到 `js_dumps/<target>/`
2. **Source Map 还原源码**：下载 `.js.map` → `python3` 解析 `sourcesContent` 字段
3. **敏感信息提取**：使用 `grep -ohP` 提取 AccessKey/SecretKey/JWT/内网IP/硬编码凭证
4. **路径模式提取**：`grep -ohP` 提取所有 `"/xxx/yyy"` 路径，按一级目录分组统计
5. **Webpack chunk 枚举**：补下载 lazy JS
6. **登录态补下载**：尝试获取Cookie → 下载需要认证的页面JS

**鉴权方式识别**：先找鉴权方式再测试

**组件审计**：指纹识别 → 源码获取(GitHub/官方) → 本地审计 → 回测目标

**开源系统识别**：JeecgBoot/RuoYi/Guns/BladeX/Pear Admin 等快速开发框架识别

**dir_enum — 智能路径枚举**：JS分析提取的API前缀 + 框架识别路径 → 自动组合fuzz

**API模式字典积累**：每次运行将新发现的API前缀/路径段/端点追加到 `api_patterns.json`

---

## 阶段3：漏洞挖掘

| 类型 | 测试要点 |
|------|---------|
| dirsearch扫描 | 合并 dirsearch 内置字典 + api_patterns.json |
| 未授权/信息泄露 | 批量不带Cookie重放，对比响应差异 |
| API文档/配置泄露 | swagger-ui / actuator / .env / .git |
| 越权(IDOR) | 替换 user_id/order_id/session_id/company_id |
| RCE | 反序列化/文件上传/表达式注入/已知CVE |
| SSRF | URL参数 → 内网地址 + 云元数据 |
| 弱口令 | 通用字典 + JS发现的默认凭证 |
| 逻辑漏洞 | 金额修改/优惠券叠加/流程绕过 |

**TSRC 重点关注漏洞类型：**
- **核心产品RCE/代码执行**：严重，最高2574安全币+6万现金奖
- **大模型产品**（元宝/混元/微信AI）：仅收录信息安全漏洞，内容安全/Prompt注入等不收
- **SSRF**：全回显→高(7分)；无回显→中(3分)；使用指定 `http://tst.woa.com/flag.html`
- **AK/SK泄露**：严禁自行深入验证，仅验证凭据有效性
- **微信小程序密钥泄露**：不超过[中]
- **邮箱类漏洞**：同模版XSS仅首个计分

**本地部署实现**：已识别快速开发框架 → 下载源码 → Docker搭建复现环境

**源码审计三大维度**：权限审计 → 控制审计 → 零凭据Admin Token路径

---

## 阶段4：验证与证据

**不允许虚构漏洞或伪造证明。** 详细判定规则 → `references/judgment-rules.md`

- [必需] 完整HTTP请求包 + 响应包 + 200 OK + curl可复现命令
- [必需] 漏洞当前仍可访问且返回200（curl重放确认）
- [推荐] 敏感数据脱敏

**TSRC SSRF 测试规范：**
- 全回显SSRF使用：`http://tst.woa.com/flag.html` 或 `http://9.138.237.216/flag.html`
- 不得对内网服务进行扫描
- SSRF不区分业务性质，一律按重点业务计分

**有效性判定速查：**
- **F(不符)**: 资产不符/无复现/漏洞不成立/明确不收
- **R(保留)**: 非敏感泄露/利用门槛高/暴露未深入/利用价值低
- **T(属实)**: 完整攻击链/高敏感数据未授权获取

**严格 curl 验证：** 记录 `http_status` + `curl_command` + `evidence`

| 判定 | 条件 |
|------|------|
| confirmed | curl 200 + 响应体含**实际敏感数据** |
| suspected | 200 但返回权限错误信息 |
| needs_manual_test | 无法构造可测试URL |
| false_positive | 404/超时/返回无敏感数据 |

---

## 阶段5：资产标记与状态存储

**三种标记状态（必填 reason 字段）：**
- **「已完全测试完毕」** — 所有维度完成 + 无发现或已出报告
- **「还未测试完毕」** — 部分维度未完成
- **「无法进行测试」** — 端口关闭/无法连接/非腾讯范围

**测试维度矩阵：** `http_probe` / `unauth_test` / `dir_enum` / `dirsearch_scan` / `weak_pass` / `js_analysis`

**存储位置：**
- 资产状态：`/home/my/SRC/TSRC/asset_test_status.json`
- 线索存档：`/home/my/SRC/TSRC/asset_findings.json`
- API模式字典：`references/api_patterns.json`

---

## 阶段6：报告编写

**文件命名：** `{等级}_{漏洞类型}_TSRC_{简述}.md`

**编写顺序：** 严重 → 高危 → 中危 → 低危（低危默认不生成）

**默认过滤规则：**
- 低危漏洞默认不生成报告
- CORS同源配置缺陷默认不生成报告

**TSRC 高质量报告标准（额外奖励50-5000元）：**
- 规范清晰，含步骤、数据包、漏洞相关接口
- 积极配合审核复现，主动提供测试账号
- 思路新颖、手法独特
- 标题格式：`xxx平台xxx域名的xxx漏洞`

**报告输出路径：** `/home/my/SRC/TSRC/报告/` → `.md` → `python3 scripts/generate_html.py` → `.html`

---

## 阶段7：自审

1. **读取判定规则**：`references/judgment-rules.md`
2. **对照TSRC V4.2标准**：`/home/my/SRC/TSRC/漏洞处理和评分标准/markdown/TSRC漏洞处理和评分标准.md`
3. **逐报告判定**：格式合规 → 等级准确性 → TSRC接受度 → **T(可提交)/R(保留)/F(不符)**

**TSRC 重要不收录规则：**
- 内部已知漏洞（2个发版周期内）
- 存量影响用户量<10%（高/严重）/ <50%（中/低危）
- 隐私合规、大模型内容安全、沙箱代码执行（除非逃逸）
- 同一条威胁情报仅首个报告者计分

4. **重复检测**：同产品间检查端点重叠
5. **无效处理**：F判定 → 移入 `_invalid/` → 运行 consolidate_findings.py

---

## 阶段8：提交准备

**最终检查清单：**
- [ ] 文件名 `{等级}_{类型}_TSRC_{简述}.md` 规范
- [ ] 完整HTTP请求/响应包 + 200 OK + curl可复现
- [ ] 漏洞URL当前仍可访问（复测通过）
- [ ] 类型在TSRC接受范围内 + 不在忽略清单
- [ ] 等级与危害匹配（对照V4.2标准）
- [ ] 敏感数据已脱敏（单人≤10组）
- [ ] HTML版本已生成

**TSRC 提交平台：** https://security.tencent.com/

**提交顺序：** 严重→高危→中危→低危。同类合并。
**禁止：** 未经授权以任何形式传播漏洞细节。

---

## 关键路径速查

| 用途 | 路径 |
|------|------|
| TSRC资产清单 | `/home/my/SRC/TSRC/资产收集/腾讯资产清单.md` |
| TSRC评分标准V4.2 | `/home/my/SRC/TSRC/漏洞处理和评分标准/markdown/TSRC漏洞处理和评分标准.md` |
| TSRC安全测试规范 | `/home/my/SRC/TSRC/安全测试规范/markdown/TSRC安全测试规范.md` |
| SRC行业安全测试规范 | `/home/my/SRC/TSRC/安全测试规范/markdown/SRC行业安全测试规范.md` |
| FOFA/Hunter资产数据 | `/home/my/SRC/TSRC/资产收集/mht_fofa.csv` |
| 报告输出 | `/home/my/SRC/TSRC/报告/` |
| 吐司抓包脚本 | `/home/my/SRC/TSRC/scripts/toast_capture.py` |
| 吐司越权测试 | `/home/my/SRC/TSRC/scripts/toast_idor_test.py` |
| 抓包数据 | `/home/my/SRC/TSRC/scripts/captured/` |
| 判定规则 | `references/judgment-rules.md` |
| TSRC VulnType | `references/vulntype-matrix.md` |
| 报告模板 | `references/report-templates.md` |
| 命令参考 | `references/phase-cmd-reference.md` |
| 深度挖掘方法论 | `references/deep-mining-methodology.md` |
| TSRC提交平台 | https://security.tencent.com/ |
| SSRF测试域名 | http://tst.woa.com/flag.html |
| SSRF测试IP | http://9.138.237.216/flag.html |

---
name: edusrc-mining
description: >
  教育漏洞报告平台(EDUSRC)专属漏洞挖掘全流程技能。当用户请求涉及以下任一场景时激活：

  **核心场景：**
  1. EDUSRC漏洞挖掘：挖掘教育行业漏洞、渗透测试、教育行业众测
  2. Hunter资产分析：粘贴或指定Hunter CSV/JSON数据进行教育资产分析、攻击面识别、院校子域名发现
  3. 报告编写：生成EDUSRC漏洞报告、格式转换(.md/.html)、按模板写报告、报告规范化
  4. JS逆向/API发现：分析JavaScript文件、寻找隐藏API端点、前后端源码审计
  5. 组件/系统审计：审计教育行业开源组件、识别学校常用开源系统/框架、CVE匹配、版本指纹
  6. 漏洞复现与验证：验证漏洞是否有效、复测端点、确认漏洞存在性
  7. 报告自审/质量检查：检查报告格式合规性、判断是否符合EDUSRC提交标准、运行audit脚本
  8. 深度利用/利用链：分析多漏洞组合、权限提升链、长利用链构建
  9. 目标选择/范围确认：推荐教育行业挖掘目标、查看院校资产、确认EDUSRC收录范围
  10. 漏洞等级判定：分类严重/高危/中危/低危、对应EDUSRC评分标准

  **触发关键词：**
  EDUSRC、教育漏洞、教育行业、edu、学校、大学、学院、教务处、校园网、edu.cn、
  漏洞挖掘、渗透测试、众测、Hunter、资产分析、JS逆向、API发现、
  组件审计、报告生成、漏洞验证、复测、自审、利用链、教育SRC、挖洞、
  统一认证、IAAA、教务系统、学工系统、图书馆、科研系统、学位论文、
  梯度、Rank、金币、礼品中心、教育白帽子
---

# 教育漏洞报告平台(EDUSRC)专属漏洞挖掘技能

**注意：挖掘过程，不能实行删除、修改、覆盖操作，仅可说明有此功能存在。**

## 技能结构

```
EDUSRC_SKILLS_V1/
├── SKILL.md                    ← 本文件：核心流程指令
├── workflow_runner.js          ← 全自动8阶段workflow编排
├── scripts/                    ← 自动化脚本（复用SRC_SKILLS_V1）
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
│   └── probe_actuator.sh       # Actuator端点探测
├── references/                 ← 详细参考文档
│   ├── judgment-rules.md       # EDUSRC F/R/T 三级判定规则 ⬅ 必读
│   ├── report-templates.md     # EDUSRC报告标准模板
│   ├── deep-mining-methodology.md # 深度挖掘方法论（通用）
│   ├── hunter-reference.md     # Hunter语法与探测命令
│   ├── phase-cmd-reference.md  # 各阶段bash命令/字典/CVE表
│   └── api_patterns.json       # 跨目标API模式积累字典（自动增长）
└── assets/
    └── report-template.html    # 报告HTML样式模板
```

## 启动检查

```bash
for tool in curl jq httpx dirsearch hydra python3 awk sed grep; do
  command -v $tool &>/dev/null && echo "[✓] $tool" || echo "[✗] $tool 缺失"
done
python3 -c "import requests, bs4, lxml" 2>/dev/null || echo "pip install requests bs4 lxml"
```

**缺工具策略：** 缺 dirsearch → ffuf/手动curl；缺 httpx → `curl -sI`

---

## 八阶段工作流

```
阶段1: 资产发现与目标识别  →  教育资产清单 + 范围确认
阶段2: 深度分析              →  隐藏端点 + 开源系统识别 + 攻击面清单
阶段3: 漏洞挖掘              →  未授权测试 + 越权弱口令 + 批量探测
阶段4: 验证取证              →  手动复测 + 发散扩展 + false_positive剔除
阶段5: 资产标记              →  标记已测资产状态（避免重复测试）
阶段6: 报告编写              →  MD+HTML双格式 + 多报告并行
阶段7: 自审                  →  格式检查 + 等级复核 + F/R/T判定
阶段8: 提交准备              →  最终清单 + 排序 + 提交指引
```

---

## EDUSRC 收录范围

教育漏洞报告平台接收如下类别单位漏洞：

| 类别 | 范围 |
|------|------|
| **政府单位** | 教育部、人力资源和社会保障部、中国科学院 |
| **教育行政部门** | 各省/自治区教育厅、直辖市教委、各级教育局 |
| **人社行政部门** | 各省/自治区人社厅、直辖市人社局、各级人社局 |
| **学校/技校** | 各级教育部门及人社部门主管的学校、技校 |
| **中科院** | 中科院所属各单位（各中心、研究所等） |
| **教育软件** | 教育相关软件 |

**不受理：** 非教育行业单位、虚假漏洞、已公开漏洞、Self-XSS、无敏感CSRF、钓鱼、拒绝服务

---

## 教育行业常见攻击面

教育行业与其他行业的区别决定了挖掘策略的调整：

| 特点 | 挖掘策略 |
|------|---------|
| **高校数量多，外包开发普遍** | 同一套系统可能在多所院校部署（如：强智教务系统、青果教务系统） |
| **老旧系统多** | 大量遗留系统（Tomcat 6/7、Struts2、ASP.NET、PHP） |
| **统一认证普及** | IAAA/CAS 单点登录 → 越权、令牌伪造、Session劫持 |
| **默认弱口令普遍** | 初始密码=学号/身份证后6位/生日 → 批量撞库 |
| **管理后台暴露** | 教务处/学工处/后勤系统后台往往未授权 |
| **附件/文档多** | PDF/Word含敏感信息（公示名单、成绩单、通讯录） |
| **外包框架同质化** | 强智、正方、金智、青果等教务系统有历史漏洞 |

---

## 教育行业常见系统 & 挖掘重点

| 系统类型 | 常见框架 | 关键攻击面 |
|---------|---------|-----------|
| 教务管理系统 | 强智、正方、金智、青果 | 越权查成绩/课表/学生信息 |
| 统一认证系统 | IAAA、CAS、OAuth2 | 认证绕过、令牌伪造、Session固定 |
| 校园门户 | 自研、Liferay | 信息泄露、未授权访问 |
| 科研管理系统 | 易普拉格、自研 | 项目信息泄露、文件上传 |
| 图书馆系统 | 汇文、Interlib、自研 | 读者信息泄露、未授权API |
| 学工系统 | 自研、金智 | 学生档案泄露、弱口令 |
| 缴费/财务系统 | 自研、用友 | 支付逻辑、订单遍历 |
| 网络教学平台 | 超星、智慧树、Moodle | 用户信息泄露、越权 |
| 一卡通/后勤系统 | 新中新、自研 | 余额信息、交易记录 |
| 招生系统 | 自研 | 考生信息泄露、录取数据 |
| 实习就业平台 | 自研 | 简历泄露、企业信息 |
| 学位论文系统 | 知网、自研 | 论文全文泄露 |

---

## 深度挖掘敏捷指南

### 第一阶段：资产发现
```
1. 使用Hunter/FOFA搜索目标院校的edu.cn子域名
2. 对发现的子域名做web探活（httpx）
3. 识别统一认证入口（iaaa.*.edu.cn, cas.*.edu.cn）
4. 标记教务/学工/科研/图书馆等核心系统
```

### 第二阶段：JS逆向与API发现
```
1. 下载核心系统前端JS包
2. 提取API_BASE/URL路径、鉴权方式
3. 关注统一认证系统的OAuth2/CAS配置
4. 寻找硬编码密钥/Token
```

### 第三阶段：漏洞挖掘
```
1. 统一认证绕过测试
2. 教务系统越权查成绩/课表
3. 默认弱口令测试（初始密码规则）
4. 敏感文件泄露（PDF/公示名单）
5. 通用框架漏洞（Shiro/Spring Boot/ThinkPHP）
```

---

## CVE 速查（教育行业常见）

| CVE编号 | 影响组件 | 危害 |
|---------|---------|------|
| CVE-2023-24187 | UReport2 | 文件写入/SSRF |
| CVE-2023-24188 | UReport2 | 任意文件读取 |
| CVE-2023-24189 | UReport2 | 未授权API |
| CVE-2022-22965 | Spring Boot <2.6.6 | RCE |
| CVE-2021-44228 | Log4j ≤2.14.1 | RCE |
| CVE-2023-22602 | Apache Shiro <1.9.1 | 授权绕过 |
| CVE-2021-29441 | Nacos ≤2.0.3 | 认证绕过 |
| CVE-2018-11776 | Apache Struts2 | RCE |
| CVE-2022-22947 | Spring Cloud Gateway | SpEL注入RCE |
| CVE-2021-3129 | Laravel Ignition | RCE |

---

## 漏洞等级标准 (EDUSRC Rank 0-10)

| 等级 | Rank分值 | 判定标准 |
|------|---------|---------|
| **严重** | 9~10 | 直接获取服务器权限、重要系统SQL注入、核心机密泄露 |
| **高危** | 7~9 | 普通系统权限、严重逻辑缺陷、批量用户权限、严重权限绕过 |
| **中危** | 4~7 | 条件限制下的权限获取、文件操作、水平权限绕过 |
| **低危** | 0~4 | 非核心数据、条件严苛下的操作、需用户交互的漏洞 |

---

## 参考与资源

- 教育漏洞报告平台: https://src.edu.cn/
- 教育相关单位列表: https://docs.qq.com/sheet/DUXFYZUZXRXFtQkNw
- Hunter语法: `domain="edu.cn" && status_code="200"`
- FOFA语法: `org="China Education and Research Network Center"`

---

## 使用方式

```bash
# 完整流程（指定院校名称）
Workflow({scriptPath: "skills/EDUSRC_SKILLS_V1/workflow_runner.js", args: {company: "北京大学", mode: "full"}})


**split-horizon DNS / hosts 碰撞（目标不可达处理）:** 目标域名 curl 超时/连接失败时，**先判断 split-horizon DNS 再 hosts 碰撞**，禁止因 DNS 超时直接放弃资产。
- 本地解析出内网IP（10.x/172.16-31.x/192.168.x/100.64.x/169.254.x）→ split-horizon → 用 FOFA资产CSV / 同域其他主机名（minio.xx.com/xx-dev.xx.com）溯源公网IP → curl 加 `--resolve <host>:<port>:<公网IP>` 直连（保持Host头），验证 HTTP 200 后该域名后续所有 curl 一律带 `--resolve`
- hosts 碰撞：对资产CSV全部公网IP批量 `timeout 2 nc -zv -w 2 <ip> <port>` 探测目标端口，找到同端口开放的其他IP后用目标Host头请求验证服务指纹（S3 XML/MinIO/应用标题）
- 判定 IP 白名单门禁（TCP 可连但发数据即 RST，`write:errno=104`）→ 服务公网暴露但 IP 受限，改走平台侧可达面（API/导出/SSRF）间接验证，报告中如实标注网络边界
- zsh 注意：`--resolve` 参数必须内联写在 curl 命令里，不能放变量（未引号变量不 word-split）
- 详细命令 → `references/dns-hosts-collision.md`

# 单URL模式
Workflow({scriptPath: "skills/EDUSRC_SKILLS_V1/workflow_runner.js", args: {mode: "url", url: "https://gzl.pku.edu.cn"}})

# 直接挖洞模式（跳过资产发现和深度分析）
Workflow({scriptPath: "skills/EDUSRC_SKILLS_V1/workflow_runner.js", args: {company: "北京大学", mode: "phase3"}})

# 报告模式（仅生成报告，用已有发现数据）
Workflow({scriptPath: "skills/EDUSRC_SKILLS_V1/workflow_runner.js", args: {company: "北京大学", mode: "phase5"}})
```

**EDUSRC项目根目录:** `/home/my/edusrc/`

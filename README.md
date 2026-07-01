# 🛡️ MY_SKILLS — Claude Code 自动化渗透测试技能集

**基于 Claude Code Workflow 引擎的全自动渗透测试框架**，覆盖补天 SRC 漏洞挖掘与 360 众测项目测试两大场景。

## 📦 结构概览

```
MY_SKILLS/
├── SRC_SKILLS_V1/     # 补天专属 SRC 漏洞挖掘框架（7+阶段自动化）
│   ├── SKILL.md           # 核心流程文档（八阶段工作流指引）
│   ├── workflow_runner.js # 全自动 Workflow 编排（~2000行）
│   ├── scripts/           # 辅助脚本集
│   ├── references/        # 参考文档（判定规则/厂商速查/命令参考/报告模板/深度方法论）
│   └── assets/            # 报告 HTML 模板
│
├── ZC_SKILLS_V1/      # 360 众测项目测试框架
│   ├── SKILL.md           # 核心流程文档
│   ├── ZC_SKILL.md        # 众测专项技能文档
│   ├── workflow_runner.js # 全自动 Workflow 编排（~1700行）
│   ├── scripts/           # 辅助脚本集（共享类工具）
│   ├── references/        # 参考文档（判定规则/厂商速查/命令参考/报告模板）
│   └── vpn-split.sh       # VPN 分流辅助脚本
│
└── README.md           # 本文件
```

## 🔧 前置要求

```bash
# 基础工具链
for tool in curl jq httpx dirsearch hydra python3 awk sed grep; do
  command -v $tool &>/dev/null && echo "[✓] $tool" || echo "[✗] $tool 缺失"
done

# Python 依赖
pip3 install requests beautifulsoup4 lxml
```

- Claude Code CLI（Workflow 引擎）
- Hunter API Key（SRC 资产采集，可选）
- Python 3 + requests/bs4/lxml

## 🚀 使用方法

### SRC 模式（补天专属）

```bash
# 完整 8 阶段流程：资产发现 → 深度分析 → 漏洞挖掘 → 验证 → 报告
claude Workflow --script workflow_runner.js \
  --args '{"company":"目标公司","mode":"full"}'

# 跳过资产发现，直接从深度分析/漏洞挖掘开始（已有资产数据）
claude Workflow --script workflow_runner.js \
  --args '{"company":"目标公司","mode":"phase3"}'

# 单 URL 模式：直接对单个目标进行渗透测试
claude Workflow --script workflow_runner.js \
  --args '{"mode":"url","url":"https://target.com:8080"}'

# 仅报告编写（已有漏洞数据）
claude Workflow --script workflow_runner.js \
  --args '{"company":"目标公司","mode":"phase5"}'
```

### ZC 模式（360 众测）

```bash
# 完整流程
claude Workflow --script workflow_runner.js \
  --args '{"company":"项目名称","mode":"full"}'

# Phase 3 直接挖洞（有资产数据时）
claude Workflow --script workflow_runner.js \
  --args '{"company":"项目名称","mode":"phase3"}'
```

## 🔄 八阶段工作流

| 阶段 | SRC_SKILLS_V1 | ZC_SKILLS_V1 |
|------|---------------|--------------|
| 1️⃣ | 资产发现 — Hunter CSV 解析 + 优先级排序 | 项目资产解析 — xlsx/CSV 资产清单加载 |
| 2️⃣ | 深度分析 — JS 逆向 + API 提取 + 组件审计 | 攻击面识别 — 组件指纹 + 开源系统识别 |
| 3️⃣ | 漏洞挖掘 — 未授权/弱口令/越权/源码审计 | 漏洞挖掘 — 多维度探测 + 自定义字典 |
| 4️⃣ | 验证取证 — 严格 curl 复现 + 证据链 | 验证取证 — 流程复现 + 请求/响应录制 |
| 5️⃣ | 资产标记 — 7 维度矩阵 + 状态持久化 | 线索存档 — asset_findings.json 存储 |
| 6️⃣ | 报告编写 — MD + HTML 双格式输出 | 报告编写 — MD 报告（向官网格式对齐） |
| 7️⃣ | 自审 — F/R/T 三级判定 + VulnType 合规 | 自审 — 按项目规则 + 等级表判定 |
| 8️⃣ | 提交准备 — 最终检查 + 提交排序 | 提交准备 — 去重合并 + 最终审核 |

## ⭐ 特色功能

### 框架审计缓存
自动识别目标使用的开源框架（JeecgBoot/RuoYi/Apereo CAS/MCMS 等），缓存审计结果到 `frameworks_audited.json`，同款系统直接跳过重复审计。
```json
// 缓存示例：frameworks_audited.json
{
  "audited": {
    "JeecgBoot": {
      "last_audited": "2026-07-01",
      "findings_count": 10
    }
  }
}
```

### 业务场景分类（防误报）
所有 RCE/命令执行类发现自动做 **业务场景分类**：
- **A. 业务设计（非漏洞）** — 命令硬编码/包名白名单/接口参数约束 → 标记 `is_business_feature: true`
- **B. 确认为漏洞** — 无白名单/参数用户可控/无权限保护 → 正常定级

### 自动测试状态跟踪
`asset_test_status.json` 跟踪每个资产的 7 维度测试进度：HTTP 探活、未授权测试、目录枚举、dirsearch 全量扫描、弱口令测试、JS 分析。已完成的资产自动跳过，避免重复劳动。

## 📂 数据存储路径

```
/home/my/butiansrc/Exclusive_SRC/
├── {公司名}/
│   ├── {公司名}_Information.html   # 厂商信息（范围/赏金/规则）
│   ├── VulnType.html              # 厂商接受漏洞类型
│   ├── hunter_info/               # Hunter 资产 CSV 数据
│   ├── asset_findings.json        # 漏洞/线索存储
│   ├── asset_test_status.json     # 资产测试状态
│   ├── frameworks_audited.json    # 框架审计缓存
│   └── submittable_reports/       # 最终可提交报告
│       ├── *.md                   # Markdown 报告
│       └── reports_html/          # HTML 版报告
```

## 📜 许可

内部工具 — 仅限授权安全测试使用。

> **注意：** 所有 Workflow 操作的唯一约束为「不实行删除、修改、覆盖操作」，仅验证和报告漏洞存在。

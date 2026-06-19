# 补天 SRC 漏洞挖掘自动化框架

基于 Claude Code Workflow 的七+阶段补天专属 SRC 自动化漏洞挖掘框架。

## 快速开始

```bash
# 检查依赖
for tool in curl jq nmap masscan httpx dirsearch hydra python3 awk sed grep; do
  command -v $tool &>/dev/null && echo "[✓] $tool" || echo "[✗] $tool 缺失"
done
pip install requests bs4 lxml
```

## 使用方法

```bash
# 完整模式：资产发现 → 深度分析 → 挖洞 → 验证 → 报告 → 自审 → 提交
claude Workflow --script workflow_runner.js --args '{"company":"理想汽车","mode":"full"}'

# 跳过早的资产发现阶段，直接挖洞
claude Workflow --script workflow_runner.js --args '{"company":"理想汽车","mode":"phase3"}'

# 仅报告编写模式（已有数据）
claude Workflow --script workflow_runner.js --args '{"company":"理想汽车","mode":"phase5"}'
```

## 8 阶段工作流

| 阶段 | 说明 |
|------|------|
| 1️⃣ 资产发现 | Hunter CSV 解析 + 端口扫描 + 优先级排序 |
| 2️⃣ 深度分析 | JS 逆向 + API 端点提取 + 组件审计 |
| 3️⃣ 漏洞挖掘 | 未授权/弱口令/越权/目录探测（Tier 1 全量 + Tier 2 快速） |
| 4️⃣ 验证取证 | 严格 curl 验证，confirmed 必须有 http_status + evidence |
| 5️⃣ 资产标记 | 7 维度矩阵跟踪 + 状态存储 + 线索存档 |
| 6️⃣ 报告编写 | MD + HTML 双格式报告 |
| 7️⃣ 自审 | F/R/T 三级判定 + 厂商 VulnType 合规 |
| 8️⃣ 提交准备 | 最终检查清单 + 提交排序 |

## 目录结构

```
├── SKILL.md                    核心流程文档
├── workflow_runner.js          自动化 Workflow 编排
├── scripts/                    工具脚本
│   ├── generate_html.py        MD→HTML 报告转换
│   ├── audit_reports.py        报告质量审计
│   ├── consolidate_findings.py 报告整合
│   └── fetch_hunter.py         Hunter API 资产采集（需 API Key）
├── references/                 参考文档
│   ├── judgment-rules.md       F/R/T 三级判定规则
│   ├── vulntype-matrix.md      厂商漏洞类型速查
│   ├── deep-mining-methodology.md 深度挖掘方法论
│   ├── hunter-reference.md     Hunter 语法参考
│   ├── phase-cmd-reference.md  各阶段命令参考
│   └── report-templates.md     报告模板
└── assets/
    └── report-template.html    报告 HTML 样式
```

## 前置要求

- Claude Code CLI
- curl, jq, nmap/masscan, httpx, dirsearch
- Python 3 + requests/bs4/lxml
- Hunter API Key（用于资产采集）
- sudo 权限（用于端口扫描），密码存于 `.sudo_pass`

## 注意事项

- 该框架自动读取 `Exclusive_SRC/{公司}/` 下的 Hunter CSV 数据和厂商信息
- 资产测试状态自动存于 `asset_test_status.json`，避免重复测试
- 发现的线索/漏洞自动存于 `asset_findings.json`

# TSRC 腾讯安全应急响应中心漏洞挖掘自动化框架

基于 Claude Code Workflow 的八阶段 TSRC 自动化漏洞挖掘框架。

## 快速开始

```bash
# 检查依赖
for tool in curl jq httpx dirsearch python3 awk sed grep mitmproxy; do
  command -v $tool &>/dev/null && echo "[✓] $tool" || echo "[✗] $tool 缺失"
done
pip install requests bs4 lxml mitmproxy
```

## TSRC 项目结构

本项目工作区位于 `/home/my/SRC/TSRC/`，包含：

| 目录/文件 | 说明 |
|-----------|------|
| `资产收集/腾讯资产清单.md` | 腾讯域名/IP/App/新产品线详尽清单 |
| `资产收集/mht_fofa.csv` | FOFA/Hunter 导出的原始资产数据 |
| `漏洞处理和评分标准/` | TSRC V4.2 完整评分标准（含核心/重点/其他产品范围、等级定义、奖励体系） |
| `安全测试规范/` | TSRC安全测试规范 + SRC行业安全测试规范 |
| `scripts/toast_capture.py` | mitmproxy 脚本—抓取吐司App流量 |
| `scripts/toast_idor_test.py` | mitmproxy 内联篡改脚本—验证 session_id 越权 |
| `scripts/captured/` | 抓包得到的 HTTP 请求响应 JSON |

## 使用方法

```bash
# 完整模式：资产发现 → 深度分析 → 挖洞 → 验证 → 报告 → 自审 → 提交
claude Workflow --script workflow_runner.js --args '{"mode":"full"}'

# 跳过早的资产发现阶段，直接挖洞
claude Workflow --script workflow_runner.js --args '{"mode":"phase3"}'

# 仅报告编写模式（已有数据）
claude Workflow --script workflow_runner.js --args '{"mode":"phase5"}'


# 吐司 App 抓包（手动）
mitmweb -s /home/my/SRC/TSRC/scripts/toast_capture.py --listen-port 8080
mitmweb -s /home/my/SRC/TSRC/scripts/toast_capture.py -s /home/my/SRC/TSRC/scripts/toast_idor_test.py --listen-port 8080 --web-port 8081
```

## 8 阶段工作流

| 阶段 | 说明 |
|------|------|
| 1️⃣ 资产发现 | 腾讯资产清单解析 + FOFA/Hunter数据 + 优先级排序 |
| 2️⃣ 深度分析 | JS 逆向 + API 端点提取 + 组件审计 + 开源系统识别 |
| 3️⃣ 漏洞挖掘 | 未授权/弱口令/越权/目录探测（Tier 1 全量 + Tier 2 快速） |
| 4️⃣ 验证取证 | 严格 curl 验证，confirmed 必须有 http_status + evidence |
| 5️⃣ 资产标记 | 维度矩阵跟踪 + 状态存储 + 线索存档 |
| 6️⃣ 报告编写 | MD + HTML 双格式报告，对照TSRC高质量标准 |
| 7️⃣ 自审 | F/R/T 三级判定 + 对照 TSRC V4.2 标准 + VulnType 合规 |
| 8️⃣ 提交准备 | 最终检查清单 + 提交至 security.tencent.com |

## TSRC 奖励速查

| 等级 | 核心产品 (1安全币=5元) | 重点产品 | 其他产品 |
|------|-------------------|---------|---------|
| 严重 | 12870~14300元 + 税后1~6万现金奖 | 8640~9600元 + 税后1~3万现金奖 | 810~900元 |
| 高危 | 4020~5360元 | 2700~3600元 | 330~440元 |
| 中危 | 525~875元 | 270~450元 | 75~125元 |
| 低危 | 110~220元 | 60~120元 | 20~40元 |

## 目录结构

```
├── SKILL.md                   核心流程文档
├── README.md                  本文件
├── scripts/                   工具脚本
│   ├── download_js.py         JS下载到本地
│   ├── enumerate_chunks.py    Webpack chunk枚举补下载
│   ├── extract_creds.py       从JS提取鉴权凭证
│   ├── find_js_dumps.py       查找JS缓存/还原目录
│   ├── smart_fuzz.py          基于系统特征的智能路径枚举
│   ├── merge_assets.py        程序化合并asset文件
│   ├── update_dict.py         更新API模式字典(LRU裁剪)
│   ├── generate_html.py       MD→HTML 批量转换
│   ├── audit_reports.py       报告质量审计
│   ├── consolidate_findings.py 报告整合/无效归档
│   ├── fetch_hunter.py        Hunter API 资产采集
│   ├── probe.sh               路径探测脚本
│   ├── probe2.sh              批量API路径探测
│   └── probe_actuator.sh      Actuator端点探测
├── references/                参考文档
│   ├── judgment-rules.md      TSRC F/R/T 三级判定规则
│   ├── vulntype-matrix.md     TSRC 漏洞类型/等级判定速查
│   ├── deep-mining-methodology.md 深度挖掘方法论
│   ├── phase-cmd-reference.md 各阶段命令参考
│   └── report-templates.md    报告模板
└── assets/
    └── report-template.html   报告 HTML 样式
```

## 前置要求

- Claude Code CLI
- curl, jq, httpx, dirsearch
- Python 3 + requests/bs4/lxml
- mitmproxy（可选，用于吐司App抓包）

## 注意事项

- 严格遵守 [TSRC安全测试规范]和[SRC行业安全测试规范]
- 禁止拖库、禁止扫描内网、禁止增删改用户数据
- 敏感数据获取不超过10组，测试后立即删除
- 未经授权严禁公开漏洞细节
- 资产测试状态自动存于 `asset_test_status.json`，避免重复测试

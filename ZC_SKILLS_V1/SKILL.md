---
name: zhongce-project-mining
description: >
  360众测(ZhongCe)项目漏洞挖掘全流程技能。当用户请求涉及以下任一场景时激活：

  **核心场景：**
  1. 众测项目漏洞挖掘：360众测项目、渗透测试、众测、挖洞
  2. 资产分析：解析项目资产列表(xlsx)、攻击面识别、目标发现
  3. 报告编写：生成漏洞报告、格式转换(.md/.docx)、按模板写报告
  4. JS逆向/API发现：分析JavaScript文件、寻找隐藏API端点
  5. 组件/系统审计：审计开源组件、识别系统框架、CVE匹配
  6. 漏洞复现与验证：验证漏洞有效性、复测确认
  7. 报告自审/质量检查：检查格式合规性、判断提交标准
  8. 深度利用/利用链：多漏洞组合、权限提升链
  9. 项目信息查看：读取VulnType/项目NOTICE/确认资产范围
  10. 漏洞等级判定：严重/高危/中危/低危

  **触发关键词：**
  众测、360众测、ZC、中远海运、项目测试、资产分析、报告编写、漏洞验证、
  VulnType、项目报告、VPN测试、NOTICE、复测、自审、利用链、漏洞复现、
  资产列表、xlsx解析、docx模板、项目规则、行为约束
---

# 360众测项目漏洞挖掘技能

**注意：** 必须全程挂 VPN 测试，危险动作前需报备。挖掘过程中不能实行删除、修改、覆盖操作，仅可说明有此功能存在。

**当前项目：** 1516期 — 中远海运
**项目目录：** `/home/my/360zc/1516_中远海运/`

## 技能结构

```
ZC_SKILLS_V1/
├── SKILL.md                    ← 本文件：核心流程指令
├── workflow_runner.js          ← 全自动8阶段workflow编排
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
│   └── probe_actuator.sh       # Actuator端点探测
├── references/                 ← 详细参考文档
│   ├── judgment-rules.md       # 判定规则（F/R/T三级）
│   ├── vulntype-matrix.md      # 厂商VulnType速查
│   ├── deep-mining-methodology.md # 深度挖掘方法论
│   ├── hunter-reference.md     # Hunter语法与探测命令
│   ├── phase-cmd-reference.md  # 各阶段Bash命令/字典
│   ├── report-templates.md     # 报告模板参考
│   └── api_patterns.json       # API模式积累字典（自动增长）
```

## 项目目录结构

```
{project_dir}/
├── VULN_TYPE.html          ← 项目漏洞类型定义（从众测平台保存）
├── VULN_TYPE_files/        ← HTML页面静态资源
├── NOTICE/                 ← 项目测试规则/公告
│   ├── NOTICE1             ← 项目公告（测试范围、行为约束）
│   └── NOTICE2             ← VPN账号信息
├── OPENVPN/                ← VPN连接配置
│   ├── {config}.ovpn       ← OpenVPN配置文件
│   ├── ca.crt              ← CA证书
│   └── OPENVPEN_USERNAME_AND_PASSWORD
├── report_template/        ← 报告模板
│   └── {year}-Q{quarter}-*.docx
└── assets/                 ← 项目资产文件
    └── *资产列表.xlsx      ← 目标资产清单
```

## 启动检查

```bash
# 0. 首次使用：配置 sudoers（一次即可，此后 VPN 自动免密启动）
echo "my ALL=(ALL) NOPASSWD: $(pwd)/OPENVPN/vpn-split.sh" | sudo tee /etc/sudoers.d/vpn-split
sudo chmod 440 /etc/sudoers.d/vpn-split

# 1. 检查必要工具
for tool in curl jq httpx dirsearch hydra python3 awk sed grep; do
  command -v $tool &>/dev/null && echo "[✓] $tool" || echo "[✗] $tool 缺失"
done
python3 -c "import requests, bs4, lxml, openpyxl" 2>/dev/null || echo "pip install requests bs4 lxml openpyxl"

# 2. VPN 检查（workflow 启动时会自动拉起，这里仅手动验证）
OPENVPN/vpn-split.sh status 2>/dev/null && echo "[✓] 隔离VPN已就绪" || echo "[✗] VPN未连接 - 请执行: sudo OPENVPN/vpn-split.sh up"

# 3. 验证隔离生效（众测走VPN + 外网直连 均可达）
ZC_CHECK=$(curl -sk --max-time 5 https://zhongce.360.net/ -o /dev/null -w '%{http_code}' 2>/dev/null)
BAIDU_CHECK=$(curl -sk --max-time 5 https://www.baidu.com -o /dev/null -w '%{http_code}' 2>/dev/null)
echo "[✓] 众测: HTTP $ZC_CHECK | 外网: HTTP $BAIDU_CHECK"
```

---

## 八阶段工作流

```
阶段1: 项目信息读取 + 资产发现  →  项目范围 + 目标清单
阶段2: 深度分析                  →  隐藏端点 + 开源系统识别 + 攻击面清单
阶段3: 漏洞挖掘                  →  原始发现列表 + 本地部署实现 + 源码审计发现
阶段4: 验证与证据                →  可复现POC/EXP
阶段5: 资产标记                  →  已测资产状态存储
阶段6: 报告编写                  →  .md + .html 双格式报告
阶段7: 自审                      →  判定结果(可提交/保留/不符)
阶段8: 提交准备                  →  最终可提交报告包
```

---

## 阶段1：项目信息读取 + 资产发现

1. **读取 VulnType**：项目目录下的 `VULN_TYPE.html`（接受的漏洞类型、忽略清单）
2. **读取 NOTICE**：项目目录下的 `NOTICE/`（测试范围、行为约束、去重规则、报告要求）
3. **解析资产列表**：读取 `assets/*资产列表.xlsx`
   - 提取所有域名、IP、URL
   - 按标签分类：`[范围内]` `[管理后台]` `[新发现]` `[非常见端口]`
4. **VPN 隔离连接（渗透与日常隔离）**：
   - **原则**：仅渗透测试探测流量走 VPN 隧道，日常上网走外网直连
   - **自动启动**：workflow 启动时自动执行 `sudo OPENVPN/vpn-split.sh up`（需提前配置 sudoers）
   - **配置 sudoers（一次即可）**：
     ```bash
     echo "my ALL=(ALL) NOPASSWD: $(pwd)/OPENVPN/vpn-split.sh" | sudo tee /etc/sudoers.d/vpn-split
     sudo chmod 440 /etc/sudoers.d/vpn-split
     ```
   - **通用脚本**：`OPENVPN/vpn-split.sh`（适配任意项目，无需硬编码）
     - `sudo ./vpn-split.sh up [项目目录]` — 启动 VPN，自动扫描项目资产文件添加路由
     - `sudo ./vpn-split.sh down` — 关闭 VPN 并清理路由
     - `./vpn-split.sh exec <cmd>` — 单条命令走 VPN 执行
     - `./vpn-split.sh shell` — 进入 VPN 隔离 shell
     - `./vpn-split.sh status` — 查看 VPN 状态（确认隔离正常）
   - **自动发现**：扫描 `assets/` 目录下所有 `xlsx/csv/txt` → 提取域名和 IP → 通过 VPN DNS 解析 → 添加路由到 `tun0`
   - **实现原理**：`route-nopull` + `pull-filter ignore redirect-gateway` → 默认路由不变 → 仅目标 IP 走 `tun0`
   - **验证隔离**：`curl -sk https://zhongce.360.net/`（走 VPN）+ `curl -sk https://www.baidu.com`（走外网）→ 两者均可达说明隔离正常
5. **目标优先级排序**：RCE > 敏感数据 > 文件读写 > SSRF > 越权 > 信息泄露 > XSS > 弱口令

**去重规则（NOTICE 规定）：**
同一漏洞源产生的多个漏洞算同一个漏洞：全局函数/配置导致的问题、同一配置影响的多个文件、同一漏洞的不同利用方式、同一函数导致的漏洞、同一功能模块下的不同接口、同一文件的不同参数、同一参数出现在不同文件、同一文件在不同目录、不同版本的同一漏洞、泛域名解析产生的多个安全漏洞。

---

## 阶段2：深度分析

**JS源码本地审计**（下载到本地→再审计，VPN 全程 `--interface tun0`）：
1. **下载JS到本地**：`curl --interface tun0 -s` 获取HTML → 提取 `<script src>` → `curl -s -o` 下载到 `js_dumps/<target>/`
2. **Source Map 还原源码**：下载 `.js.map` → `python3` 解析 `sourcesContent` → 写出原始源码到 `reconstructed/` → 审计未混淆的API/路由/鉴权
3. **敏感信息提取**：在本地JS上提取 AccessKey/SecretKey/JWT/数据库连接串/内网IP
4. **路径模式提取**：提取所有 `"/xxx/yyy"` 路径分组统计
5. **Webpack chunk 枚举**：`chunk-`/`assets/`/`_nuxt/` 引用 → 补下载lazy JS → 接近F12完整度

**鉴权方式识别**：先找鉴权方式再测试（Authorization: Bearer/Basic/X-TOKEN/Cookie）

**组件审计**：指纹识别 → 源码获取 → 本地审计 → 回测目标

**【开源系统识别】**（新增 — 聚焦快速开发框架/低代码平台）：
1. **指纹采集**：响应头、Cookie 特征名、页面底部版权声明、静态资源路径特征、登录页特有元素
2. **快速开发框架识别重点**：
   - **JeecgBoot** — `X-Powered-By: JeecgBoot`、`/jeecg-boot/` 前缀、`/sys/` 通用API、minio配置泄露
   - **JeeSite** — `JeeSite` Cookie、`/js/a/login`、默认账号 `admin/admin123`
   - **RuoYi (若依)** — `RuoYi` 版权信息、`/ruoyi/` 前缀、Shiro + Thymeleaf 组合、`/prod-api/`
   - **Guns** — Guns 特征、Beetl 模板、`/guns-api/` 前缀
   - **TeaWeb** — Go 编写、`TeaWeb` 响应头
   - **BladeX** — `/blade-` 前缀、`blade-auth` 鉴权
   - **Pear Admin / AntdV / Vue Admin** — 前端框架特征
   - **低代码平台 / iPaas** — 表单引擎、`/designer/`、代码生成器 `/code/generate`
   - **悟空CRM / 72CMS / 企业系统** — 版权特征
3. **快速框架特有攻击面分析**：
   - **默认口令库**：`admin/admin123`、`admin/admin`、`admin/123456`、`jeecg/jeecg123`
   - **代码生成器遗留接口**：`/code/generate`、`/generator/`、`/gen/` — 未授权可生成任意代码
   - **Swagger API 文档泄露**：`/swagger-ui.html`、`/doc.html`（Knife4j）、`/v2/api-docs`
   - **Deprecated 接口残留**：低代码升级遗留的旧版 API
   - **Minio/OSS 配置泄露**：`/sys/oss`、`/sys/minio` 端点暴露密钥
   - **定时任务接口**：`/job/`、`/schedule/`、`/quartz/` — 未授权可操作
   - **文件上传接口**：`/file/upload`、`/common/upload` — 是否限制文件类型
   - **Shiro 配置绕过**：过滤链配置缺陷、`/anon` 端点未收全
4. **自主识别（不依赖预定义列表）**：当不匹配已知框架时，通过以下通用线索判断**是否疑似开源系统搭建**：
   - **路径结构特征**：`/vendor/`、`/node_modules/`、`/plugins/`、`/modules/`、`/themes/`、`/uploads/`、`/install/`、`/setup/` — 这些目录来自第三方包而非自研
   - **文件特征**：`robots.txt` 暴露目录结构、`sitemap.xml` 暴露模块路径、`package.json`/`composer.json` 暴露依赖（可推断技术栈）
   - **响应特征**：错误页出现文件路径（如 `/var/www/html/vendor/` 说明是Composer项目）、调试信息泄露后端框架名
   - **资源特征**：favicon.ico 哈希比对、CSS class 命名规范（Bootstrap/ElementUI/AntD/Tailwind）、JS全局变量暴露框架对象（`window.Vue`、`window.React`、`window.angular`）
   - **Cookie 模式**：`laravel_session`、`ci_session`、`django_language`、`wordpress_`、`PHPSESSID` — 表明后端框架
   - **管理层特征**：`/admin/`、`/manager/`、`/dashboard/` 统一前缀——商业自研通常命名多样
   - **分析结论**：`高度疑似开源 / 部分疑似 / 大概率自研 / 无法判断`
   - 即使无法确定具体名称，**「疑似开源」本身就值得深入**——意味着有通用漏洞和默认配置的风险
5. **输出**：已知框架 → `{框架名} {版本} → 攻击面`；未知框架 → `疑似开源系统 → 线索清单 → 推荐方向`

**dir_enum — 基于系统特征的智能路径枚举（新增）：**
- 从JS分析的API前缀 + 框架路径 → 自动组合泛化fuzz（VPN `--interface tun0`）
- 使用 `api_patterns.json` 的 `framework_patterns`、`path_segments` 组合探测
- 输出200/401/403端点 + 提取新API模式

**API模式字典本积累（新增）：**
- 每次运行后自动将新发现的API前缀、路径段、端点追加到 `api_patterns.json`
- 跨项目积累，越用越准

## 阶段3：漏洞挖掘

以**反思为主、迁跃为辅、分析为底、扩展为路**的原则执行。

| 类型 | 测试要点 |
|------|---------|
| **dirsearch 字典扫描** | 合并 dirsearch 内置 `dicc.txt`(9482条) + 积累 `api_patterns.json`，VPN `--interface tun0` 广度爆破 |
| 未授权/信息泄露 | 批量不带Cookie重放，对比响应差异 |
| API文档/配置泄露 | swagger-ui / actuator / .env / .git |
| 越权(IDOR) | 替换user_id/order_id/company_id |
| RCE | 反序列化/文件上传/表达式注入/CVE |
| SSRF | URL参数 → 内网地址 + 云元数据 |
| 弱口令 | 通用字典 + JS发现的默认凭证 |
| 逻辑漏洞 | 金额修改/优惠券叠加/流程绕过 |
| **本地部署实现** | 对已识别的快速开发框架（JeecgBoot/RuoYi/JeeSite等）下载对应版本源码 → Docker/本地搭建复现环境 → 验证默认口令/分析漏洞触发条件/复现利用链 → POC 迁移到目标验证差异 |
| **源码审计** | **三大审计维度**：<br>① **权限审计（未授权探查）** — Shiro/Spring Security 过滤链 `/anon` 端点遗漏；控制器鉴权注解缺失；Swagger 接口逐一无 Token 测试；代码生成器/定时任务/数据字典接口鉴权是否完整<br>② **控制审计** — 文件上传后缀校验绕过；文件下载路径穿越；命令执行参数可控性；SQL 注入（尤其 orderBy）；反序列化输入可控；SSTI/XXE 注入<br>③ **零凭据获取 Admin Token 路径** — login/auth/token 控制器鉴权逻辑缺陷；无需凭证即可签发 Token 的接口；硬编码 adminKey/secret 派生 Token；密码重置/OAuth 回调逻辑绕过 |

**⚠️ 360众测特殊规则：**
- 禁止大功率扫描
- 禁止恶意刷洞
- 危险动作前需报备
- 禁止高危操作（DDOS、高频遍历、数据库增删改、服务器提权）
- 上传漏洞仅限上传普通文件证明存在
- 涉及个人敏感信息泄露需证明危害性，提供三条数据即可

---

## 阶段4：验证与证据

**不允许虚构漏洞或伪造证明。**

- [必需] 完整HTTP请求包 + 响应包 + 200 OK + curl可复现命令
- [必需] 漏洞当前仍可访问且返回200（curl重放确认）
- [必需] 时间截图（360众测要求提交时附时间截图）
- [推荐] 敏感数据脱敏
- 高危和复杂漏洞需录屏保存（避免后续扯皮）
- 数据类的需说明数量及泄漏了哪些数据

**有效性判定：**
- **F(不符)**: 资产不符/无复现/漏洞不成立/明确不收/403无权访问/空响应无业务数据
- **R(保留)**: 非敏感泄露/利用门槛高/暴露未深入/仅端点存在无实际数据
- **T(属实)**: 完整攻击链/高敏感数据未授权获取/有实际业务数据泄露

**判定红线（硬性遵守）：**
- HTTP 403 + 任何响应 ≠ 漏洞 — 403 表示服务端正常拒绝了请求
- `{"success":false}`、`{"code":-1,"msg":"xxx"}` 等纯元数据响应 ≠ 漏洞
- JS 中找到 API 端点但 curl 未返回实际数据 ≠ 未授权漏洞
- Actuator/Swagger 端点返回 403 或空数据 ≠ 可被利用的漏洞
- HTTP 200 + 权限错误（"Unauthorized"/"需要登录"）→ 认证在正常工作，非漏洞

---

## 阶段5：资产标记与状态存储

标记每个已测资产的测试状态并持久化存储，避免后续重复测试。

**三种标记状态：**
- **「已完全测试完毕」** — 所有适用维度已完成
- **「还未测试完毕」** — 部分维度未完成
- **「无法进行测试」** — 端口关闭/非Web/非范围

**程序化合并写入（新增）：** Phase 5 在 AI 标记前先执行读-合并-写：
- `asset_test_status.json`：追加新资产/更新已有（保留旧记录）
- `asset_findings.json`：按 endpoint 去重追加新发现
- 不依赖 AI 自觉性，硬性保证每次是「追加合并」而非「覆盖」

---

## 阶段6：报告编写

**文件命名：** `{等级}_{漏洞类型}_{项目简称}_{简述}.md`

**编写顺序：** 严重 → 高危 → 中危 → 低危（低危默认不生成）

**结构要求：**
- 漏洞信息表（名称、等级、类型、影响范围、发现时间）
- **需包含时间截图**（360众测特殊要求）
- 漏洞描述
- 复现步骤（HTTP请求/响应包 + curl命令）
- 影响分析
- 修复建议
- 验证记录

**报告模板路径：** `{project_dir}/report_template/{template_name}.docx`

**双格式输出：** 写`.md` → `python3 scripts/generate_html.py` → 生成`.html`到 `reports_html/`

---

## 阶段7：自审

1. 读取判定规则 + 项目 VulnType
2. 逐报告判定：
   - 格式合规（命名/请求包/curl/脱敏/时间截图）
   - 等级准确性
   - 厂商接受度（类型在范围内？非忽略清单？）
   - **最终判定：T(可提交) / R(保留) / F(不符)**
3. 重复检测（按 NOTICE 去重规则）

---

## 阶段8：提交准备

**最终检查清单：**
- [ ] 文件名规范
- [ ] 完整HTTP请求/响应包 + curl可复现
- [ ] 漏洞URL当前仍可访问（复测通过）
- [ ] 有时间截图
- [ ] 类型在VulnType接受范围内
- [ ] 等级与危害匹配 + 敏感数据已脱敏
- [ ] 非低危 / 非禁用类型（如短信轰炸、Self-XSS等）
- [ ] 已说明漏洞URL是从哪里发现的
- [ ] 弱口令类已说明用户名密码获取来源

---

## 关键路径速查

| 用途 | 路径 |
|------|------|
| 所有众测项目目录 | `/home/my/360zc/` |
| 当前项目目录 | `/home/my/360zc/1516_中远海运/` |
| 漏洞类型定义 | `{project_dir}/VULN_TYPE.html` |
| 资产列表 | `{project_dir}/assets/*资产列表.xlsx` |
| 项目规则 | `{project_dir}/NOTICE/` |
| 报告模板 | `{project_dir}/report_template/*.docx` |
| VPN配置 | `{project_dir}/OPENVPN/` |
| 阶段命令参考 | `references/phase-cmd-reference.md` |
| 报告模板参考 | `references/report-templates.md` |
| 判定规则 | `references/judgment-rules.md` |

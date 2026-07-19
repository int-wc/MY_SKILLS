---
name: tsrc-skill-created
description: TSRC_SKILLS_V1 已在 .claude/skills/ 下创建，适配腾讯安全应急响应中心
metadata:
  type: project
---

**TSRC_SKILLS_V1** 适配完成，基于 SRC_SKILLS_V1（补天专用）改造为 TSRC（腾讯安全应急响应中心）专用。

**文件清单（29个）：**
- `SKILL.md` (313行) — 核心流程指令，八阶段工作流
- `workflow_runner.js` (2354行) — 全自动8阶段Workflow编排，适配TSRC
- `README.md` — 快速入门 | TSRC奖励速查表
- `references/` (5个文件) — 判定规则、VulnType、报告模板、命令参考、方法论
- `scripts/` (16个) — 共享脚本 + 吐司抓包/越权测试脚本(symlink)
- `assets/` (2个) — 报告样式模板 + 导航面板

**适配要点：**
- 产品范围：从通用SRC厂商改为腾讯（微信/QQ/企业微信/腾讯云/王者荣耀等核心产品 + 重点产品 + 其他产品 + 2026新品）
- 评分标准：全部改为 TSRC V4.2 标准（1安全币=5元，核心产品严重最高2574币+6万现金奖）
- 资产数据：指向 `/home/my/SRC/TSRC/资产收集/腾讯资产清单.md` 和 `mht_fofa.csv`
- 域名合法性过滤：新增 `TENCENT_DOMAINS` 白名单（qq.com, tencent.com, weixin.qq.com 等）
- workflow_runner.js 改造：取消company参数，默认目标为"腾讯"，Phase 1直接读取腾讯资产清单
- 新增 TSRC 特有规则：SSRF测试域名(tst.woa.com)/IP、大模型产品收录边界、AK/SK泄露规则
- 新增 TSRC 高质量报告标准（额外50-5000元现金奖励）
- 提交平台：https://security.tencent.com/

**Why:** 用户需要从补天专属 SRC 切换到 TSRC 的漏洞挖掘场景，两个平台的资产范围、评分标准、测试规则完全不同。
**How to apply:** 当用户提及 TSRC、腾讯、吐司、微信等关键词时自动激活此技能。

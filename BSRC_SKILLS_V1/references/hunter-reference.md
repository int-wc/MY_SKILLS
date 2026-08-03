# Hunter 资产平台参考

## CSV 数据格式

Hunter 导出的 CSV 文件包含以下列（以实际导出顺序为准）：

| 列名 | 说明 | 挖掘价值 |
|------|------|---------|
| IP | 目标IP地址 | C段扩展、端口扫描 |
| 端口 | 开放端口号 | 非80/443为高价值目标 |
| 域名 | 解析域名 | 子域名发现 |
| url | 完整URL | 直接探测入口 |
| 网站标题 | HTML `<title>` 内容 | 识别后台/系统类型 |
| 高危协议 | 是否含高危协议 | 标记风险资产 |
| 协议 | HTTP/HTTPS 等 | 判断加密情况 |
| 通讯协议 | TCP/UDP | 网络层信息 |
| 网站状态码 | HTTP状态码 | 200=存活, 其他=需进一步判断 |
| 操作系统 | 服务器OS | 漏洞匹配参考 |
| 备案单位 | ICP备案主体 | 确认资产归属 |
| 备案号 | ICP备案号 | 合规验证 |
| 备案异常 | 是否备案异常 | 异常=可能防护较弱 |
| 国家/省份/市区 | GeoIP 位置 | 境外资产标记 |
| Web资产 | 是否为Web资产 | 过滤非Web |
| 运营商 | 网络运营商 | CDN识别 |
| 注册机构 | IP注册机构 | 云平台识别 |
| 应用/组件 | 组件指纹 | 版本漏洞匹配 |
| 资产标签 | Hunter标签 | 快速分类 |
| 探查时间 | 数据采集时间 | 时效性判断 |

## Hunter 查询语法

```bash
# === 基础查询 ===

# 按域名搜索（最常用）
domain="target.com"

# 按证书搜索（发现更多子域名 — 推荐优先使用）
cert="target.com"

# 按ICP备案号搜索
icp="京ICP备XXXXXXXX号"

# 按备案单位搜索
company="北京XXX科技有限公司"

# === 组合查询 ===

# 组件指纹搜索
domain="target.com" && web.component="Spring Boot"

# 非常见端口（绕过CDN/WAF — 高价值）
domain="target.com" && port!=80 && port!=443

# 特定端口
domain="target.com" && port=8080

# 状态码过滤
domain="target.com" && status_code=200

# 排除CDN节点
domain="target.com" && country=CN && is_cdn=false

# 新发现资产（按时间过滤）
domain="target.com" && after="2026-01-01"

# === 高级查询 ===

# C段扫描
ip="1.2.3.0/24"

# 按响应头特征
domain="target.com" && header.server="nginx/1.18.0"

# 按页面标题关键词
domain="target.com" && title="管理"

# 按Body内容关键词
domain="target.com" && body="swagger"
```

## 常见探测命令

```bash
# === CDN/WAF 绕过 ===

# 使用Googlebot UA（核心技巧 — 抖音/飞书/火山引擎等字节业务案例均用此绕过Cloudflare）
curl -s -H "User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" "https://target/path"

# 直接使用IP绕过CDN
curl -s -H "Host: target.com" "http://1.2.3.4/path"

# === 快速存活检测 ===

for port in 80 443 8080 8443 9000 9090 5000 7001; do
  echo -n "$port "; curl -s -o /dev/null -w "%{http_code}" "http://target:$port/" --max-time 5; echo
done

# === 响应头指纹 ===
curl -sv "https://target/" 2>&1 | grep -iE 'server:|x-powered-by:|set-cookie:|< HTTP/'

# === JS 分析 ===
# 提取所有JS文件
curl -s "https://target.com" | grep -oP 'src="[^"]+\.js[^"]*"' | cut -d'"' -f2

# 全量提取路径字符串（2级以上深度）
curl -s "https://target.com/app.js" | grep -oP '["\x27]/([a-zA-Z0-9_-]+/){1,}[a-zA-Z0-9_./-]*["\x27]' | sort -u
```

# 阶段命令参考

本文件包含从 SKILL.md 抽离的详细 bash 命令、测试脚本、字典和配置。
当需要执行具体扫描/测试操作时，从此文件获取命令。

---

## 阶段1: 资产发现命令

### TSRC 资产路径

```bash
# 腾讯资产清单（域名/IP/App/新产品）
cat "/home/my/SRC/TSRC/资产收集/腾讯资产清单.md"
```

### URL聚合去重

```bash
# 建立 IP→域名 映射表
awk -F',' 'NR>1 && $3!="" {print $1","$3}' /home/my/SRC/TSRC/资产收集/mht_fofa.csv | sort -u > ip_domain_map.csv

# 批量探活
cat full_urls.txt | httpx -status-code -title -tech-detect -o alive_results.txt
```

### 去重脚本

```bash
awk -F',' 'NR>1 {print $3}' /home/my/SRC/TSRC/资产收集/mht_fofa.csv | sort -u | while read domain; do
  echo "http://$domain:80"
  echo "https://$domain:443"
done | sort -u > deduped_targets.txt
```

### TSRC 产品分类速查

```bash
# 核心产品域名特征
CORE_DOMAINS="qq.com|weixin.qq.com|exmail.qq.com|mail.qq.com|tencent.com|wechat.com"
# 重点产品
KEY_DOMAINS="soso.com|tenpay.com"
# 目标优先级：核心 > 重点 > 其他
```

---

## 阶段2: JS逆向命令

### API入口定位

```bash
# 查找API配置变量
curl -s "https://target.com/app.js" | \
  grep -oP '(baseURL|API_HOST|API_BASE|apiUrl|serverUrl|gatewayUrl)\s*[:=]\s*["'"'"'][^"'"'"]+["'""']'
curl -s "https://target.com/app.js" | \
  grep -oP '(domain|host|gateway|proxy|origin)\s*[:=]\s*["'"'"'][^"'"'"]+["'""']'
```

### 敏感信息提取

```bash
# 腾讯云 AccessKey
curl -s target/app.js | grep -oP 'AKID[0-9A-Za-z]{16,}'
# AWS Key（腾讯云兼容）
curl -s target/app.js | grep -oP 'AKIA[0-9A-Z]{16}'
# JWT Token
curl -s target/app.js | grep -oP '(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)'
# 密钥
curl -s target/app.js | \
  grep -oP '["'"'"'](accessKey|secretKey|privateKey|apiKey|appSecret|password)["'"'"']\s*[:=]\s*["'"'"'][^"'"'"]+["'""']'
# 内网IP
curl -s target/app.js | grep -oP '(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})'
# 数据库连接
curl -s target/app.js | grep -oP '(mongodb|mysql|postgresql|redis)://[^"'"'"\s,;]+'
```

### 鉴权方式识别

```bash
curl -s "app.js" | grep -oP '["'"'"'](Authorization|X-TOKEN|X-Auth-Token|api_key|apiKey)["'"'"']\s*[:=]\s*["'"'"'][^"'"'"]+["'""']'
curl -s "app.js" | grep -oP '(localStorage|sessionStorage)\.(getItem|setItem)\s*\(\s*["'"'"'][^"'"']*token["'"'"']'
```

### 腾讯产品特有JS分析

```bash
# 吐司(Toast) App Builder API 路径提取
grep -ohP '"/access/v[0-9]+/[^"]+"' captured/*.json | sort -u
# 微信JS-SDK
grep -ohP 'https://res\.wx\.qq\.com/[^"\s,;]+' target.js
# 腾讯云API
grep -ohP 'https://[a-z]+\.tencentcloudapi\.com' target.js
```

### JS反混淆识别

```bash
# Webpack打包
curl -s target/app.js | grep -oP 'webpackJsonp|__webpack_require__'
# Jscrambler
curl -s target/app.js | grep -oP 'jscrambler|_0x[0-9a-f]{4,}'
# obfuscator.io
curl -s target/app.js | grep -oP 'window\._0x|_0x[0-9a-f]{4,}\b'
# eval加密
curl -s target/app.js | grep -oP 'eval\(function|eval\(atob'
```

### Source Map 还原

```bash
# 下载 JS Map 文件
curl -s "https://target.com/app.js.map" -o app.js.map
# 使用 enumerate_chunks.py 提取
python3 scripts/enumerate_chunks.py app.js.map reconstructed/
```

### 下载JS到本地

```bash
# 使用 download_js.py
python3 scripts/download_js.py "https://target.com" -o js_dumps/target/
```

---

## 阶段3: 漏洞挖掘命令

### TSRC SSRF 测试（重要规范）

```bash
# TSRC 指定的 SSRF 测试地址：
# 域名: http://tst.woa.com/flag.html
# IP: http://9.138.237.216/flag.html

# 示例：测试参数中的URL
curl -s "https://target.com/api?url=http://tst.woa.com/flag.html"
```

### 目录扫描

```bash
# 通用目录扫描
dirsearch -u "https://target.com" -w $(dirname $(which dirsearch))/db/dicc.txt \
  -e php,asp,aspx,jsp,html,json,xml,do,action,git,svn \
  -t 20 -x 403,404,500,502,503

# 带自定义字典（合并 api_patterns.json）
dirsearch -u "https://target.com" \
  -w /dev/stdin <<< "$(cat api_patterns.json | jq -r '.path_segments[], .common_endpoints[]' | sort -u)"
```

### 腾讯产品常见路径

```bash
# 常见腾讯产品路径特征
# 吐司 (Toast)
/api/app/generate      # APK生成（模板注入/命令执行）
/api/user/profile      # 用户信息（越权）
/api/upload            # 文件上传
/api/proxy             # 代理/SSRF

# 企业微信
/cgi-bin/
/cgi-bin/gettoken
/cgi-bin/user/

# 腾讯云API
/v2/index.php/
/console/
```

### 弱口令字典

```bash
# 腾讯产品常见默认/弱口令
TENCENT_WEAK_PASS=(
  "admin:admin"
  "admin:admin123"
  "admin:123456"
  "root:root"
  "root:toor"
  "test:test"
  "guest:guest"
  "admin:tencent"
)
```

### 未授权测试

```bash
# 批量不带Cookie测试
curl -s -I "https://target.com/api/endpoint"
curl -s "https://target.com/api/endpoint" | head -c 500

# 批量测试常见未授权端点
for path in /api/v1/user /api/user/profile /api/admin /api/config /api/health; do
  echo "=== Testing $path ==="
  curl -s -o /dev/null -w "%{http_code}" "https://target.com$path"
  echo ""
done
```

### 本地部署实现

```bash
# JeecgBoot 快速部署
git clone https://github.com/jeecg-boot/jeecg-boot.git
cd jeecg-boot
docker-compose up -d

# RuoYi 快速部署
git clone https://github.com/yangzongzhuan/RuoYi.git
cd RuoYi
mvn package && java -jar ruoyi-admin.jar

# 分析默认口令、Swagger端点、shiro过滤链
```

---

## 阶段4: 验证命令

```bash
# SSH验证
curl -sI https://target.com/api/xxx
# 响应体
curl -s "https://target.com/api/xxx?param=value" | python3 -m json.tool 2>/dev/null || \
  curl -s "https://target.com/api/xxx?param=value" | head -c 1000

# 脱敏处理
curl -s "https://target.com/api/user/100" | \
  sed 's/"phone":"[^"]*"/"phone":"138****0000"/g' | \
  sed 's/"id_card":"[^"]*"/"id_card":"110***********1234"/g' | \
  sed 's/"email":"[^"]*"/"email":"u***@example.com"/g'

# 确认漏洞仍存在（复测）
curl -sI "https://target.com/api/xxx" | grep "200 OK"
```

---

## 阶段5-8: 报告命令

```bash
# 生成 HTML 报告
python3 scripts/generate_html.py

# 报告审计
python3 scripts/audit_reports.py

# 无效归档
python3 scripts/consolidate_findings.py

# 查看已测状态
cat /home/my/SRC/TSRC/asset_test_status.json | jq '.'
```

---

## 吐司(Toast) App 抓包命令

```bash
# 启动抓包
mitmweb -s /home/my/SRC/TSRC/scripts/toast_capture.py --listen-port 8080

# 启动抓包+越权测试
mitmweb -s /home/my/SRC/TSRC/scripts/toast_capture.py \
  -s /home/my/SRC/TSRC/scripts/toast_idor_test.py \
  --listen-port 8080 --web-port 8081

# 查看抓包结果
ls -la /home/my/SRC/TSRC/scripts/captured/
cat /home/my/SRC/TSRC/scripts/captured/latest.json | jq '.url, .method, .status_code'

# 提取API端点
grep -ohP '"/access/v[0-9]+/[^"]+"' /home/my/SRC/TSRC/scripts/captured/*.json | sort -u
```

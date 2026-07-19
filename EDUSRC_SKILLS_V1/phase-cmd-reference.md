# 阶段命令参考

本文件包含从 SKILL.md 抽离的详细 bash 命令、测试脚本、字典和配置。
当需要执行具体扫描/测试操作时，从此文件获取命令。

---

## 阶段1: 资产发现命令

### URL聚合去重

```bash
# 建立 IP→域名 映射表
awk -F',' 'NR>1 && $3!="" {print $1","$3}' hunter.csv | sort -u > ip_domain_map.csv

# 批量探活
cat full_urls.txt | httpx -status-code -title -tech-detect -o alive_results.txt
```

### 去重脚本

```bash
awk -F',' 'NR>1 {print $3}' hunter.csv | sort -u | while read domain; do
  echo "http://$domain:80"
  echo "https://$domain:443"
done | sort -u > deduped_targets.txt
```

---
## 阶段2: JS逆向命令

### API入口定位

```bash
curl -s "https://target.com/app.js" | \
  grep -oP '(baseURL|API_HOST|API_BASE|apiUrl|serverUrl|gatewayUrl)\s*[:=]\s*["'"'"'][^"'"'"]+["'""']'
curl -s "https://target.com/app.js" | \
  grep -oP '(domain|host|gateway|proxy|origin)\s*[:=]\s*["'"'"'][^"'"'"]+["'""']'
```

### 敏感信息提取

```bash
# AccessKey
curl -s target/app.js | grep -oP 'AKID[0-9A-Za-z]{16,}'
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

### JS反混淆识别

```bash
# 检测混淆类型
# Webpack打包: 搜索 webpackJsonp|__webpack_require__
curl -s target/app.js | grep -oP 'webpackJsonp|__webpack_require__'
# Jscrambler: 搜索 jscrambler|_0x[0-9a-f]{4,6}
curl -s target/app.js | grep -oP 'jscrambler|_0x[0-9a-f]{4,}'
# obfuscator.io: 搜索 window\._0x|_0x[0-9a-f]{4}\b
curl -s target/app.js | grep -oP 'window\._0x|_0x[0-9a-f]{4,}\b'
# eval加密: 搜索 eval(function|eval(atob
curl -s target/app.js | grep -oP 'eval\(function|eval\(atob'

# 反混淆思路
# 1. Webpack → 在JS底部找模块定义，提取各个chunk的字符串
# 2. _0x 混淆 → 提取最前面的 _0x 数组，建立映射表还原
# 3. eval(atob(... → console.log(atob(... 解码内容
# 4. AAEncode/JSFuck → 浏览器控制台执行解混淆
```

### 编码检测与转换

```bash
# Unicode转义检测 (\u00xx)
curl -s target/app.js | grep -oP '\\u[0-9a-fA-F]{4}' | head -5
# 还原: echo -e '你好'

# Base64硬编码检测（连续base64字符, 长度>20）
curl -s target/app.js | grep -oP '[A-Za-z0-9+/]{40,}={0,2}' | head -10
# 还原: echo 'bG9naW46cGFzcw==' | base64 -d

# Hex编码检测
curl -s target/app.js | grep -oP '(0x[0-9a-fA-F]{2})+[,\)]' | head -5
# 还原: python3 -c "print(bytes.fromhex('6c6f67696e').decode())"

# 多段拼接检测: accessKey分段存储在多个变量中
# 常见模式: key_part1 + key_part2 + key_part3
curl -s target/app.js | grep -oP 'key_part|key_frag|ak_part|sk_part|secret1|secret2'
# 检测: 拼接特征的字符串碎片
curl -s target/app.js | grep -oP '["'"'"'][A-Za-z0-9+/]{10,30}["'"'"']\s*[+]\s*["'"'"']' | head -10
```

### AK/SK字段拼接模式

很多应用不会直接写 `accessKey: "AKIA..."`，而是拆成多段拼接，以下是常见拼接模式：

```bash
# 模式1: 字符串直接拼接
#   var ak = "AKIA" + "IOSFODNN7EXAMPLE";
curl -s target/app.js | grep -oP '["'"'"'][A-Z0-9+/]{4,}["'"'"']\s*[+]\s*["'"'"']' | head -20

# 模式2: 环境变量 + 固定前缀
#   accessKey = prefix + env.AWS_ACCESS_KEY_ID
curl -s target/app.js | grep -oP '(prefix|suffix|append)\s*[:=]\s*["'"'"'][A-Za-z0-9]{2,10}["'"'"']'

# 模式3: OSS密钥 (华为云/阿里云/AWS/腾讯云)
# 华为云: OBS_ACCESS_KEY_ID / OBS_SECRET_ACCESS_KEY
# 阿里云: LTAI + OSS_ACCESS_KEY_ID
# AWS: AKIA + AWS_SECRET_ACCESS_KEY  
# 腾讯云: AKID + SECRET_KEY
curl -s target/app.js | grep -oP '(OBS_|OSS_|AWS_|COS_|BOS_)(ACCESS_KEY|SECRET_KEY|SESSION_TOKEN)'
curl -s target/app.js | grep -oP '(AKID|LTAI|AKIA)[A-Za-z0-9]{10,}'

# 模式4: decode/解密后拼接
#   realKey = atob(encoded_part1 + encoded_part2)
curl -s target/app.js | grep -oP '(atob|btoa|decodeURIComponent|unescape)\s*\(' | head -5

# 模式5: 从配置中心动态获取（Nacos/Apollo/Spring Config）
curl -s target/app.js | grep -oP '(nacos|apollo|configServer|configMap|env\.[A-Z_]+(KEY|SECRET|TOKEN))'
```

### 凭证反思清单（关键思维环节）

拿到 JS 后，按以下顺序反思每个发现到底意味着什么：

```bash
# 1. 找到 accessKey + secretKey → 这套密钥能访问什么服务？
#    阿里云: 试 OSS/ECS/RDS
#    华为云: 试 OBS
#    AWS:   试 S3/EC2
#    MinIO: 试 Bucket 列举（见阶段4）

# 2. 找到 OSS 连接信息 → 这个 Bucket 存了什么？
#    endpoint + bucket + ak → 直接测试 ListBuckets/Object
#    lhfpxtoss → 临海房票系统 Bucket（结合业务推断用途）

# 3. 找到账号密码 → 这是哪个系统的？
#    钉钉/企业微信集成 → 扫码登录相关
#    LDAP/AD 配置 → 内网认证相关
#    数据库连接串 → 能连的数据库类型和数据价值
#    SMTP/邮件 → 邮件伪造或钓鱼

# 4. 找到 JWT Token → 这是谁的 Token？过期了吗？
#    jwt.io 解码看 payload 中的 user/role/exp
#    如果是测试Token → 找签发者、可能越权到真实用户

# 5. 找到内网 IP/域名 → 是哪个环境的？
#    后缀 dev/test/staging/ontest → 测试环境
#    10.x.x.x / 192.168.x.x → 内网段
#    k8s service 名 → 可推断微服务架构

# 6. 找到 API 路径 → 这个接口做什么的？
#    /supplier-info/page → 供应商管理（数据敏感程度高）
#    /v1/vehicle-status → 车辆状态（业务核心）
#    /api/v1/config → 配置管理（可能泄漏系统配置）
```

```bash
grep -r '@\(RequestMapping\|GetMapping\|PostMapping\)' --include="*.java" .
grep -rP '(password|secret|token|apiKey|privateKey)\s*[:=]\s*["'"'"'][^"'"'"]{3,}' --include="*.java" .
grep -rP 'permitAll|anonymous|excludePathPatterns' --include="*.java" .
```

---
## 阶段3: 漏洞挖掘命令

### 批量未授权复测

```bash
while read -r endpoint; do
  authed_resp=$(curl -s -o /tmp/authed.txt -w "%{size_download}" -b "session=COOKIE" "http://target$endpoint")
  unauth_resp=$(curl -s -o /tmp/unauth.txt -w "%{size_download}" "http://target$endpoint")
  if [ "$unauth_resp" -gt 100 ] && [ "$unauth_resp" -ge $((authed_resp * 70 / 100)) ]; then
    echo "[!] 疑似未授权: $endpoint"
  fi
done < discovered_endpoints.txt
```

### 弱口令字典

```
# 通用测试账号
admin/admin, admin/123456, admin/Admin@123, admin/password
test/test, test/123456, test/test123, test/password
root/root, user/user, guest/guest, demo/demo
manager/manager, system/system, operator/operator
# 中文拼音
zhangsan/zhangsan, zhangsan/123456, lisi/lisi, lisi/123456
wangwu/wangwu, wangwu/123456, zhaoliu/zhaoliu
# 单字姓
wang/wang, li/li, zhang/zhang, liu/liu, chen/chen
yang/yang, huang/huang, zhao/zhao, wu/wu
# 英文名
john/john, tom/tom, jerry/jerry, bob/bob, alice/alice
james/james, david/david, mike/mike, peter/peter
# 公司相关
{company}/{company}, {company}/123456, {company}@123
{company_abbr}/{company_abbr}, {domain_prefix}/123456
```

### 目录扫描 (dirsearch)

```bash
dirsearch -u "http://target:port/" --deep-recursive --max-recursion-depth=3 -t 20 --random-agent --timeout=10
dirsearch -u "http://target:port/" -e php,asp,aspx,jsp,html,zip,tar,gz,bak,json,git,svn
```

### 框架定制路径

```bash
case $tech_stack in
  *"若依"*|"RuoYi"*) paths="/druid/ /gen /common/download/resource/" ;;
  *"Spring"*) paths="/actuator /actuator/env /swagger-ui.html /v2/api-docs" ;;
  *"ThinkPHP"*) paths="/runtime/ /runtime/logs/ /index.php/index/" ;;
  *"Nacos"*) paths="/nacos/v1/auth/users /nacos/v1/console" ;;
  *"Tomcat"*) paths="/examples/ /manager/html /docs/" ;;
esac
```

### 常用探测路径

```
/admin/, /manager/, /console/, /system/     → 后台管理
/api/, /v1/, /v2/, /graphql              → API端点
/backup/, *.bak, *.zip, *.tar.gz         → 备份文件
/uploads/, /files/, /download/           → 文件遍历
/.git/, /.svn/, /.env, /WEB-INF/web.xml  → 配置泄露
/swagger-ui.html, /doc.html, /api-docs   → API文档
/actuator/, /druid/, /nacos/             → 组件端点
```

### CVE版本比对速查

| 组件 | 受影响版本 | CVE | 难度 |
|------|-----------|-----|------|
| Spring Boot | <2.6.6/<2.5.12 | CVE-2022-22965 | 中 |
| Spring Cloud | <3.1.2/<3.0.5 | CVE-2022-22963 | 低 |
| Apache Shiro | <1.9.1 | CVE-2023-22602 | 中 |
| Fastjson | ≤1.2.80 | 多种RCE | 低 |
| Log4j | ≤2.14.1 | CVE-2021-44228 | 低 |
| Nacos | ≤2.0.3 | CVE-2021-29441 | 低 |
| Tomcat | <9.0.62 | CVE-2022-22965 | 中 |
| ThinkPHP | ≤6.0 | 多版本RCE | 视版本 |
```
```


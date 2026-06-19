# 阶段命令参考

本文件包含从 SKILL.md 抽离的详细 bash 命令、测试脚本、字典和配置。
当需要执行具体扫描/测试操作时，从此文件获取命令。

---

## 阶段1: 资产发现命令

### 全端口扫描 (masscan/nmap)

```bash
# Masscan 全端口快速扫描（需root，使用sudo_helper）
# rate=100  → 家庭宽带/代理
# rate=1000 → 云VPS/内网（推荐）
# rate=10000 → 高配VPS同网段
sudo_helper.sh "masscan -iL targets_ip.txt -p0-65535 --rate=1000 -oG masscan_results.gnmap"

# Nmap 服务识别
sudo_helper.sh "nmap -iL targets_ip.txt -p- -sV -sC -T4 -oA fullport_scan"

# sudo_helper.sh 路径: /home/my/.local/bin/sudo_helper.sh
```

### URL聚合去重

```bash
# 建立 IP→域名 映射表
awk -F',' 'NR>1 && $3!="" {print $1","$3}' hunter.csv | sort -u > ip_domain_map.csv

# 拼接全端口URL
while IFS=',' read -r ip domain; do
  ports=$(grep "$ip" masscan_results.gnmap | grep -oP '\d+/open' | cut -d'/' -f1)
  for port in $ports; do
    case $port in
      443|8443|9443) echo "https://$domain:$port" ;;
      *)             echo "http://$domain:$port" ;;
    esac
  done
done < ip_domain_map.csv > full_urls.txt

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

### 本地审计命令

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


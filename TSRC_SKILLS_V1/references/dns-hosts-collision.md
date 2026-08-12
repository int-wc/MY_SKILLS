# split-horizon DNS / hosts 碰撞（目标不可达处理）

> 适用场景：目标域名 curl 超时（HTTP 000）、连接失败、或返回异常 404 时，**第一排查项**就是 split-horizon DNS 与 hosts 碰撞。禁止因 DNS 超时直接放弃资产或误标"无法进行测试"。

## 1. split-horizon DNS（内网解析）识别

**现象**：域名直连超时/失败，但 FOFA/资产CSV 显示该域名存在公网IP记录；或同IP段其他域名可正常访问。

**判断**：本地解析出内网IP → split-horizon，公网访问必须绕过。

```bash
getent hosts <domain>          # 本地解析（可能拿到内网IP: 10.x/172.16-31.x/192.168.x/100.64.x/169.254.x）
dig +short <domain>            # 同上
dig @8.8.8.8 +short <domain>   # 公网DNS对照（@1.1.1.1 亦可）
```

**溯源公网IP（三选一）**：
1. `assets_info/*.csv`（FOFA资产）中该域名/IP 记录
2. 同域名不同主机名指向的公网IP：`minio.xx.com`、`xx-dev.xx.com`、`oss-test.xx.com` 等
3. 指纹/标题相似的其他域名（FOFA 搜 title/body 关键字）

**绕过（关键）**：curl 加 `--resolve` 或 `--connect-to` 直连公网IP，同时保持正确 Host 头/SNI。

```bash
# --resolve: 仅指定域名解析，Host头/SNI 自动用 <host>
curl -sk --resolve aimdata-label.agibot.com:443:14.103.74.217 https://aimdata-label.agibot.com/api/xxx

# --connect-to: 更通用（可换端口）
curl -sk --connect-to aimdata-label.agibot.com:443:14.103.74.217:443 https://aimdata-label.agibot.com/api/xxx
```

**验证**：加 `--resolve` 后返回 HTTP 200 → 目标实际可达 → **后续所有**对该域名的 curl 一律带 `--resolve`（内网IP解析默认不可达，漏掉会全部超时）。

## 2. hosts 碰撞（同IP多域名 / 共享集群服务定位）

**场景**：目标服务（尤其对象存储 / 内网API / 数据库管理面 / MinIO / OSS）只解析内网DNS，但其端口可能在某公网IP上开放（多业务共享集群 / NAT映射 / SLB暴露）。

**方法**：对资产CSV收集的全部公网IP批量探测目标端口，找同端口开放的其他IP。

```bash
# 批量探测（短超时，并行）
for ip in $(grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' assets_info/*.csv | sort -u); do
  ( timeout 2 nc -zv -w 2 $ip <port> 2>/dev/null && echo "OPEN: $ip <port>" ) &
done; wait
```

对候选IP用目标 Host 头/SNI 发请求，看是否返回目标服务指纹：

```bash
curl -sk --resolve <host>:<port>:<ip> https://<host>:<port>/
# 命中判定：返回目标服务特征（S3 XML / MinIO / 具体应用页面/标题）即该端口可经此IP到达
```

**典型案例（智元创新 aimdata-label）**：
- `aimdata-label.agibot.com` 内网DNS=`10.111.101.201`，公网=`14.103.74.217`（--resolve 后可达，HTTP 200）
- `s3-zhoupu.agibot.com:20481`（MinIO对象存储）仅内网解析=`10.111.101.91`，公网端口20481/9000/9001经FOFA全量IP碰撞发现开放在 `121.199.83.93`（集团级网关IP）
- 该IP对非白名单IP在TLS握手即RST → 判定为**IP白名单门禁**（服务确实公网暴露，但仅允许平台出口/内网IP）

## 3. 常见坑（务必遵守）

1. **zsh 未引号变量不 word-split**：`--resolve` 参数必须**内联写在 curl 命令里**，不能放在变量中展开（`$R` 会被当作单个参数导致 `option ... is unknown`）。要放变量需用 `${=VAR}` 强制分词。
2. **`--resolve` 格式**为 `<host>:<port>:<ip>`，端口必须与请求端口一致（443/20481/8080 等）；访问带端口服务时 Host 头需含端口。
3. **签名类请求签名绑定 Host 头**（S3预签名URL / 带 `Authorization` 签名的请求）：`--resolve` 换IP但 Host 头必须保持原样，否则签名校验失败（SigV4 的 `X-Amz-SignedHeaders=host`）。
4. **split-horizon 判定后该资产按"可达"处理**，纳入后续全部阶段测试；不要因 DNS 超时误标"无法进行测试"或直接跳过。
5. **IP白名单门禁识别**：TCP可连（nc能connect）但发送数据即被RST（`write:errno=104` / TLS ClientHello 被重置）→ 服务公网暴露但IP受限。此时改走平台侧可达面（平台API/导出/SSRF）间接验证，并如实标注网络边界限制。
6. **扫描批量端口时控制超时**：对不响应IP用 `timeout 2` 且并行，避免串行扫描挂死（一条命令超时拖垮整个探测）。

## 4. 判定结果落库

- 确认可达（含 --resolve 绕过成功）→ 该资产进入正常测试流程，curl 命令统一带 `--resolve`。
- 判定 IP 白名单门禁 → 记录"端口公网开放但IP受限"，走平台侧验证，报告中如实标注。
- DNS 全部内网且无公网IP可溯源 → 才可标记"无法进行测试"并写明原因。

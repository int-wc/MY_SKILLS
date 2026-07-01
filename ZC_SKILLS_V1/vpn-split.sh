#!/bin/bash
# ============================================================
# ZC VPN 渗透隔离脚本（通用版 — 适配任意项目）
# 功能：仅渗透测试流量走 OpenVPN，日常流量走外网
#
# 用法：
#   ./vpn-split.sh up [项目目录]    — 启动VPN
#   ./vpn-split.sh down             — 关闭VPN
#   ./vpn-split.sh status           — 查看状态
#   ./vpn-split.sh exec <cmd>       — 单条命令走VPN
#   ./vpn-split.sh shell            — 进入VPN隔离shell
#
# 不指定项目目录时，默认取脚本所在目录的父目录
# ============================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ============================================================
# 颜色输出
# ============================================================
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; }
title() { echo -e "\n${CYAN}════════════════════════════════════════${NC}"; echo -e "${CYAN}  $1${NC}"; echo -e "${CYAN}════════════════════════════════════════${NC}"; }

# ============================================================
# 解析项目目录
# ============================================================
PROJECT_DIR="${2:-$(dirname "$SCRIPT_DIR")}"
info "项目目录: $PROJECT_DIR"

# ============================================================
# 自动发现 OVPN 配置
# ============================================================
discover_ovpn() {
  local ovpn_files=($(ls "$SCRIPT_DIR"/*.ovpn 2>/dev/null))
  if [ ${#ovpn_files[@]} -eq 0 ]; then
    error "未找到 .ovpn 文件，请检查 OPENVPN/ 目录"
    exit 1
  fi
  echo "${ovpn_files[0]}"
}

# ============================================================
# 自动发现 VPN 账号密码
# ============================================================
discover_credentials() {
  # 尝试多个来源查找账号密码
  local creds=()

  # 1. OPENVPEN_USERNAME_AND_PASSWORD 文件
  local cred_file=$(ls "$SCRIPT_DIR"/OPENVPEN_USERNAME_AND_PASSWORD "$SCRIPT_DIR"/*username* "$SCRIPT_DIR"/*password* 2>/dev/null | head -1)
  if [ -n "$cred_file" ]; then
    creds+=("$(head -1 "$cred_file" | grep -oP '账号[：:]\s*\S+|vpn_\w+' | head -1)")
    creds+=("$(tail -1 "$cred_file" | grep -oP '密码[：:]\s*\S+' | head -1)")
    # 如果 grep 没抓到，尝试从内容中直接提取
    if [ -z "${creds[0]}" ]; then
      creds=($(grep -oP '(vpn_\w+)' "$cred_file" | head -1) $(grep -oP '(?<=密码[：:])[\w]+' "$cred_file" | head -1))
    fi
  fi

  # 2. NOTICE 目录
  local notice_file=$(ls "$(dirname "$SCRIPT_DIR")/NOTICE"/NOTICE2 2>/dev/null | head -1)
  if [ -z "${creds[0]}" ] && [ -n "$notice_file" ]; then
    creds=(
      $(grep -oP '(?<=VPN账号[：:]\s*)\S+' "$notice_file" | head -1)
      $(grep -oP '(?<=密码[：:]\s*)\S+' "$notice_file" | head -1)
    )
  fi

  echo "${creds[0]}" > "$AUTH_FILE"
  echo "${creds[1]}" >> "$AUTH_FILE"
  chmod 600 "$AUTH_FILE"

  if [ -z "${creds[0]}" ]; then
    error "无法自动发现 VPN 账号密码"
    echo "  请手动创建 $AUTH_FILE（第一行账号，第二行密码）"
    return 1
  fi
  info "VPN 账号: ${creds[0]} (已保存认证文件)"
}

# ============================================================
# 自动发现资产中的域名和 IP（通用扫描器）
# ============================================================
discover_targets() {
  echo ""
  title "扫描资产文件，提取域名/IP"

  local ASSETS_DIR="${PROJECT_DIR}/assets"
  local TARGETS_FILE="/tmp/.zc-vpn-targets-$$.txt"
  > "$TARGETS_FILE"

  if [ ! -d "$ASSETS_DIR" ]; then
    warn "assets/ 目录不存在，跳过自动发现"
    echo ""
    return 1
  fi

  # 查找所有数据文件
  local found=0
  for f in "$ASSETS_DIR"/*; do
    [ -f "$f" ] || continue
    local ext="${f##*.}"
    case "$ext" in
      xlsx|xls)
        found=1
        info "解析 xlsx: $(basename $f)"
        python3 -c "
import openpyxl, re, sys
wb = openpyxl.load_workbook('$f')
ws = wb.active
seen = set()
for row in ws.iter_rows(values_only=True):
    for cell in row:
        if cell and isinstance(cell, str):
            # 提取 IP
            for m in re.finditer(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', cell):
                if m.group(1) not in seen:
                    seen.add(m.group(1))
                    print(m.group(1))
            # 提取域名（不含IP格式和邮箱）
            for m in re.finditer(r'(?:(?:https?://))?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:\:\d+)?)(?:\s|$|/)', cell):
                domain = m.group(1).split(':')[0]
                if domain not in seen and not re.match(r'^\d+\.\d+\.\d+\.\d+', domain):
                    seen.add(domain)
                    print(domain)
" 2>/dev/null >> "$TARGETS_FILE" || warn "  解析失败: $(basename $f)"
        ;;
      csv)
        found=1
        info "解析 csv: $(basename $f)"
        # 尝试提取 URL 列、域名列、IP 列
        awk -F',' 'NR>1 {
          for(i=1;i<=NF;i++) {
            gsub(/^["\047]|["\047]$/,"",$i)
            if ($i ~ /^https?:\/\//) { split($i,a,"/"); print a[3]; }
            else if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+/) print $i
          }
        }' "$f" 2>/dev/null >> "$TARGETS_FILE"
        ;;
      txt)
        found=1
        info "解析 txt: $(basename $f)"
        python3 -c "
import re
with open('$f') as fh:
    for line in fh:
        for m in re.finditer(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line):
            print(m.group(1))
        for m in re.finditer(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?::\d+)?)', line):
            d = m.group(1).split(':')[0]
            if not re.match(r'^\d+\.\d+\.\d+\.\d+', d):
                print(d)
" >> "$TARGETS_FILE" 2>/dev/null
        ;;
    esac
  done

  if [ "$found" -eq 0 ]; then
    warn "assets/ 下无可解析的数据文件（支持: xlsx/csv/txt）"
  fi

  # 去重
  sort -u "$TARGETS_FILE" -o "$TARGETS_FILE"
  local count=$(wc -l < "$TARGETS_FILE")
  info "从资产文件提取到 ${count} 个目标域名/IP"

  if [ "$count" -gt 0 ]; then
    echo ""
    echo -e "${CYAN}发现的目标：${NC}"
    head -30 "$TARGETS_FILE"
    [ "$count" -gt 30 ] && echo "  ... 还有 $(($count - 30)) 个"
  fi

  echo "$TARGETS_FILE"
  return 0
}

# ============================================================
# 添加路由（通过VPN接口）
# ============================================================
add_routes() {
  local TARGETS_FILE="$1"
  local VPN_GW="$2"
  local VPN_IFACE="$3"
  local added=0

  if [ ! -f "$TARGETS_FILE" ]; then
    warn "没有目标文件可添加路由"
    return
  fi

  while IFS= read -r target; do
    [ -z "$target" ] && continue
    target=$(echo "$target" | tr -d '[:space:]')

    # 如果是 IP 格式，直接加路由
    if echo "$target" | grep -qP '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'; then
      if ! ip route get "$target" 2>/dev/null | grep -q "dev $VPN_IFACE"; then
        ip route add "$target/32" via "$VPN_GW" dev "$VPN_IFACE" 2>/dev/null && added=$((added+1))
      fi
    else
      # 如果是域名，尝试解析（优先通过 VPN DNS）
      local ips=$(dig +short "$target" @8.8.8.8 2>/dev/null; dig +short "$target" @1.1.1.1 2>/dev/null)
      if [ -n "$ips" ]; then
        while IFS= read -r ip; do
          if echo "$ip" | grep -qP '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'; then
            if ! ip route get "$ip" 2>/dev/null | grep -q "dev $VPN_IFACE"; then
              ip route add "$ip/32" via "$VPN_GW" dev "$VPN_IFACE" 2>/dev/null && added=$((added+1))
            fi
          fi
        done <<< "$ips"
      else
        # DNS 解析失败 → 添加域名到 /etc/hosts 下次再试
        warn "  DNS 解析失败: $target（VPN 连接后重试）"
      fi
    fi
  done < "$TARGETS_FILE"

  info "已添加 ${added} 条目标路由（通过 $VPN_IFACE）"
}

# ============================================================
# up — 启动VPN
# ============================================================
cmd_up() {
  title "启动 ZC 渗透 VPN（隔离模式）"

  # 检查 root
  if [ "$EUID" -ne 0 ]; then
    error "需要 root 权限"
    echo "  请使用: sudo $0 up"
    exit 1
  fi

  OVPN_FILE=$(discover_ovpn)
  info "OVPN 配置: $(basename $OVPN_FILE)"

  AUTH_FILE="${SCRIPT_DIR}/.vpn-auth"
  VPN_PID_FILE="/tmp/.zc-vpn-${PROJECT_DIR##*/}.pid"
  VPN_IFACE="tun0"

  # 检查是否已运行
  if [ -f "$VPN_PID_FILE" ] && kill -0 $(cat "$VPN_PID_FILE") 2>/dev/null; then
    warn "VPN 已在运行 (PID: $(cat $VPN_PID_FILE))"
    cmd_status
    return 0
  fi

  discover_credentials

  # 创建隔离配置
  local ISOLATED_OVPN="${SCRIPT_DIR}/.vpn-split.ovpn"
  cp "$OVPN_FILE" "$ISOLATED_OVPN"
  cat >> "$ISOLATED_OVPN" << 'ISOSEPC'

# ===== 渗透隔离配置 =====
route-nopull
pull-filter ignore redirect-gateway
pull-filter ignore route-ipv6
pull-filter ignore redirect-gateway-ipv6
persist-tun
persist-key
auth-nocache
ISOSEPC

  info "启动 OpenVPN（不修改默认路由）..."
  openvpn --config "$ISOLATED_OVPN" \
          --auth-user-pass "$AUTH_FILE" \
          --log "/tmp/.zc-vpn-${PROJECT_DIR##*/}.log" \
          --writepid "$VPN_PID_FILE" \
          --daemon zc-vpn-${PROJECT_DIR##*/}

  # 等待 VPN 接口
  local retries=0
  while [ $retries -lt 15 ]; do
    sleep 1
    if ip link show "$VPN_IFACE" 2>/dev/null | grep -q "UP"; then
      info "VPN 接口 $VPN_IFACE 就绪"
      break
    fi
    echo -n "."
    retries=$((retries+1))
  done

  if ! ip link show "$VPN_IFACE" 2>/dev/null | grep -q "UP"; then
    error "VPN 接口未就绪"
    cat "/tmp/.zc-vpn-${PROJECT_DIR##*/}.log" 2>/dev/null | tail -20
    exit 1
  fi

  # 获取 VPN 网关
  local VPN_GW=$(ip route show dev "$VPN_IFACE" 2>/dev/null | awk 'NR==1{print $1}')
  [ -z "$VPN_GW" ] && VPN_GW="10.8.0.1"
  echo "$VPN_GW" > "/tmp/.zc-vpn-${PROJECT_DIR##*/}.gw"
  info "VPN 网关: $VPN_GW"

  # 等待 3s 让 VPN 网络稳定
  sleep 3

  # 自动发现资产并添加路由
  local TARGETS_FILE=$(discover_targets)
  if [ -n "$TARGETS_FILE" ] && [ -f "$TARGETS_FILE" ]; then
    add_routes "$TARGETS_FILE" "$VPN_GW" "$VPN_IFACE"
    rm -f "$TARGETS_FILE"
  fi

  # 验证隔离
  title "✅ VPN 隔离就绪"
  echo ""
  info "🔒 渗透流量 → 🛡️ VPN ($VPN_IFACE)"
  info "🌐 日常流量 → ☀️ 外网直连"
  echo ""

  local zc_code=$(curl -sk --max-time 5 https://zhongce.360.net/ -o /dev/null -w '%{http_code}' 2>/dev/null)
  local ext_code=$(curl -sk --max-time 5 https://www.baidu.com -o /dev/null -w '%{http_code}' 2>/dev/null)
  info "众测平台: HTTP $zc_code（走VPN）"
  info "外网(百度): HTTP $ext_code（直连）"

  if [ "$zc_code" = "000" ]; then
    warn "众测平台不通，可能需要重新连接VPN"
  fi
  if [ "$ext_code" != "000" ] && [ "$ext_code" != "" ]; then
    info "✅ 外网连接正常"
  fi
  echo ""
  echo -e "  ${YELLOW}后续使用：${NC}"
  echo -e "  $0 exec curl -sk https://target.com    ${GREEN}# 单条命令走VPN${NC}"
  echo -e "  $0 shell                                ${GREEN}# 进入隔离shell${NC}"
  echo -e "  $0 status                               ${GREEN}# 查看状态${NC}"
  echo -e "  $0 down                                 ${GREEN}# 关闭VPN${NC}"
}

# ============================================================
# down
# ============================================================
cmd_down() {
  title "关闭 VPN"
  VPN_PID_FILE="/tmp/.zc-vpn-${PROJECT_DIR##*/}.pid"

  if [ -f "$VPN_PID_FILE" ]; then
    kill $(cat "$VPN_PID_FILE") 2>/dev/null || true
    rm -f "$VPN_PID_FILE"
  fi

  # 清理路由
  local gw_file="/tmp/.zc-vpn-${PROJECT_DIR##*/}.gw"
  if [ -f "$gw_file" ]; then
    local GW=$(cat "$gw_file")
    ip route show dev tun0 2>/dev/null | while read route; do
      ip route del $route 2>/dev/null || true
    done
    rm -f "$gw_file"
  fi

  rm -f "/tmp/.zc-vpn-${PROJECT_DIR##*/}.log" "/tmp/.zc-vpn-${PROJECT_DIR##*/}.targets"
  info "VPN 已关闭，路由已清理"
}

# ============================================================
# status
# ============================================================
cmd_status() {
  title "VPN 状态"
  VPN_PID_FILE="/tmp/.zc-vpn-${PROJECT_DIR##*/}.pid"

  if [ -f "$VPN_PID_FILE" ] && kill -0 $(cat "$VPN_PID_FILE") 2>/dev/null; then
    info "VPN: 运行中 (PID: $(cat $VPN_PID_FILE))"
  else
    error "VPN: 未运行"
    return 1
  fi

  if ip link show tun0 2>/dev/null | grep -q UP; then
    local vpn_ip=$(ip addr show tun0 | awk '/inet /{print $2}' | cut -d/ -f1)
    info "接口: tun0 | IP: $vpn_ip"
    echo ""
    echo -e "${CYAN}VPN 路由表：${NC}"
    ip route show dev tun0 2>/dev/null || echo "  (无自定义路由)"
    echo ""

    local zc=$(curl -sk --max-time 5 https://zhongce.360.net/ -o /dev/null -w '%{http_code}' 2>/dev/null)
    local ext=$(curl -sk --max-time 5 https://www.baidu.com -o /dev/null -w '%{http_code}' 2>/dev/null)
    info "众测平台: HTTP $zc"
    info "外网(百度): HTTP $ext"

    local ok=0
    [ "$zc" != "000" ] && [ -n "$zc" ] && ok=$((ok+1))
    [ "$ext" != "000" ] && [ -n "$ext" ] && ok=$((ok+1))
    [ "$ok" -ge 2 ] && echo "" && info "✅ 隔离正常：渗透走VPN + 日常走外网"
  else
    error "tun0 接口不可用"
  fi
}

# ============================================================
# exec / shell
# ============================================================
cmd_exec() {
  [ $# -eq 0 ] && { error "用法: $0 exec <command>"; exit 1; }
  eval "$@"
}

cmd_shell() {
  title "VPN 隔离 Shell（exit 退出）"
  echo -e "${YELLOW}此 shell 中的流量走 VPN，当前终端走外网${NC}\n"
  export PS1="[VPN] \u@\h:\w\$ "
  bash --norc --noprofile
}

# ============================================================
# 主入口
# ============================================================
case "${1:-status}" in
  up)     cmd_up ;;
  down)   cmd_down ;;
  status) cmd_status ;;
  exec)   shift; cmd_exec "$@" ;;
  shell)  cmd_shell ;;
  *)
    echo "用法: $0 <command> [项目目录]"
    echo ""
    echo "命令:"
    echo "  up [项目目录]  启动 VPN（隔离模式）"
    echo "  down           关闭 VPN"
    echo "  status         查看状态"
    echo "  exec <cmd>     单条命令走 VPN"
    echo "  shell          进入隔离 shell"
    echo ""
    echo "示例:"
    echo "  sudo $0 up /home/my/360zc/1516_中远海运"
    echo "  $0 exec curl -sk https://target"
    echo "  $0 status"
    ;;
esac

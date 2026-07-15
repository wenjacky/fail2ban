#!/usr/bin/env bash
set -euo pipefail

# systemd 使用默认路径；测试时可用环境变量指向临时文件，避免修改宿主机。
CONFIG_FILE=${TINYVPN_CONFIG_FILE:-/etc/tinyvpn/network.conf}
HOSTS_FILE=${TINYVPN_HOSTS_FILE:-/etc/hosts}
DOMAIN=tinyvpn.host.com

[[ -r $CONFIG_FILE ]] || {
  printf '错误: 无法读取 tinyvpn 配置: %s\n' "$CONFIG_FILE" >&2
  exit 1
}
[[ -r $HOSTS_FILE && -w $HOSTS_FILE ]] || {
  printf '错误: hosts 文件不可读写: %s\n' "$HOSTS_FILE" >&2
  exit 1
}

# network.conf 由 root 管理，仅用于提供 SUBNET。
# shellcheck disable=SC1090
source "$CONFIG_FILE"

[[ ${SUBNET:-} =~ ^([0-9]{1,3}\.){3}0$ ]] || {
  printf '错误: SUBNET 必须是 IPv4 /24 网络地址（例如 10.44.44.0）\n' >&2
  exit 1
}

IFS=. read -r octet1 octet2 octet3 octet4 <<< "$SUBNET"
for octet in "$octet1" "$octet2" "$octet3"; do
  [[ $octet =~ ^(0|[1-9][0-9]{0,2})$ ]] && (( 10#$octet <= 255 )) || {
    printf '错误: SUBNET 包含无效 IPv4 八位组: %s\n' "$octet" >&2
    exit 1
  }
done

# /24 网络的服务端隧道地址固定取 .1。
gateway="$octet1.$octet2.$octet3.1"
tmp_file=$(mktemp "${HOSTS_FILE}.tmp.XXXXXX")
trap 'rm -f "$tmp_file"' EXIT

# 删除包含目标域名的旧行，确保重复运行只保留一条映射。
awk -v domain="$DOMAIN" '
  {
    for (field = 2; field <= NF; field++) {
      if ($field == domain) {
        next
      }
    }
    print
  }
' "$HOSTS_FILE" > "$tmp_file"
printf '%s %s\n' "$gateway" "$DOMAIN" >> "$tmp_file"

# 尽量继承原文件的权限和属主；macOS 测试环境不支持 --reference 时退回安全权限。
chmod --reference="$HOSTS_FILE" "$tmp_file" 2>/dev/null || chmod 0644 "$tmp_file"
chown --reference="$HOSTS_FILE" "$tmp_file" 2>/dev/null || true
mv "$tmp_file" "$HOSTS_FILE"
trap - EXIT

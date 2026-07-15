#!/usr/bin/env bash
set -euo pipefail

BASE_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

assert_contains() {
  local file=$1 expected=$2
  grep -Fq -- "$expected" "$file" || fail "$file 缺少: $expected"
}

assert_not_contains() {
  local file=$1 unexpected=$2
  if grep -Fq -- "$unexpected" "$file"; then
    fail "$file 不应包含: $unexpected"
  fi
}

test_units_and_roles() {
  local tiny_client="$BASE_DIR/tinyvpn/client/tinyvpn.service"
  local tiny_server="$BASE_DIR/tinyvpn/server/tinyvpn.service"
  local speeder_unit="$BASE_DIR/speeder2/speederv2@.service"
  local udp2raw_unit="$BASE_DIR/udp2raw/udp2raw@.service"

  [[ -f $speeder_unit ]] || fail "缺少规范文件名: $speeder_unit"
  [[ ! -e "$BASE_DIR/speeder2/speederv2@.service " ]] || fail 'speederv2 unit 文件名末尾仍有空格'

  assert_contains "$tiny_client" 'Description=tinyfecVPN client service'
  assert_contains "$tiny_client" 'ExecStartPre=/etc/tinyvpn/update-hosts.sh'
  assert_contains "$tiny_client" 'ExecStart=/usr/local/bin/tinyvpn_amd64 -c -r127.0.0.1:44096'
  assert_contains "$tiny_server" 'Description=tinyfecVPN server service'
  assert_contains "$tiny_server" 'ExecStart=/usr/local/bin/tinyvpn_amd64 -s -l127.0.0.1:44096'
  assert_not_contains "$tiny_server" 'ExecStartPre='

  assert_contains "$speeder_unit" 'ExecStart=/usr/local/bin/speederv2_amd64 $OPTS'
  assert_contains "$udp2raw_unit" 'ExecStart=/usr/local/bin/udp2raw_amd64 $OPTS'

  assert_contains "$BASE_DIR/speeder2/client/spdwg_sg2gz.conf" 'OPTS=-c -l127.0.0.1:44001 -r127.0.0.1:44101'
  assert_contains "$BASE_DIR/speeder2/server/spdwg_sg2gz.conf" 'OPTS=-s -l127.0.0.1:44101 -r127.0.0.1:44001'

  assert_contains "$BASE_DIR/udp2raw/client/tinyvpn.conf" 'OPTS=-c -l0.0.0.0:44096 -r47.245.124.39:24096'
  assert_contains "$BASE_DIR/udp2raw/server/tinyvpn.conf" 'OPTS=-s -l0.0.0.0:24096 -r127.0.0.1:44096'
  assert_contains "$BASE_DIR/udp2raw/client/uspdwg_sg2gz.conf" 'OPTS=-c -l127.0.0.1:44101 -r47.245.124.39:44101'
  assert_contains "$BASE_DIR/udp2raw/server/uspdwg_sg2gz.conf" 'OPTS=-s -l0.0.0.0:44101 -r127.0.0.1:44101'
  assert_contains "$BASE_DIR/udp2raw/client/wireguard.conf" 'OPTS=-c -l127.0.0.1:22180 -r47.245.124.39:21180'
  assert_contains "$BASE_DIR/udp2raw/server/wireguard.conf" 'OPTS=-s -l0.0.0.0:21180 -r127.0.0.1:22180'

  printf 'PASS: config and systemd units\n'
}

test_update_hosts() {
  local tmp_dir config_file hosts_file before count
  tmp_dir=$(mktemp -d)
  config_file="$tmp_dir/network.conf"
  hosts_file="$tmp_dir/hosts"
  trap 'rm -rf "$tmp_dir"' RETURN

  printf '127.0.0.1 localhost\n192.0.2.9 tinyvpn.host.com old-alias\n' > "$hosts_file"
  printf 'SUBNET=10.44.44.0\n' > "$config_file"

  TINYVPN_CONFIG_FILE=$config_file TINYVPN_HOSTS_FILE=$hosts_file \
    bash "$BASE_DIR/tinyvpn/update-hosts.sh"
  assert_contains "$hosts_file" '10.44.44.1 tinyvpn.host.com'
  assert_not_contains "$hosts_file" '192.0.2.9 tinyvpn.host.com'

  TINYVPN_CONFIG_FILE=$config_file TINYVPN_HOSTS_FILE=$hosts_file \
    bash "$BASE_DIR/tinyvpn/update-hosts.sh"
  count=$(grep -Ec '(^|[[:space:]])tinyvpn\.host\.com([[:space:]]|$)' "$hosts_file")
  [[ $count == 1 ]] || fail "重复运行后 tinyvpn.host.com 出现 $count 次"

  before=$(cat "$hosts_file")
  printf 'SUBNET=10.44.44.1\n' > "$config_file"
  if TINYVPN_CONFIG_FILE=$config_file TINYVPN_HOSTS_FILE=$hosts_file \
    bash "$BASE_DIR/tinyvpn/update-hosts.sh" >/dev/null 2>&1; then
    fail '应拒绝主机地址作为 SUBNET'
  fi
  [[ $(cat "$hosts_file") == "$before" ]] || fail '非法 SUBNET 修改了 hosts 文件'

  printf 'SUBNET=300.1.1.0\n' > "$config_file"
  if TINYVPN_CONFIG_FILE=$config_file TINYVPN_HOSTS_FILE=$hosts_file \
    bash "$BASE_DIR/tinyvpn/update-hosts.sh" >/dev/null 2>&1; then
    fail '应拒绝超出范围的 IPv4 地址'
  fi
  [[ $(cat "$hosts_file") == "$before" ]] || fail '越界 SUBNET 修改了 hosts 文件'

  rm -rf "$tmp_dir"
  trap - RETURN
  printf 'PASS: update-hosts\n'
}

test_documentation() {
  local readme="$BASE_DIR/README.md"
  [[ -f $readme ]] || fail "缺少目录说明: $readme"

  assert_contains "$readme" 'https://github.com/wangyu-/tinyfecVPN/releases'
  assert_contains "$readme" 'https://github.com/wangyu-/UDPspeeder/releases'
  assert_contains "$readme" 'https://github.com/wangyu-/udp2raw-tunnel/releases'
  assert_contains "$readme" '--role'
  assert_contains "$readme" '--component'
  assert_contains "$readme" '--dry-run'
  assert_contains "$readme" '--enable-now'
  assert_contains "$readme" '24096'
  assert_contains "$readme" '44101'
  assert_contains "$readme" '21180'
  assert_contains "$readme" '预编译服务端'
  assert_contains "$readme" '轮换密钥'
  assert_contains "$readme" 'udp2raw -a'
  assert_contains "$readme" 'systemctl status'
  assert_contains "$readme" 'journalctl'
  assert_contains "$readme" '回滚'

  printf 'PASS: documentation\n'
}

test_units_and_roles
test_update_hosts
test_documentation

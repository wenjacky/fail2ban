#!/usr/bin/env bash
set -euo pipefail

BASE_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
TEST_ROOT=$(mktemp -d)

cleanup() {
  rm -rf "$TEST_ROOT"
}
trap cleanup EXIT

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

new_fixture() {
  local temp fixture
  temp=$(mktemp -d "$TEST_ROOT/fixture.XXXXXX")
  fixture="$temp/source"
  mkdir -p "$fixture"
  cp -R "$BASE_DIR/." "$fixture/"
  printf '%s\n' "$fixture"
}

seed_binaries() {
  local fixture=$1 name
  mkdir -p "$fixture/bin"
  for name in tinyvpn_amd64 speederv2_amd64 udp2raw_amd64; do
    printf '#!/bin/sh\nexit 0\n' > "$fixture/bin/$name"
    chmod 0755 "$fixture/bin/$name"
  done
}

expect_failure() {
  local description=$1
  shift
  if "$@" >/dev/null 2>&1; then
    fail "$description 应失败"
  fi
}

assert_file() {
  [[ -f $1 ]] || fail "缺少文件: $1"
}

assert_not_exists() {
  [[ ! -e $1 ]] || fail "不应存在: $1"
}

file_mode() {
  local file=$1
  stat -f '%Lp' "$file" 2>/dev/null || stat -c '%a' "$file"
}

test_argument_validation() {
  local fixture root
  fixture=$(new_fixture)
  root="$fixture/root"

  assert_file "$fixture/deploy.sh"
  bash "$fixture/deploy.sh" --help >/dev/null
  expect_failure '缺少全部必填参数' bash "$fixture/deploy.sh"
  expect_failure '缺少 component' bash "$fixture/deploy.sh" --role client
  expect_failure '非法 role' bash "$fixture/deploy.sh" --role invalid --component tinyvpn
  expect_failure '非法 component' bash "$fixture/deploy.sh" --role client --component invalid
  expect_failure '--root 与 --enable-now 冲突' bash "$fixture/deploy.sh" \
    --role client --component tinyvpn --root "$root" --enable-now
  expect_failure '缺少 tinyvpn 二进制' bash "$fixture/deploy.sh" \
    --role client --component tinyvpn --root "$root"

  printf 'PASS: deploy argument validation\n'
}

test_dry_run() {
  local fixture root output
  fixture=$(new_fixture)
  seed_binaries "$fixture"
  root="$fixture/root"

  output=$(bash "$fixture/deploy.sh" --role client --component all --root "$root" --dry-run)
  [[ $output == *'将安装'* ]] || fail 'dry-run 没有输出安装动作'
  assert_not_exists "$root"

  printf 'PASS: deploy dry-run\n'
}

test_installation_and_backup() {
  local fixture client_root server_root backup_count
  fixture=$(new_fixture)
  seed_binaries "$fixture"
  client_root="$fixture/client-root"
  server_root="$fixture/server-root"

  bash "$fixture/deploy.sh" --role client --component tinyvpn --root "$client_root"
  assert_file "$client_root/usr/local/bin/tinyvpn_amd64"
  assert_file "$client_root/etc/tinyvpn/network.conf"
  assert_file "$client_root/etc/tinyvpn/update-hosts.sh"
  assert_file "$client_root/etc/systemd/system/tinyvpn.service"
  grep -Fq -- ' -c -r127.0.0.1:44096' "$client_root/etc/systemd/system/tinyvpn.service" || \
    fail '客户端安装了错误的 tinyvpn unit'
  assert_not_exists "$client_root/usr/local/bin/speederv2_amd64"
  [[ $(file_mode "$client_root/usr/local/bin/tinyvpn_amd64") == 755 ]] || fail '二进制权限不是 755'
  [[ $(file_mode "$client_root/etc/tinyvpn/update-hosts.sh") == 755 ]] || fail '辅助脚本权限不是 755'
  [[ $(file_mode "$client_root/etc/tinyvpn/network.conf") == 644 ]] || fail 'network.conf 权限不是 644'

  printf 'old unit\n' > "$client_root/etc/systemd/system/tinyvpn.service"
  bash "$fixture/deploy.sh" --role client --component tinyvpn --root "$client_root"
  backup_count=$(find "$client_root/etc/systemd/system" -name 'tinyvpn.service.bak.*' | wc -l | tr -d ' ')
  [[ $backup_count -ge 1 ]] || fail '覆盖 unit 前没有生成备份'
  grep -Fq -- ' -c -r127.0.0.1:44096' "$client_root/etc/systemd/system/tinyvpn.service" || \
    fail '重复部署没有恢复正确 unit'

  bash "$fixture/deploy.sh" --role server --component all --root "$server_root"
  assert_file "$server_root/usr/local/bin/tinyvpn_amd64"
  assert_file "$server_root/usr/local/bin/speederv2_amd64"
  assert_file "$server_root/usr/local/bin/udp2raw_amd64"
  assert_file "$server_root/etc/speederv2/spdwg_sg2gz.conf"
  assert_file "$server_root/etc/udp2raw/tinyvpn.conf"
  assert_file "$server_root/etc/udp2raw/uspdwg_sg2gz.conf"
  assert_file "$server_root/etc/udp2raw/wireguard.conf"
  grep -Fq -- ' -s -l127.0.0.1:44096' "$server_root/etc/systemd/system/tinyvpn.service" || \
    fail '服务端安装了错误的 tinyvpn unit'
  grep -Fq -- 'OPTS=-s ' "$server_root/etc/speederv2/spdwg_sg2gz.conf" || fail 'speeder2 服务端配置错误'
  grep -Fq -- 'OPTS=-s ' "$server_root/etc/udp2raw/tinyvpn.conf" || fail 'udp2raw 服务端配置错误'
  [[ $(file_mode "$server_root/etc/udp2raw/tinyvpn.conf") == 600 ]] || fail '含密钥配置权限不是 600'

  printf 'PASS: deploy installation and backup\n'
}

test_argument_validation
test_dry_run
test_installation_and_backup

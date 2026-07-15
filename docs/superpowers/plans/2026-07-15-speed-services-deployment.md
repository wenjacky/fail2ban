# Speed 加速服务部署 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 修正并注释三套加速服务配置，提供从本地 amd64 二进制进行安全、可重复部署的 Bash 脚本。

**Architecture:** 配置目录保持按组件和角色划分；通用模板 unit 配合实例配置，tinyvpn 因两端预启动行为不同而保留两个角色 unit。`deploy.sh` 负责参数校验、备份和安装，通过 `--root` 将测试完全隔离到临时目录。

**Tech Stack:** Bash、systemd unit、Bash 自包含测试脚本。

## Global Constraints

- 目标平台为使用 systemd 的 Linux amd64。
- 部署过程不联网下载二进制。
- 未传入 `--enable-now` 时不得启用或启动服务。
- `update-hosts.sh` 仅由 tinyvpn 客户端调用。
- 不自动配置防火墙、安全组、WireGuard 或业务 VPN。
- 不改变现有公网 IP、端口、密钥、FEC 和 MTU，角色方向修正所必需的地址除外。

---

### Task 1: 配置与 systemd unit 角色修正

**Files:**
- Create: `config/speed加速服务/tests/config_test.sh`
- Create: `config/speed加速服务/speeder2/speederv2@.service`
- Delete: `config/speed加速服务/speeder2/speederv2@.service `
- Modify: `config/speed加速服务/speeder2/client/spdwg_sg2gz.conf`
- Modify: `config/speed加速服务/speeder2/server/spdwg_sg2gz.conf`
- Modify: `config/speed加速服务/tinyvpn/client/tinyvpn.service`
- Modify: `config/speed加速服务/tinyvpn/server/tinyvpn.service`
- Modify: `config/speed加速服务/udp2raw/udp2raw@.service`
- Modify: `config/speed加速服务/udp2raw/client/tinyvpn.conf`
- Modify: `config/speed加速服务/udp2raw/client/uspdwg_sg2gz.conf`
- Modify: `config/speed加速服务/udp2raw/client/wireguard.conf`
- Modify: `config/speed加速服务/udp2raw/server/tinyvpn.conf`
- Modify: `config/speed加速服务/udp2raw/server/uspdwg_sg2gz.conf`
- Modify: `config/speed加速服务/udp2raw/server/wireguard.conf`

**Interfaces:**
- Consumes: 设计文档中确定的端口流向。
- Produces: 使用 `/usr/local/bin` 与 `/etc/<component>` 的可部署配置；`config_test.sh` 作为后续总测试入口之一。

- [ ] **Step 1: 写配置静态测试**

测试逐项使用 `grep -F` 断言：tinyvpn client 为 `-c -r127.0.0.1:44096` 且引用 `/etc/tinyvpn/update-hosts.sh`；server 为 `-s -l127.0.0.1:44096` 且不含 `ExecStartPre`；speeder 两端分别为 `-c`/`-s`；udp2raw 三组配置两端分别为 `-c`/`-s`；所有 unit 仅引用 `/usr/local/bin`；规范 service 文件存在且带空格文件名不存在。

- [ ] **Step 2: 运行测试并确认因旧配置失败**

Run: `bash 'config/speed加速服务/tests/config_test.sh'`

Expected: FAIL，首先报告 tinyvpn server 角色或旧二进制路径不符合预期。

- [ ] **Step 3: 修正角色、方向、路径并加入中文备注**

使用以下确定值：

```text
tinyvpn client: -c -r127.0.0.1:44096
tinyvpn server: -s -l127.0.0.1:44096
speeder client: -c -l127.0.0.1:44001 -r127.0.0.1:44101
speeder server: -s -l127.0.0.1:44101 -r127.0.0.1:44001
udp2raw tinyvpn client: -c -l0.0.0.0:44096 -r47.245.124.39:24096
udp2raw tinyvpn server: -s -l0.0.0.0:24096 -r127.0.0.1:44096
udp2raw speeder client: -c -l127.0.0.1:44101 -r47.245.124.39:44101
udp2raw speeder server: -s -l0.0.0.0:44101 -r127.0.0.1:44101
udp2raw wireguard client: -c -l127.0.0.1:22180 -r47.245.124.39:21180
udp2raw wireguard server: -s -l0.0.0.0:21180 -r127.0.0.1:22180
```

tinyvpn client 使用 `ExecStartPre=/etc/tinyvpn/update-hosts.sh`；server 不使用。三个 unit 的 `ExecStart` 分别指向 `/usr/local/bin/tinyvpn_amd64`、`speederv2_amd64` 和 `udp2raw_amd64`。

- [ ] **Step 4: 运行静态测试**

Run: `bash 'config/speed加速服务/tests/config_test.sh'`

Expected: `PASS: config and systemd units`

- [ ] **Step 5: 提交**

```bash
git add 'config/speed加速服务'
git commit -m 'fix: correct speed service roles and units'
```

### Task 2: tinyvpn hosts 更新脚本

**Files:**
- Modify: `config/speed加速服务/tests/config_test.sh`
- Modify: `config/speed加速服务/tinyvpn/update-hosts.sh`
- Modify: `config/speed加速服务/tinyvpn/network.conf`

**Interfaces:**
- Consumes: 默认配置 `/etc/tinyvpn/network.conf` 中的 `SUBNET`。
- Produces: `TINYVPN_CONFIG_FILE`、`TINYVPN_HOSTS_FILE` 可覆盖测试路径；合法 `/24` 网络生成 `${SUBNET%.*}.1 tinyvpn.host.com`。

- [ ] **Step 1: 写 hosts 行为测试**

在测试脚本创建临时 config/hosts，覆盖以下行为：合法 `SUBNET=10.44.44.0` 生成 `10.44.44.1 tinyvpn.host.com`；重复运行只有一条；非法值 `10.44.44.1` 与 `300.1.1.0` 均失败且 hosts 不被破坏。

- [ ] **Step 2: 运行测试并确认旧脚本失败**

Run: `bash 'config/speed加速服务/tests/config_test.sh'`

Expected: FAIL，因为旧脚本忽略测试路径覆盖或不拒绝非法子网。

- [ ] **Step 3: 实现严格、安全更新**

脚本实现以下逻辑：

```bash
#!/usr/bin/env bash
set -euo pipefail
CONFIG_FILE="${TINYVPN_CONFIG_FILE:-/etc/tinyvpn/network.conf}"
HOSTS_FILE="${TINYVPN_HOSTS_FILE:-/etc/hosts}"
DOMAIN="tinyvpn.host.com"
[[ -r "$CONFIG_FILE" ]] || { echo "错误: 无法读取配置: $CONFIG_FILE" >&2; exit 1; }
# shellcheck disable=SC1090
source "$CONFIG_FILE"
[[ ${SUBNET:-} =~ ^([0-9]{1,3}\.){3}0$ ]] || { echo "错误: SUBNET 必须是 IPv4 /24 网络地址" >&2; exit 1; }
IFS=. read -r a b c d <<< "$SUBNET"
for octet in "$a" "$b" "$c"; do
  (( octet >= 0 && octet <= 255 )) || { echo "错误: SUBNET 八位组越界" >&2; exit 1; }
done
GW="$a.$b.$c.1"
tmp_file="$(mktemp "${HOSTS_FILE}.tmp.XXXXXX")"
trap 'rm -f "$tmp_file"' EXIT
awk -v domain="$DOMAIN" '$2 != domain { print }' "$HOSTS_FILE" > "$tmp_file"
printf '%s %s\n' "$GW" "$DOMAIN" >> "$tmp_file"
chmod --reference="$HOSTS_FILE" "$tmp_file" 2>/dev/null || chmod 0644 "$tmp_file"
mv "$tmp_file" "$HOSTS_FILE"
trap - EXIT
```

- [ ] **Step 4: 运行测试与语法检查**

Run: `bash -n 'config/speed加速服务/tinyvpn/update-hosts.sh' && bash 'config/speed加速服务/tests/config_test.sh'`

Expected: `PASS: config and systemd units` 与 `PASS: update-hosts`

- [ ] **Step 5: 提交**

```bash
git add 'config/speed加速服务/tinyvpn' 'config/speed加速服务/tests/config_test.sh'
git commit -m 'feat: harden tinyvpn hosts update'
```

### Task 3: 可组合部署脚本

**Files:**
- Create: `config/speed加速服务/tests/deploy_test.sh`
- Create: `config/speed加速服务/deploy.sh`
- Create: `config/speed加速服务/bin/README.md`

**Interfaces:**
- Consumes: `bin/{tinyvpn_amd64,speederv2_amd64,udp2raw_amd64}` 和角色配置目录。
- Produces: `deploy.sh --role client|server --component tinyvpn|speeder2|udp2raw|all [--dry-run] [--enable-now] [--root DIR]`。

- [ ] **Step 1: 写部署失败路径测试**

测试复制整个加速服务目录到临时 fixture，并断言：`--help` 成功；缺失参数、非法角色、非法组件、缺失二进制失败；`--root` 与 `--enable-now` 组合失败。

- [ ] **Step 2: 运行测试并确认缺少脚本而失败**

Run: `bash 'config/speed加速服务/tests/deploy_test.sh'`

Expected: FAIL，报告 `deploy.sh` 不存在。

- [ ] **Step 3: 实现参数解析和源文件校验**

`deploy.sh` 使用 `set -euo pipefail`，通过 `while (($#)); do case "$1" in ... esac; done` 解析参数。真实根目录要求 `EUID=0`；`--root` 使用指定目录且不得配合 `--enable-now`。组件展开为 Bash 数组，二进制必须是非空普通文件且可执行。

- [ ] **Step 4: 扩充安装行为测试并确认失败**

向 fixture 的 `bin/` 写入三个可执行假二进制，断言：dry-run 不写文件；单组件只安装对应文件；all 安装全部；client/server 选择正确；模式为二进制/脚本 `755`、敏感实例配置 `600`、unit/网络配置 `644`；覆盖时生成 `.bak.<UTC时间戳>`；重复部署成功。

- [ ] **Step 5: 实现安装、备份与 systemd 行为**

实现函数：

```bash
destination() { printf '%s%s' "$ROOT_DIR" "$1"; }
install_one() {
  local source=$1 target=$2 mode=$3 target_dir
  target_dir=$(dirname "$target")
  if (( DRY_RUN )); then printf '将安装 %s -> %s (mode %s)\n' "$source" "$target" "$mode"; return; fi
  mkdir -p "$target_dir"
  [[ ! -e "$target" ]] || cp -p "$target" "$target.bak.$TIMESTAMP"
  install -m "$mode" "$source" "$target"
}
```

tinyvpn 安装二进制、network.conf、update-hosts.sh 和所选角色 unit；speeder2/udp2raw 安装二进制、模板 unit 和所选角色目录全部非空 `.conf`。真实根目录调用 `systemctl daemon-reload`；只有 `--enable-now` 调用 `systemctl enable --now`，实例名来自配置文件 basename。

- [ ] **Step 6: 运行部署测试与语法检查**

Run: `bash -n 'config/speed加速服务/deploy.sh' && bash 'config/speed加速服务/tests/deploy_test.sh'`

Expected: `PASS: deploy argument validation`、`PASS: deploy dry-run`、`PASS: deploy installation and backup`。

- [ ] **Step 7: 提交**

```bash
git add 'config/speed加速服务/deploy.sh' 'config/speed加速服务/tests/deploy_test.sh' 'config/speed加速服务/bin/README.md'
git commit -m 'feat: add speed service deployment script'
```

### Task 4: 运维文档与最终验收

**Files:**
- Create: `config/speed加速服务/README.md`
- Modify: `config/speed加速服务/tests/config_test.sh`

**Interfaces:**
- Consumes: 已实现的部署接口和最终端口配置。
- Produces: 下载、配置、部署、验证、排错和回滚说明。

- [ ] **Step 1: 写文档存在性测试**

断言 README 包含三个上游 URL、`--role`、`--component`、`--dry-run`、`--enable-now`、端口 `24096`/`44101`/`21180`、tinyfecVPN 预编译服务端限制、密钥轮换、`udp2raw -a`、`systemctl status`、`journalctl`、回滚说明。

- [ ] **Step 2: 运行测试并确认 README 缺失而失败**

Run: `bash 'config/speed加速服务/tests/config_test.sh'`

Expected: FAIL，报告缺少目录 README。

- [ ] **Step 3: 编写 README**

README 给出：组件说明；三条客户端到服务端链路；二进制表；部署前 IP/端口/密钥/子网/域名检查；client/server/all 示例；默认仅安装与显式启动差异；防火墙、安全组和 `-a` 风险；状态、日志、unit 验证和 `.bak` 回滚命令。

- [ ] **Step 4: 运行全套验证**

Run:

```bash
bash -n 'config/speed加速服务/deploy.sh' \
  'config/speed加速服务/tinyvpn/update-hosts.sh' \
  'config/speed加速服务/tests/config_test.sh' \
  'config/speed加速服务/tests/deploy_test.sh'
bash 'config/speed加速服务/tests/config_test.sh'
bash 'config/speed加速服务/tests/deploy_test.sh'
git diff --check
```

Expected: 所有语法检查和测试退出码为 0，`git diff --check` 无输出。

- [ ] **Step 5: 运行可选检查**

Run: 若 `shellcheck` 存在则检查四个 shell 文件；若 `systemd-analyze` 存在则验证三个 unit，否则明确记录因当前环境缺少工具而跳过。

- [ ] **Step 6: 检查范围并提交**

```bash
git status --short
git diff --stat
git add 'config/speed加速服务/README.md' 'config/speed加速服务/tests/config_test.sh'
git commit -m 'docs: document speed service deployment'
```

# Speed 加速服务部署设计

## 目标

整理 `config/speed加速服务` 下的 tinyfecVPN、UDPspeeder 和 udp2raw 配置，为现有文件补充中文备注，修正客户端与服务端角色配置，并提供一个可重复执行、默认不启动服务的部署脚本。

部署目标是使用 systemd 的 Linux amd64 主机。部署过程不联网下载二进制；用户从项目官方发布页下载后，将文件放入仓库内的 `bin/` 目录。

## 范围

本次包含：

- 为 tinyvpn、speeder2、udp2raw 的配置与 systemd unit 补充中文备注。
- 修正错误的 `-c`、`-s`、监听地址、转发方向和 unit 描述。
- 将文件名末尾带空格的 `speederv2@.service ` 规范为 `speederv2@.service`。
- 新建 `bin/` 目录说明，约定三个 amd64 二进制的名称。
- 保留并增强 tinyvpn 的 `network.conf` 和 `update-hosts.sh`。
- 新建统一部署脚本和自动化测试。
- 新建目录级 README，记录链路、端口、部署和排错方式。

本次不包含：

- 自动下载或更新上游二进制。
- 自动配置防火墙、安全组、WireGuard 或业务 VPN。
- 自动探测公网 IP、网卡名或改变现有端口与密钥。
- 在没有显式传入 `--enable-now` 时启动或启用服务。

## 上游二进制

`bin/` 使用以下标准文件名：

| 组件 | 仓库 | 本地文件名 |
| --- | --- | --- |
| tinyfecVPN | `https://github.com/wangyu-/tinyfecVPN/releases` | `tinyvpn_amd64` |
| UDPspeeder | `https://github.com/wangyu-/UDPspeeder/releases` | `speederv2_amd64` |
| udp2raw | `https://github.com/wangyu-/udp2raw-tunnel/releases` | `udp2raw_amd64` |

README 必须提醒：tinyfecVPN 上游说明预编译服务端二进制带有使用限制；若使用场景受影响，需要按上游说明自行编译服务端，而不是由部署脚本规避限制。

## 目录与安装布局

仓库布局：

```text
config/speed加速服务/
├── README.md
├── deploy.sh
├── bin/
│   └── README.md
├── tests/
│   └── deploy_test.sh
├── tinyvpn/
│   ├── network.conf
│   ├── update-hosts.sh
│   ├── client/tinyvpn.service
│   └── server/tinyvpn.service
├── speeder2/
│   ├── speederv2@.service
│   ├── client/*.conf
│   └── server/*.conf
└── udp2raw/
    ├── udp2raw@.service
    ├── client/*.conf
    └── server/*.conf
```

目标主机布局：

- 二进制：`/usr/local/bin/{tinyvpn_amd64,speederv2_amd64,udp2raw_amd64}`，模式 `0755`。
- tinyvpn 配置：`/etc/tinyvpn/network.conf`。
- tinyvpn 辅助脚本：`/etc/tinyvpn/update-hosts.sh`，模式 `0755`。
- speeder2 实例配置：`/etc/speederv2/*.conf`。
- udp2raw 实例配置：`/etc/udp2raw/*.conf`。
- systemd unit：`/etc/systemd/system/*.service`。

systemd unit 使用上述固定安装路径，不再依赖 `/root/tinyvpn` 或 `/home/wenjigang/*`。

## 网络链路和角色修正

配置中的现有公网地址、端口、密钥、FEC 和 MTU 数值原则上保留；只修正可以由上下游连接关系明确判断的角色与方向。每个配置文件都要在 `OPTS` 前用中文解释本机监听、远端目标和关键参数。

### tinyvpn 与 udp2raw

客户端链路：

```text
tinyvpn client -> 127.0.0.1:44096 -> udp2raw client -> 服务端公网地址:24096
```

服务端链路：

```text
udp2raw server 监听 0.0.0.0:24096 -> 127.0.0.1:44096 -> tinyvpn server
```

因此 tinyvpn 客户端使用 `-c -r127.0.0.1:44096`；服务端使用 `-s -l127.0.0.1:44096`。udp2raw 客户端使用 `-c`，服务端使用 `-s`。

tinyvpn 两端都从 `/etc/tinyvpn/network.conf` 读取 `SUBNET`。只有客户端 unit 使用 `ExecStartPre=/etc/tinyvpn/update-hosts.sh`；服务端不得修改 `/etc/hosts`。

### speeder2 与 udp2raw

客户端的 UDPspeeder 接收本地业务流量并转发给本地 udp2raw；udp2raw 再连接服务端公网端口。服务端 udp2raw 将还原后的 UDP 流量转发给本地 UDPspeeder，UDPspeeder 再转发给服务端本地业务端口。

- UDPspeeder 客户端必须使用 `-c`。
- UDPspeeder 服务端必须使用 `-s`。
- udp2raw 的 `uspdwg_sg2gz` 客户端必须使用 `-c`。
- udp2raw 的 `uspdwg_sg2gz` 服务端必须使用 `-s`。

如现有数值造成同一协议、同一地址和端口的实际监听冲突，README 将其列为部署前检查项；部署脚本不擅自修改业务端口。

### WireGuard 与 udp2raw

补全当前为空的客户端 `wireguard.conf`：客户端在环回地址监听 WireGuard 发来的 UDP，并连接服务端公网 raw 端口；服务端监听公网 raw 端口，并把还原后的 UDP 转发到本机 WireGuard 监听地址。两端使用相同密钥、raw 模式和加密方式。

## tinyvpn hosts 更新脚本

`update-hosts.sh` 负责从 `SUBNET` 推导服务端隧道地址，并更新 `/etc/hosts` 中 `tinyvpn.host.com` 的唯一映射。

脚本要求：

- 使用 Bash 严格模式，任何读取或写入失败均以非零状态退出。
- 默认读取 `/etc/tinyvpn/network.conf`，缺失时给出明确错误；测试可通过 `TINYVPN_CONFIG_FILE` 指向临时配置。
- 接受且只接受规范 IPv4 `/24` 网络地址形式，例如 `10.44.44.0`。
- 推导网关地址为同一网段的 `.1`。
- 删除已有的同域名映射后追加一条新映射，多次运行结果一致。
- 默认使用临时文件和原子替换更新 `/etc/hosts`，失败时不留下半写文件；测试可通过 `TINYVPN_HOSTS_FILE` 指向临时 hosts 文件。
- 仅由 tinyvpn 客户端 unit 调用。

## 部署脚本接口

主命令格式：

```text
./deploy.sh --role client|server --component tinyvpn|speeder2|udp2raw|all [--dry-run] [--enable-now] [--root DIR]
```

参数行为：

- `--role` 必填，选择客户端或服务端配置。
- `--component` 必填，可选择单个组件或 `all`。
- `--dry-run` 只打印将执行的目录创建、安装、备份、daemon-reload 和启用动作，不写文件。
- `--enable-now` 安装后执行 `systemctl daemon-reload`，并启用、立即启动本次部署对应的 unit/实例；不传时只执行 `daemon-reload`。
- `--root DIR` 用于测试或离线构建，将目标路径前置到指定根目录；该模式不得调用目标根目录外的 systemctl。
- `--root` 与 `--enable-now` 不得同时使用，组合使用时脚本必须报错退出。
- `--help` 输出用法并成功退出。

部署流程：

1. 校验运行环境、参数、角色、组件和所需源文件。
2. 校验选定组件的二进制存在、是普通文件且具有可执行权限；缺失时提示对应上游发布页和目标文件名。
3. 校验将部署配置中不存在未解析占位符。
4. 创建目标目录。
5. 覆盖已有文件前，将其备份为同目录下带 UTC 时间戳的 `.bak` 文件。
6. 使用明确权限安装二进制、脚本、配置和 unit。
7. 真实根目录部署时执行 `systemctl daemon-reload`。
8. 仅在传入 `--enable-now` 时启用并启动相应服务。

脚本必须使用 `set -euo pipefail`，错误信息写入标准错误并返回非零状态。重复部署相同内容可以安全执行。

## systemd 行为

- unit 在网络在线后启动，并保持自动重启策略。
- `ExecStart` 使用 `/usr/local/bin` 下的二进制。
- tinyvpn 客户端和服务端使用独立 unit 文件，以表达不同启动参数和 `ExecStartPre` 行为。
- speeder2、udp2raw 继续使用模板 unit，通过 `%i` 加载实例配置。
- unit 内只保留适合 systemd 解析的注释，不把 shell 专属语法误用于 `ExecStart`。
- 安装前对 unit 做静态结构校验；目标机存在 `systemd-analyze` 时，README 提供 `systemd-analyze verify` 验证命令。

## 备注与文档

中文备注重点解释“为什么”和部署关系，不逐字翻译显而易见的 systemd 字段。README 包含：

- 三组件用途和组合链路。
- 端口流向表和客户端/服务端配对关系。
- 二进制下载地址、命名与放置方式。
- `deploy.sh` 示例。
- 修改公网 IP、端口、密钥、子网和域名的位置。
- tinyfecVPN 预编译服务端限制。
- 防火墙、安全组、root/capability 风险说明。
- `systemctl status`、`journalctl`、`systemd-analyze verify` 等排错命令。

## 测试与验收

部署脚本使用独立 Bash 测试，通过临时 `--root` 验证真实文件结果，不修改宿主机的 `/etc` 或调用真实 systemctl。至少覆盖：

- `--help` 成功。
- 缺少必填参数、非法角色、非法组件失败。
- 缺少或不可执行二进制时失败并指出文件名。
- client/server 只安装对应角色配置。
- 单组件和 `all` 安装内容正确、权限正确。
- `--dry-run` 不产生文件。
- 已有目标文件会备份，重复部署可成功。
- tinyvpn 客户端安装 hosts 更新脚本并引用它；服务端 unit 不引用它。
- hosts 更新脚本拒绝非法 `SUBNET`，对合法子网生成唯一映射，重复运行无重复项。
- 三组 unit 指向 `/usr/local/bin` 和正确配置目录。

最终验收命令包括：

- `bash -n` 检查所有新增或修改的 shell 脚本。
- 执行完整 Bash 测试套件并确认零失败。
- 若环境已安装 ShellCheck，则检查所有 shell 脚本；未安装时明确报告跳过。
- 若环境可用 `systemd-analyze verify`，对 unit 做验证；macOS 开发机缺少该命令时明确报告，并保留 Linux 目标机验证步骤。
- 检查 Git diff，确认不包含二进制文件、临时文件或无关改动。

## 安全与回滚

- 配置中现有密钥继续按用户现状保留，但 README 明确建议部署前轮换，并避免提交真实生产密钥。
- `udp2raw -a` 可能修改防火墙规则，README 必须提示其权限和影响。
- 部署脚本不操作云安全组或远程主机。
- 配置覆盖前生成备份；回滚时恢复对应 `.bak` 文件，执行 `systemctl daemon-reload` 后重启相关服务。

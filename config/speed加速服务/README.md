# Speed 加速服务配置与部署

本目录管理 tinyfecVPN、UDPspeeder 和 udp2raw 的客户端/服务端配置。目标系统是使用 systemd 的 Linux amd64 主机；部署脚本只安装本地文件，不会联网下载程序，也不会自动修改云安全组、WireGuard 或业务 VPN。

## 组件与链路

- tinyfecVPN：建立带 FEC 的三层隧道，本配置使用 `tun10` 和 `10.44.44.0/24`。
- UDPspeeder：为 UDP 业务增加 FEC；当前 `spdwg_sg2gz` 实例与 udp2raw 配合。
- udp2raw：把 UDP 封装成 faketcp raw 流量，避开部分 UDP 限速或不稳定链路。

端口方向如下：

| 用途 | 客户端 | 服务端公网入口 | 服务端本地目标 |
| --- | --- | --- | --- |
| tinyfecVPN + udp2raw | tinyvpn → `127.0.0.1:44096` | udp2raw `0.0.0.0:24096` | tinyvpn `127.0.0.1:44096` |
| UDPspeeder + udp2raw | 业务 `127.0.0.1:44001` → speeder → udp2raw `127.0.0.1:44101` | udp2raw `0.0.0.0:44101` | speeder `127.0.0.1:44101` → 业务 `127.0.0.1:44001` |
| WireGuard + udp2raw | WireGuard → udp2raw `127.0.0.1:22180` | udp2raw `0.0.0.0:21180` | WireGuard `127.0.0.1:22180` |

服务端 udp2raw 的 raw faketcp 端口和本机 UDP 端口即使数字相同，也属于不同协议。仍应在部署前用 `ss -lntup` 检查是否与其他进程冲突。

## 准备二进制

从上游发布页下载 Linux amd64 版本，解压并放入 `bin/`：

| 组件 | 发布页 | 本地名称 |
| --- | --- | --- |
| tinyfecVPN | <https://github.com/wangyu-/tinyfecVPN/releases> | `bin/tinyvpn_amd64` |
| UDPspeeder | <https://github.com/wangyu-/UDPspeeder/releases> | `bin/speederv2_amd64` |
| udp2raw | <https://github.com/wangyu-/udp2raw-tunnel/releases> | `bin/udp2raw_amd64` |

```bash
chmod +x bin/tinyvpn_amd64 bin/speederv2_amd64 bin/udp2raw_amd64
```

注意：tinyfecVPN 上游说明其预编译服务端二进制带有使用限制。如果你的用途受限，应按照上游文档自行编译服务端；部署脚本不会规避该限制。

## 部署前检查

1. 在 `udp2raw/client/*.conf` 中把 `47.245.124.39` 确认或改为实际服务端公网 IP。
2. 确认两端对应配置的端口、`-k` 密钥、raw 模式、加密方式、FEC 和 MTU 完全匹配。
3. 确认 `tinyvpn/network.conf` 的 `SUBNET` 未与现有局域网、容器或 VPN 网段冲突。
4. 如需更换 `tinyvpn.host.com`，同时修改 `tinyvpn/update-hosts.sh` 中的 `DOMAIN`。
5. 当前文件含示例/现有密钥。生产部署前应轮换密钥，并避免把真实生产密钥提交到公开仓库。
6. 放行服务端公网入口 `24096`、`44101`、`21180` 所需的 faketcp 流量，并检查云安全组和主机防火墙。

`udp2raw -a` 会以高权限自动添加和删除 iptables 规则。使用 nftables 或自定义防火墙策略时，应先确认兼容性；如改为手工规则，需要按上游文档移除 `-a` 并自行维护规则。

## 使用部署脚本

脚本接口：

```text
./deploy.sh --role client|server --component tinyvpn|speeder2|udp2raw|all [--dry-run] [--enable-now] [--root DIR]
```

先检查客户端全部组件将执行的动作：

```bash
sudo ./deploy.sh --role client --component all --dry-run
```

只安装服务端 udp2raw：

```bash
sudo ./deploy.sh --role server --component udp2raw
```

安装并立即启用客户端全部服务：

```bash
sudo ./deploy.sh --role client --component all --enable-now
```

默认行为是安装文件并执行 `systemctl daemon-reload`，不会启用或启动服务。只有显式传入 `--enable-now` 才会执行 `systemctl enable --now`。

`--root DIR` 把所有目标路径放到指定目录中，适合离线构建和测试。它不会调用 systemctl，且不能与 `--enable-now` 同用：

```bash
./deploy.sh --role server --component all --root /tmp/speed-root
```

安装位置：

- 二进制：`/usr/local/bin/`
- tinyvpn 配置和辅助脚本：`/etc/tinyvpn/`
- UDPspeeder 实例配置：`/etc/speederv2/`
- udp2raw 实例配置：`/etc/udp2raw/`
- systemd unit：`/etc/systemd/system/`

## 启动与排错

按实际部署的组件检查 unit：

```bash
systemd-analyze verify /etc/systemd/system/tinyvpn.service
systemd-analyze verify /etc/systemd/system/speederv2@.service
systemd-analyze verify /etc/systemd/system/udp2raw@.service
```

常用状态与日志命令：

```bash
systemctl status tinyvpn.service
systemctl status speederv2@spdwg_sg2gz.service
systemctl status udp2raw@tinyvpn.service
journalctl -u tinyvpn.service -n 100 --no-pager
journalctl -u speederv2@spdwg_sg2gz.service -n 100 --no-pager
journalctl -u udp2raw@tinyvpn.service -n 100 --no-pager
```

tinyvpn 客户端启动前会运行 `/etc/tinyvpn/update-hosts.sh`，将 `tinyvpn.host.com` 指向 `SUBNET` 网段的 `.1`。服务端不会修改 `/etc/hosts`。如果客户端启动失败，优先检查：

```bash
/etc/tinyvpn/update-hosts.sh
grep tinyvpn.host.com /etc/hosts
ip address show tun10
```

## 备份与回滚

部署脚本覆盖已有目标文件前，会在同一目录生成 `原文件.bak.<UTC时间戳>`。回滚时停止相关服务、恢复需要的备份并重新加载 unit，例如：

```bash
sudo systemctl stop tinyvpn.service
sudo cp -p /etc/systemd/system/tinyvpn.service.bak.20260715T120000Z /etc/systemd/system/tinyvpn.service
sudo cp -p /etc/tinyvpn/network.conf.bak.20260715T120000Z /etc/tinyvpn/network.conf
sudo systemctl daemon-reload
sudo systemctl restart tinyvpn.service
```

将示例时间戳替换为实际备份文件名。二进制和实例配置也采用相同的备份命名规则。

## 本地验证

不需要 root，也不会接触宿主机 `/etc`：

```bash
bash tests/config_test.sh
bash tests/deploy_test.sh
```

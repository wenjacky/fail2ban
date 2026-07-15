# amd64 二进制目录

请从上游发布页下载 Linux amd64 版本，解压后按下列名称放在本目录，并赋予可执行权限：

| 组件 | 上游发布页 | 文件名 |
| --- | --- | --- |
| tinyfecVPN | <https://github.com/wangyu-/tinyfecVPN/releases> | `tinyvpn_amd64` |
| UDPspeeder | <https://github.com/wangyu-/UDPspeeder/releases> | `speederv2_amd64` |
| udp2raw | <https://github.com/wangyu-/udp2raw-tunnel/releases> | `udp2raw_amd64` |

```bash
chmod +x bin/tinyvpn_amd64 bin/speederv2_amd64 bin/udp2raw_amd64
```

本目录不提交实际二进制。部署脚本不会联网下载或自动更新它们。

tinyfecVPN 上游说明预编译服务端带有使用限制；若受影响，请按上游文档自行编译服务端二进制。

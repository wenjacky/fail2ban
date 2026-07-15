#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROLE=
COMPONENT=
ROOT_DIR=
ROOT_SET=0
DRY_RUN=0
ENABLE_NOW=0
TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
SERVICES=()

usage() {
  cat <<'EOF'
用法:
  ./deploy.sh --role client|server --component tinyvpn|speeder2|udp2raw|all [选项]

选项:
  --root DIR       把目标路径安装到 DIR 下，用于测试或离线构建
  --dry-run        只显示动作，不写文件、不调用 systemctl
  --enable-now     安装后启用并立即启动服务（不能与 --root 同用）
  -h, --help       显示帮助
EOF
}

die() {
  printf '错误: %s\n' "$*" >&2
  exit 1
}

need_value() {
  [[ $# -ge 2 && -n ${2:-} ]] || die "$1 需要一个值"
}

while (($# > 0)); do
  case $1 in
    --role)
      need_value "$@"
      ROLE=$2
      shift 2
      ;;
    --component)
      need_value "$@"
      COMPONENT=$2
      shift 2
      ;;
    --root)
      need_value "$@"
      ROOT_DIR=${2%/}
      [[ -n $ROOT_DIR ]] || ROOT_DIR=/
      ROOT_SET=1
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --enable-now)
      ENABLE_NOW=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "未知参数: $1（使用 --help 查看用法）"
      ;;
  esac
done

[[ $ROLE == client || $ROLE == server ]] || die '必须用 --role 指定 client 或 server'
case $COMPONENT in
  tinyvpn|speeder2|udp2raw|all) ;;
  '') die '必须用 --component 指定组件' ;;
  *) die "不支持的组件: $COMPONENT" ;;
esac
(( ROOT_SET == 0 || ENABLE_NOW == 0 )) || die '--root 不能与 --enable-now 同时使用'

if (( ROOT_SET == 0 && DRY_RUN == 0 && EUID != 0 )); then
  die '安装到真实系统目录需要 root 权限；可先使用 --dry-run 检查'
fi

COMPONENTS=()
if [[ $COMPONENT == all ]]; then
  COMPONENTS=(tinyvpn speeder2 udp2raw)
else
  COMPONENTS=("$COMPONENT")
fi

binary_name() {
  case $1 in
    tinyvpn) printf '%s\n' tinyvpn_amd64 ;;
    speeder2) printf '%s\n' speederv2_amd64 ;;
    udp2raw) printf '%s\n' udp2raw_amd64 ;;
  esac
}

upstream_url() {
  case $1 in
    tinyvpn) printf '%s\n' 'https://github.com/wangyu-/tinyfecVPN/releases' ;;
    speeder2) printf '%s\n' 'https://github.com/wangyu-/UDPspeeder/releases' ;;
    udp2raw) printf '%s\n' 'https://github.com/wangyu-/udp2raw-tunnel/releases' ;;
  esac
}

require_file() {
  local file=$1 description=$2
  [[ -f $file && -s $file ]] || die "缺少或为空的${description}: $file"
}

validate_sources() {
  local component binary config
  local configs=()
  shopt -s nullglob
  for component in "${COMPONENTS[@]}"; do
    binary=$(binary_name "$component")
    require_file "$SCRIPT_DIR/bin/$binary" '二进制文件'
    [[ -x $SCRIPT_DIR/bin/$binary ]] || die "二进制不可执行: $SCRIPT_DIR/bin/$binary；请运行 chmod +x，来源: $(upstream_url "$component")"

    case $component in
      tinyvpn)
        require_file "$SCRIPT_DIR/tinyvpn/network.conf" '配置文件'
        require_file "$SCRIPT_DIR/tinyvpn/update-hosts.sh" '辅助脚本'
        require_file "$SCRIPT_DIR/tinyvpn/$ROLE/tinyvpn.service" 'systemd unit'
        configs=("$SCRIPT_DIR/tinyvpn/network.conf")
        ;;
      speeder2)
        require_file "$SCRIPT_DIR/speeder2/speederv2@.service" 'systemd unit'
        configs=("$SCRIPT_DIR/speeder2/$ROLE/"*.conf)
        ((${#configs[@]} > 0)) || die "没有找到 speeder2 $ROLE 配置"
        ;;
      udp2raw)
        require_file "$SCRIPT_DIR/udp2raw/udp2raw@.service" 'systemd unit'
        configs=("$SCRIPT_DIR/udp2raw/$ROLE/"*.conf)
        ((${#configs[@]} > 0)) || die "没有找到 udp2raw $ROLE 配置"
        ;;
    esac

    for config in "${configs[@]}"; do
      require_file "$config" '配置文件'
      if grep -Eq '@@[A-Z0-9_]+@@|\{\{[A-Z0-9_]+\}\}' "$config"; then
        die "配置含未解析占位符: $config"
      fi
    done
  done
  shopt -u nullglob
}

destination() {
  local path=$1
  if (( ROOT_SET )); then
    if [[ $ROOT_DIR == / ]]; then
      printf '%s\n' "$path"
    else
      printf '%s%s\n' "$ROOT_DIR" "$path"
    fi
  else
    printf '%s\n' "$path"
  fi
}

install_one() {
  local source=$1 target=$2 mode=$3 target_dir backup suffix
  if (( DRY_RUN )); then
    printf '将安装 %s -> %s (mode %s)\n' "$source" "$target" "$mode"
    return
  fi

  target_dir=$(dirname -- "$target")
  mkdir -p "$target_dir"
  if [[ -e $target ]]; then
    backup="$target.bak.$TIMESTAMP"
    suffix=1
    while [[ -e $backup ]]; do
      backup="$target.bak.$TIMESTAMP.$suffix"
      ((suffix += 1))
    done
    cp -p "$target" "$backup"
    printf '已备份 %s -> %s\n' "$target" "$backup"
  fi
  install -m "$mode" "$source" "$target"
  printf '已安装 %s\n' "$target"
}

install_tinyvpn() {
  install_one "$SCRIPT_DIR/bin/tinyvpn_amd64" "$(destination /usr/local/bin/tinyvpn_amd64)" 0755
  install_one "$SCRIPT_DIR/tinyvpn/network.conf" "$(destination /etc/tinyvpn/network.conf)" 0644
  install_one "$SCRIPT_DIR/tinyvpn/update-hosts.sh" "$(destination /etc/tinyvpn/update-hosts.sh)" 0755
  install_one "$SCRIPT_DIR/tinyvpn/$ROLE/tinyvpn.service" "$(destination /etc/systemd/system/tinyvpn.service)" 0644
  SERVICES+=(tinyvpn.service)
}

install_speeder2() {
  local config name
  local configs=("$SCRIPT_DIR/speeder2/$ROLE/"*.conf)
  install_one "$SCRIPT_DIR/bin/speederv2_amd64" "$(destination /usr/local/bin/speederv2_amd64)" 0755
  install_one "$SCRIPT_DIR/speeder2/speederv2@.service" "$(destination /etc/systemd/system/speederv2@.service)" 0644
  for config in "${configs[@]}"; do
    name=$(basename -- "$config" .conf)
    install_one "$config" "$(destination "/etc/speederv2/$name.conf")" 0600
    SERVICES+=("speederv2@$name.service")
  done
}

install_udp2raw() {
  local config name
  local configs=("$SCRIPT_DIR/udp2raw/$ROLE/"*.conf)
  install_one "$SCRIPT_DIR/bin/udp2raw_amd64" "$(destination /usr/local/bin/udp2raw_amd64)" 0755
  install_one "$SCRIPT_DIR/udp2raw/udp2raw@.service" "$(destination /etc/systemd/system/udp2raw@.service)" 0644
  for config in "${configs[@]}"; do
    name=$(basename -- "$config" .conf)
    install_one "$config" "$(destination "/etc/udp2raw/$name.conf")" 0600
    SERVICES+=("udp2raw@$name.service")
  done
}

validate_sources
for component in "${COMPONENTS[@]}"; do
  case $component in
    tinyvpn) install_tinyvpn ;;
    speeder2) install_speeder2 ;;
    udp2raw) install_udp2raw ;;
  esac
done

if (( ROOT_SET == 0 )); then
  if (( DRY_RUN )); then
    printf '将执行 systemctl daemon-reload\n'
    if (( ENABLE_NOW )); then
      printf '将执行 systemctl enable --now'
      printf ' %s' "${SERVICES[@]}"
      printf '\n'
    fi
  else
    systemctl daemon-reload
    if (( ENABLE_NOW )); then
      systemctl enable --now "${SERVICES[@]}"
    fi
  fi
fi

if (( ENABLE_NOW )); then
  printf '部署完成，已启用并启动所选服务。\n'
else
  printf '部署完成，服务尚未启用或启动。\n'
fi

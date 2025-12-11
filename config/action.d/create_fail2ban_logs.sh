#!/bin/bash
# 功能：自动创建fail2ban配置中logpath指定的日志文件（含目录创建）
# 适配文件：/etc/fail2ban/jail.d/v2ray.local

# 定义配置文件路径
JAIL_CONF="/etc/fail2ban/jail.d/v2ray.local"

# 检查配置文件是否存在
if [ ! -f "${JAIL_CONF}" ]; then
    echo "错误：配置文件 ${JAIL_CONF} 不存在！"
    exit 1
fi

# 提取所有logpath行并去重，过滤空行和注释行
LOG_PATHS=$(grep -E "^[[:space:]]*logpath" "${JAIL_CONF}" | \
            sed -e 's/^[[:space:]]*logpath[[:space:]]*=[[:space:]]*//' -e 's/[[:space:]]*$//' | \
            tr ' ' '\n' | \
            grep -v "^$" | \
            sort -u)

# 遍历每个日志路径
for LOG_FILE in ${LOG_PATHS}; do
    # 提取日志文件的目录路径
    LOG_DIR=$(dirname "${LOG_FILE}")
    
    # 1. 创建日志目录（若不存在）
    if [ ! -d "${LOG_DIR}" ]; then
        echo "创建目录：${LOG_DIR}"
        mkdir -p "${LOG_DIR}"
        # 设置目录权限（与系统日志目录一致）
        chmod 755 "${LOG_DIR}"
        chown root:root "${LOG_DIR}"
    fi

    # 2. 创建空日志文件（若不存在）
    if [ ! -f "${LOG_FILE}" ]; then
        echo "创建空文件：${LOG_FILE}"
        touch "${LOG_FILE}"
        # 设置文件权限（与系统日志文件一致）
        chmod 640 "${LOG_FILE}"
        chown root:adm "${LOG_FILE}"
    fi
done

echo "所有日志文件/目录创建完成！"
exit 0

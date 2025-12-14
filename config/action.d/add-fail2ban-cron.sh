#!/bin/bash
# add-fail2ban-cron.sh

# 定义任务和它们的标识符
declare -A CRON_TASKS=(
    ["ban-notify-10min"]="*/10 * * * * cat /var/log/fail2ban/ban-actions.log | /usr/local/bin/nali > /tmp/test.log && /usr/bin/python3 /etc/fail2ban/action.d/dingding-geo.py --logfile /tmp/test.log --hours 0.1667"
    ["ban-notify-daily"]="4 3 * * * cat /var/log/fail2ban/ban-actions.log | /usr/local/bin/nali > /tmp/test.log && /usr/bin/python3 /etc/fail2ban/action.d/dingding-geo.py --logfile /tmp/test.log --daily"
    ["ssh-login-notify-10min"]="*/10 * * * * cat /var/log/fail2ban/ssh-login-monitor.log | /usr/local/bin/nali > /tmp/testlogin.log && /usr/bin/python3 ssh-login-notify.py --logfile /tmp/testlogin.log --hours 0.1667"
    ["ssh-login-notify-daily"]="4 2 * * * cat /var/log/fail2ban/ssh-login-monitor.log | /usr/local/bin/nali > /tmp/testlogin.log && /usr/bin/python3 ssh-login-notify.py --logfile /tmp/testlogin.log --daily"
)

# 检查依赖项
check_dependencies() {
    local error=0

    if [ ! -x "/usr/local/bin/nali" ]; then
        echo "错误: /usr/local/bin/nali 不存在或不可执行" >&2
        error=1
    fi

    if [ ! -f "/etc/fail2ban/action.d/dingding-geo.py" ]; then
        echo "错误: /etc/fail2ban/action.d/dingding-geo.py 不存在" >&2
        error=1
    else
        # 检查Python脚本是否有执行权限
        if [ ! -x "/etc/fail2ban/action.d/dingding-geo.py" ]; then
            echo "警告: /etc/fail2ban/action.d/dingding-geo.py 不可执行，尝试修复权限" >&2
            chmod +x "/etc/fail2ban/action.d/dingding-geo.py" 2>/dev/null || true
        fi
    fi

    if [ ! -f "/var/log/fail2ban/ban-actions.log" ]; then
        echo "警告: /var/log/fail2ban/ban-actions.log 不存在" >&2
        echo "提示: 确保fail2ban已配置记录ban-actions.log" >&2
    fi

    if [ $error -eq 1 ]; then
        exit 1
    fi
}

# 添加或更新cron任务
setup_cron_tasks() {
    # 获取当前crontab
    local current_crontab
    current_crontab=$(crontab -l 2>/dev/null || echo "# Crontab")

    local updated=false

    # 为每个任务添加或更新
    for task_id in "${!CRON_TASKS[@]}"; do
        local task_cmd="${CRON_TASKS[$task_id]}"

        # 检查是否已存在（通过标识符或命令内容）
        if echo "$current_crontab" | grep -q "# $task_id"; then
            # 移除旧的任务（包括注释）
            current_crontab=$(echo "$current_crontab" | sed "/# $task_id/,/# end $task_id/d")
            echo "更新任务: $task_id"
        elif echo "$current_crontab" | grep -Fq "$task_cmd"; then
            # 如果存在相同的命令但没有标识符，也移除
            echo "发现未标记的相同任务，重新添加: $task_id"
            # 删除包含该命令的行
            current_crontab=$(echo "$current_crontab" | grep -vF "$task_cmd")
        else
            echo "添加新任务: $task_id"
        fi

        # 添加带注释的任务
        current_crontab="${current_crontab}"$'\n'"# $task_id"$'\n'"$task_cmd"$'\n'"# end $task_id"
        updated=true
    done

    # 如果有更新，写入crontab
    if [ "$updated" = true ]; then
        echo "$current_crontab" | crontab -

        if [ $? -eq 0 ]; then
            echo "✓ Crontab已成功更新"
        else
            echo "错误: 无法更新crontab" >&2
            exit 1
        fi
    else
        echo "✓ 没有需要更新的任务"
    fi
}

# 显示结果
show_result() {
    echo -e "\n当前fail2ban监控任务:"
    echo "================================"
    crontab -l | grep -B1 -A1 "fail2ban-" | while read line; do
        if [[ "$line" == "#"* ]]; then
            echo "$line"
        elif [[ "$line" == *"nali"* ]] || [[ "$line" == *"dingding-geo"* ]]; then
            echo "  $line"
        fi
    done

    echo -e "\n下次执行时间参考:"
    echo "================================"
    # 简单显示cron时间说明
    echo "• 每10分钟执行一次（检查过去10分钟内的封禁）"
    echo "• 每天09:00执行一次（每日汇总报告）"
}

# 主函数
main() {
    echo "设置fail2ban钉钉通知cron任务..."
    echo "================================"

    # 检查依赖
    check_dependencies

    # 设置cron任务
    setup_cron_tasks

    # 显示结果
    show_result

    echo -e "\n✓ 设置完成"
}

# 如果脚本被直接执行，调用main函数
if [[ "${BASH_SOURCE[0]}" = "${0}" ]]; then
    main
fi
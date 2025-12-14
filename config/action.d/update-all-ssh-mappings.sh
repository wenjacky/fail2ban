#!/bin/bash
# 为所有有authorized_keys的用户生成映射表（处理重复key）

MAP_FILE="/etc/fail2ban/ssh-key-mappings.txt"
TEMP_FILE="/tmp/ssh-mappings.tmp"

> "$TEMP_FILE"

# 使用关联数组记录已处理的指纹
declare -A processed_fingerprints

# 遍历所有有authorized_keys的用户
getent passwd | while IFS=: read -r username _ uid gid _ home shell; do
    # 跳过系统用户和无效home目录（可根据需要调整）
    if ([ $uid -ge 1000 ] || [ $uid -eq 0 ]) && [ -d "$home" ]; then
        AUTH_KEYS="$home/.ssh/authorized_keys"
        if [ -f "$AUTH_KEYS" ]; then
            echo "处理用户 $username 的authorized_keys..."

            line_num=0
            while IFS= read -r line; do
                line_num=$((line_num + 1))
                # 跳过空行和注释
                line=$(echo "$line" | sed 's/#.*//' | xargs)
                if [ -n "$line" ]; then
                    key_type=$(echo "$line" | awk '{print $1}')
                    key_data=$(echo "$line" | awk '{print $2}')
                    comment=$(echo "$line" | cut -d' ' -f3-)
                    [ -z "$comment" ] && comment="no-comment"

                    if [ -n "$key_data" ]; then
                        # 生成指纹
                        fingerprint=$(echo "$key_type $key_data" | ssh-keygen -l -f /dev/stdin 2>&1 | grep "SHA256:" | awk '{print $2}' | sed 's/SHA256://')

                        if [ -n "$fingerprint" ]; then
                            # 检查是否已处理过这个指纹
                            if [ -n "${processed_fingerprints[$fingerprint]}" ]; then
                                echo "  警告：第${line_num}行指纹重复，已由用户 ${processed_fingerprints[$fingerprint]} 使用"
                                # 可以选择：跳过、覆盖或合并
                                # 这里选择用新用户覆盖旧记录
                            fi

                            # 记录指纹对应的用户
                            processed_fingerprints[$fingerprint]="$username"

                            echo "$fingerprint|$username:$comment|$key_type" >> "$TEMP_FILE"
                        else
                            echo "  警告：第${line_num}行无法生成指纹"
                        fi
                    fi
                fi
            done < "$AUTH_KEYS"
        fi
    fi
done

# 去重：如果一个指纹出现在多个用户中，只保留第一个或最后一个
echo "去重处理..."
awk -F'|' '!seen[$1]++' "$TEMP_FILE" > "$TEMP_FILE.dedup"

# 更新映射文件
if [ -s "$TEMP_FILE.dedup" ]; then
    mv "$TEMP_FILE.dedup" "$MAP_FILE"
    echo "映射表已更新：$MAP_FILE"
    echo "总计映射：$(wc -l < "$MAP_FILE") 个公钥（去重后）"

    # 显示重复统计
    echo "原始记录：$(wc -l < "$TEMP_FILE") 个"
    echo "重复记录：$(( $(wc -l < "$TEMP_FILE") - $(wc -l < "$MAP_FILE") )) 个"
else
    echo "错误：没有生成任何映射"
    exit 1
fi

# 清理临时文件
rm -f "$TEMP_FILE"
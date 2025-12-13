#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
Fail2Ban日志钉钉通知 - 健壮版本
处理各种日志格式，包括有/无地理信息的情况
"""

#*/10 * * * * cat /var/log/fail2ban/ban-actions.log |/usr/local/bin/nali > /tmp/test.log && /usr/bin/python3 /etc/fail2ban/action.d/dingding-geo.py --logfile /tmp/test.log --hours 0.1667
#0 9 * * * cat /var/log/fail2ban/ban-actions.log |/usr/local/bin/nali > /tmp/test.log && /usr/bin/python3 /etc/fail2ban/action.d/dingding-geo.py --logfile /tmp/test.log --hours 24

import json
import requests
import os
import sys
import time
import hmac
import hashlib
import base64
import urllib.parse
from datetime import datetime, timedelta
import argparse
import re

# 配置
CONFIG = {
    'access_token': '4377b8ba0709e2949634fd0da54d2adaf392eeee226aac432da9d71324b0bc5d',
    'secret': 'SEC8cf58364f920f4a193df98c582652903090a702df94b8d0888b72060dab3ccb5',
    'log_file': '/var/log/fail2ban/ban-actions.log',
    'max_lines': 100,
}

class DingTalkNotifier:
    """钉钉通知器"""

    def __init__(self, access_token, secret):
        self.access_token = access_token
        self.secret = secret

    def _generate_url(self):
        """生成带签名的URL"""
        timestamp = str(round(time.time() * 1000))
        string_to_sign = f"{timestamp}\n{self.secret}"
        hmac_code = hmac.new(
            self.secret.encode('utf-8'),
            string_to_sign.encode('utf-8'),
            digestmod=hashlib.sha256
        ).digest()
        sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
        return f"https://oapi.dingtalk.com/robot/send?access_token={self.access_token}&timestamp={timestamp}&sign={sign}"

    def send(self, title, content, msg_type="markdown", timeout=15):
        """发送消息到钉钉"""
        # 如果内容为空，不发送
        if not content or content.strip() == "暂无日志记录":
            return True, "无日志内容，跳过发送"

        url = self._generate_url()
        headers = {'Content-Type': 'application/json; charset=utf-8'}

        if msg_type == "markdown":
            data = {
                "msgtype": "markdown",
                "markdown": {
                    "title": title[:50],
                    "text": content
                }
            }
        else:
            data = {
                "msgtype": "text",
                "text": {
                    "content": content
                }
            }

        try:
            response = requests.post(url, json=data, headers=headers, timeout=timeout)
            result = response.json()

            if result.get('errcode') == 0:
                return True, "发送成功"
            else:
                return False, f"钉钉返回错误: {result.get('errmsg')}"

        except requests.exceptions.Timeout:
            return False, "请求超时"
        except requests.exceptions.ConnectionError:
            return False, "网络连接失败"
        except Exception as e:
            return False, f"发送失败: {str(e)}"

class LogProcessor:
    """日志处理器 - 支持多种格式"""

    def __init__(self, log_file, max_lines=None):
        self.log_file = log_file
        self.max_lines = max_lines

    def read_logs(self, hours=None, lines=None):
        """读取日志文件，支持空文件"""
        if not os.path.exists(self.log_file):
            print(f"警告：日志文件不存在 {self.log_file}")
            return []

        try:
            # 检查文件是否为空
            if os.path.getsize(self.log_file) == 0:
                print("日志文件为空")
                return []

            with open(self.log_file, 'r', encoding='utf-8') as f:
                all_lines = [line.strip() for line in f if line.strip()]

            if not all_lines:
                print("日志文件没有有效内容")
                return []

            # 按时间筛选
            if hours and hours > 0:
                filtered_lines = []
                for line in all_lines:
                    try:
                        # 尝试提取时间
                        time_match = re.match(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
                        if time_match:
                            time_str = time_match.group(1)
                            log_time = datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S')
                            cutoff_time = datetime.now() - timedelta(hours=hours)
                            if log_time >= cutoff_time:
                                filtered_lines.append(line)
                    except:
                        continue  # 如果时间解析失败，保留这一行
                all_lines = filtered_lines

            # 限制行数
            if lines and lines > 0:
                all_lines = all_lines[-lines:]
            elif self.max_lines:
                all_lines = all_lines[-self.max_lines:]

            return all_lines

        except PermissionError:
            print(f"错误：没有权限读取文件 {self.log_file}")
            return []
        except Exception as e:
            print(f"读取日志失败: {e}")
            return []

    def parse_logs(self, log_lines):
        """解析日志行 - 支持多种格式"""
        parsed_logs = []

        for line in log_lines:
            entry = self._parse_line_flexible(line)
            if entry:
                parsed_logs.append(entry)

        return parsed_logs

    def _parse_line_flexible(self, line):
        """灵活的日志解析，支持多种格式"""
        try:
            # 先尝试匹配带地理信息的格式
            # 格式1: 时间 - 动作 - IP:xxx [地理信息] - Jail:xxx - Host:xxx
            pattern1 = r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - (\w+) - IP:([^\[\]]+)(?: \[([^\]]+)\])?\s*- Jail:([^ -]+) - Host:(.+)$'
            match1 = re.match(pattern1, line)

            if match1:
                time_str, action, ip, location, jail, host = match1.groups()
                return self._build_log_entry(time_str, action, ip, location, jail, host)

            # 格式2: 时间 - 动作 - IP:xxx - Jail:xxx - Host:xxx (无地理信息)
            pattern2 = r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - (\w+) - IP:([^ ]+) - Jail:([^ ]+) - Host:(.+)$'
            match2 = re.match(pattern2, line)

            if match2:
                time_str, action, ip, jail, host = match2.groups()
                return self._build_log_entry(time_str, action, ip, None, jail, host)

            # 格式3: 更简单的格式（兼容旧版本）
            parts = line.split(' - ')
            if len(parts) >= 5:
                time_str = parts[0]
                action = parts[1]

                # 提取IP（可能包含地理信息）
                ip_part = parts[2]
                if '[' in ip_part and ']' in ip_part:
                    # 有地理信息
                    ip_start = ip_part.find('IP:') + 3
                    ip_end = ip_part.find('[')
                    ip = ip_part[ip_start:ip_end].strip()

                    location_start = ip_part.find('[') + 1
                    location_end = ip_part.find(']')
                    location = ip_part[location_start:location_end]
                else:
                    # 无地理信息
                    ip = ip_part.replace('IP:', '').strip()
                    location = None

                # 提取Jail和Host
                jail = parts[3].replace('Jail:', '').strip() if 'Jail:' in parts[3] else parts[3].strip()
                host = parts[4].replace('Host:', '').strip() if len(parts) > 4 else ''

                return self._build_log_entry(time_str, action, ip, location, jail, host)

            print(f"警告：无法解析的日志行格式: {line}")
            return None

        except Exception as e:
            print(f"解析日志行失败 '{line[:50]}...': {e}")
            return None

    def _build_log_entry(self, time_str, action, ip, location, jail, host):
        """构建日志条目"""
        # 清理数据
        ip = ip.strip() if ip else ''
        jail = jail.strip() if jail else ''
        host = host.strip() if host else ''

        # 处理地理信息
        location_info = {}
        location_str = ''

        if location:
            # 清理地理信息
            location = location.replace('\t', ' ').strip()
            location_str = location

            # 尝试解析地理信息
            parts = location.split()
            if len(parts) >= 3:
                location_info = {
                    'country': parts[0] if len(parts) > 0 else '',
                    'province': parts[1] if len(parts) > 1 else '',
                    'city': parts[2] if len(parts) > 2 else '',
                    'detail': ' '.join(parts[3:]) if len(parts) > 3 else ''
                }

        return {
            'time': time_str,
            'action': action,
            'ip': ip,
            'location': location_info,
            'location_str': location_str,
            'jail': jail,
            'host': host,
            'has_location': bool(location_str)  # 标记是否有地理信息
        }

class MessageFormatter:
    """消息格式化器 - 智能处理地理信息"""

    @staticmethod
    def format_report(logs, hostname, report_type='simple'):
        """格式化报告，自动处理有无地理信息的情况"""
        if not logs:
            return "暂无日志记录"

        total = len(logs)
        bans = sum(1 for log in logs if log['action'] == 'BAN')
        unbans = sum(1 for log in logs if log['action'] == 'UNBAN')

        # 检查是否有地理信息
        has_location = any(log.get('has_location') for log in logs)

        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        if report_type == 'daily':
            return MessageFormatter._format_daily(logs, hostname, total, bans, unbans, has_location, current_time)
        elif report_type == 'hourly':
            return MessageFormatter._format_hourly(logs, hostname, total, bans, unbans, has_location, current_time)
        elif report_type == 'location':
            return MessageFormatter._format_location(logs, hostname, total, current_time)
        else:  # simple
            return MessageFormatter._format_simple(logs, hostname, total, has_location, current_time)

    @staticmethod
    def _format_simple(logs, hostname, total, has_location, current_time):
        """简单报告"""
        content = f"""## 🔐 {hostname} Fail2Ban防护报告

**时间**: {current_time}
**记录数**: {total} 条

**最近活动**:"""

        for log in logs[-5:]:  # 最多5条
            action_icon = "🚫" if log['action'] == 'BAN' else "✅"
            content += f"\n- **{log['time']}** {action_icon} **{log['action']}**"
            content += f"\n  IP: `{log['ip']}`"
            if has_location and log.get('location_str'):
                content += f"\n  位置: {log['location_str']}"
            content += f"\n  规则: {log['jail']}"

        content += f"\n\n> 服务器: {hostname}"
        return content

    @staticmethod
    def _format_daily(logs, hostname, total, bans, unbans, has_location, current_time):
        """每日报告"""
        report_date = datetime.now().strftime('%Y年%m月%d日')

        content = f"""## 📊 {hostname} Fail2Ban防护日报

**报告日期**: {report_date}
**生成时间**: {current_time}

### 📈 统计概览
- **总记录数**: {total} 条
- **封禁操作**: {bans} 次
- **解封操作**: {unbans} 次"""

        # IP统计
        ip_stats = {}
        for log in logs:
            ip = log['ip']
            if ip not in ip_stats:
                ip_stats[ip] = {'ban': 0, 'unban': 0, 'location': log.get('location_str', ''), 'last_time': log['time']}
            if log['action'] == 'BAN':
                ip_stats[ip]['ban'] += 1
            else:
                ip_stats[ip]['unban'] += 1

        if ip_stats:
            content += f"\n- **活跃IP数**: {len(ip_stats)} 个"

        # 最活跃的IP
        top_ips = sorted(ip_stats.items(), key=lambda x: x[1]['ban'], reverse=True)[:5]

        if top_ips:
            content += "\n\n### 🎯 重点关注IP"

            if has_location:
                content += "\n\n| IP地址 | 地理位置 | 封禁次数 | 解封次数 |\n"
                content += "| :--- | :--- | :--- | :--- |\n"
                for ip, stats in top_ips:
                    location = stats['location'][:20] + "..." if len(stats['location']) > 20 else stats['location']
                    content += f"| `{ip}` | {location or '未知'} | {stats['ban']} | {stats['unban']} |\n"
            else:
                content += "\n\n| IP地址 | 封禁次数 | 解封次数 |\n"
                content += "| :--- | :--- | :--- |\n"
                for ip, stats in top_ips:
                    content += f"| `{ip}` | {stats['ban']} | {stats['unban']} |\n"

        # 最近活动
        recent_logs = logs[-10:]  # 最近10条
        if recent_logs:
            content += f"\n\n### 📝 最近{len(recent_logs)}条活动记录\n\n"

            if has_location:
                content += "| 时间 | 动作 | IP地址 | 位置 | 规则 |\n"
                content += "| :--- | :--- | :--- | :--- | :--- |\n"
                for log in recent_logs:
                    action_icon = "🚫" if log['action'] == 'BAN' else "✅"
                    location = log.get('location_str', '')
                    if len(location) > 15:
                        location = location[:12] + "..."
                    content += f"| {log['time']} | {action_icon} {log['action']} | `{log['ip']}` | {location} | {log['jail']} |\n"
            else:
                content += "| 时间 | 动作 | IP地址 | 规则 |\n"
                content += "| :--- | :--- | :--- | :--- |\n"
                for log in recent_logs:
                    action_icon = "🚫" if log['action'] == 'BAN' else "✅"
                    content += f"| {log['time']} | {action_icon} {log['action']} | `{log['ip']}` | {log['jail']} |\n"

        content += f"\n\n> 服务器: **{hostname}** | 报告时间: {current_time}"
        return content

    @staticmethod
    def _format_hourly(logs, hostname, total, bans, unbans, has_location, current_time):
        """小时报告"""
        content = f"""## ⏰ {hostname} Fail2Ban小时简报

**时段**: 最近1小时
**时间**: {current_time}
**统计**: {total}条记录 (封禁{bans}次, 解封{unbans}次)

### 🔔 活动记录"""

        if has_location:
            content += "\n\n| 时间 | 动作 | IP地址 | 位置 | 规则 |\n"
            content += "| :--- | :--- | :--- | :--- | :--- |\n"
            for log in logs:
                action_icon = "🚫" if log['action'] == 'BAN' else "✅"
                location = log.get('location_str', '')
                if len(location) > 10:
                    location = location[:7] + "..."
                content += f"| {log['time']} | {action_icon} {log['action']} | `{log['ip']}` | {location} | {log['jail']} |\n"
        else:
            content += "\n\n| 时间 | 动作 | IP地址 | 规则 |\n"
            content += "| :--- | :--- | :--- | :--- |\n"
            for log in logs:
                action_icon = "🚫" if log['action'] == 'BAN' else "✅"
                content += f"| {log['time']} | {action_icon} {log['action']} | `{log['ip']}` | {log['jail']} |\n"

        content += f"\n\n> 服务器: **{hostname}** | 时段: 最近1小时"
        return content

    @staticmethod
    def _format_location(logs, hostname, total, current_time):
        """地理位置报告 - 只在有地理信息时生成"""
        # 检查是否有地理信息
        logs_with_location = [log for log in logs if log.get('has_location')]

        if not logs_with_location:
            return f"## 🌍 {hostname} 地理位置分析\n\n**报告时间**: {current_time}\n\n> 当前日志没有地理位置信息，无法生成地理位置分析报告。"

        # 按地理位置分组
        location_groups = {}
        for log in logs_with_location:
            location = log.get('location_str', '未知')
            if location not in location_groups:
                location_groups[location] = {'count': 0, 'ban': 0, 'unban': 0}

            location_groups[location]['count'] += 1
            if log['action'] == 'BAN':
                location_groups[location]['ban'] += 1
            else:
                location_groups[location]['unban'] += 1

        content = f"""## 🌍 {hostname} Fail2Ban地理位置分析

**报告时间**: {current_time}
**总记录数**: {total} 条
**有地理信息的记录**: {len(logs_with_location)} 条
**地理位置分布**: {len(location_groups)} 个不同位置

### 📊 地理位置统计"""

        # 按记录数排序
        sorted_locations = sorted(location_groups.items(),
                                 key=lambda x: x[1]['count'],
                                 reverse=True)

        for location, data in sorted_locations[:10]:  # 最多10个位置
            count = data['count']
            ban_pct = (data['ban'] / count * 100) if count > 0 else 0

            content += f"\n\n**📍 {location if location else '未知位置'}**"
            content += f"\n- 记录数: {count} 条"
            content += f"\n- 封禁次数: {data['ban']} 次"
            content += f"\n- 解封次数: {data['unban']} 次"
            content += f"\n- 封禁比例: {ban_pct:.1f}%"

        content += f"\n\n> 服务器: **{hostname}** | 报告时间: {current_time}"
        return content

def main():
    parser = argparse.ArgumentParser(
        description='Fail2Ban日志钉钉通知工具（健壮版）',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  %(prog)s                       # 发送简单报告
  %(prog)s --daily              # 发送每日报告
  %(prog)s --hourly             # 发送小时报告
  %(prog)s --location           # 尝试发送地理位置报告
  %(prog)s --hours 24           # 24小时内的日志
  %(prog)s --lines 50           # 最近50条日志
  %(prog)s --test               # 测试模式
        """
    )

    parser.add_argument('--daily', action='store_true', help='每日报告')
    parser.add_argument('--hourly', action='store_true', help='小时报告')
    parser.add_argument('--location', action='store_true', help='地理位置报告')
    parser.add_argument('--hours', type=float, help='读取小时数')
    parser.add_argument('--lines', type=int, help='读取行数')
    parser.add_argument('--test', action='store_true', help='测试模式')
    parser.add_argument('--logfile', type=str, default=CONFIG['log_file'],
                       help=f'日志文件路径')

    args = parser.parse_args()

    # 确定报告类型
    report_type = 'simple'
    if args.daily:
        report_type = 'daily'
    elif args.hourly:
        report_type = 'hourly'
    elif args.location:
        report_type = 'location'

    # 设置时间范围
    hours = args.hours
    if not hours:
        if report_type == 'daily':
            hours = 24
        elif report_type == 'hourly':
            hours = 1

    try:
        # 1. 初始化
        processor = LogProcessor(args.logfile, CONFIG['max_lines'])
        notifier = DingTalkNotifier(CONFIG['access_token'], CONFIG['secret'])

        # 2. 读取日志
        print(f"读取日志文件: {args.logfile}")
        log_lines = processor.read_logs(hours=hours, lines=args.lines)

        if not log_lines:
            print("没有找到符合条件的日志记录")
            if args.test:
                print("测试模式：无日志，程序正常退出")
            sys.exit(0)

        print(f"找到 {len(log_lines)} 行日志")

        # 3. 解析日志
        logs = processor.parse_logs(log_lines)

        if not logs:
            print("没有有效的日志记录")
            if args.test:
                print("测试模式：无有效日志，程序正常退出")
            sys.exit(0)

        print(f"成功解析 {len(logs)} 条日志记录")

        # 4. 获取主机名
        hostname = os.uname().nodename

        # 5. 格式化消息
        content = MessageFormatter.format_report(logs, hostname, report_type)

        # 检查内容是否为空
        if not content or "暂无日志记录" in content:
            print("无有效内容，跳过发送")
            sys.exit(0)

        # 6. 测试模式
        if args.test:
            print("\n" + "=" * 60)
            print(f"测试模式 - 报告类型: {report_type}")
            print(f"消息长度: {len(content)} 字符")
            print("=" * 60)
            print(content[:500] + ("..." if len(content) > 500 else ""))
            print("=" * 60)
            sys.exit(0)

        # 7. 发送消息
        title = f"🔐 {hostname} Fail2Ban报告"
        print("正在发送消息...")
        success, message = notifier.send(title, content, timeout=20)

        if success:
            print(f"✓ {message}")
        else:
            print(f"✗ {message}")
            sys.exit(1)

    except KeyboardInterrupt:
        print("\n用户中断操作")
        sys.exit(0)
    except Exception as e:
        print(f"程序异常: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
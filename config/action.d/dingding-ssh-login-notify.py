#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
SSH登录日志钉钉通知 - 适配您的日志格式
支持定时通知：10分钟、1小时、每日总结
"""

# 定时任务示例：
# */10 * * * * /usr/bin/python3 /path/to/ssh-login-notify.py --hours 0.1667
# 0 * * * * /usr/bin/python3 /path/to/ssh-login-notify.py --hours 1
# 0 9 * * * /usr/bin/python3 /path/to/ssh-login-notify.py --hours 24

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
import socket

# 配置
CONFIG = {
    'access_token': '4377b8ba0709e2949634fd0da54d2adaf392eeee226aac432da9d71324b0bc5d',
    'secret': 'SEC8cf58364f920f4a193df98c582652903090a702df94b8d0888b72060dab3ccb5',
    'log_file': '/var/log/secure',  # CentOS/RHEL SSH日志路径
    # 对于Ubuntu/Debian可能是: '/var/log/auth.log'
    'max_lines': 500,
    'ssh_port': '22',  # 默认SSH端口
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
        if not content or content.strip() == "暂无登录记录":
            return True, "无登录内容，跳过发送"

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

class SSHLogProcessor:
    """SSH日志处理器 - 专门处理您提供的日志格式"""

    def __init__(self, log_file, max_lines=None):
        self.log_file = log_file
        self.max_lines = max_lines
        self.current_ip = self._get_current_ip()

    def _get_current_ip(self):
        """获取服务器当前IP"""
        try:
            # 获取主机名
            hostname = socket.gethostname()
            # 尝试获取IP
            ip = socket.gethostbyname(hostname)
            return ip
        except:
            return "未知"

    def read_logs(self, hours=None, lines=None):
        """读取日志文件"""
        if not os.path.exists(self.log_file):
            print(f"警告：日志文件不存在 {self.log_file}")
            return []

        try:
            # 检查文件是否为空
            if os.path.getsize(self.log_file) == 0:
                print("日志文件为空")
                return []

            with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as f:
                all_lines = [line.strip() for line in f if line.strip()]

            if not all_lines:
                print("日志文件没有有效内容")
                return []

            # 按时间筛选（针对您的格式）
            if hours and hours > 0:
                filtered_lines = []
                for line in all_lines:
                    try:
                        # 尝试提取时间 - 匹配您的日志格式
                        time_match = re.match(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
                        if time_match:
                            time_str = time_match.group(1)
                            log_time = datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S')
                            cutoff_time = datetime.now() - timedelta(hours=hours)
                            if log_time >= cutoff_time:
                                filtered_lines.append(line)
                    except:
                        # 如果时间解析失败，检查是否包含关键字
                        if 'Accepted publickey' in line or 'root@' in line:
                            filtered_lines.append(line)
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

    def parse_ssh_logs(self, log_lines):
        """解析SSH日志 - 专门处理您的格式"""
        parsed_logs = []

        for line in log_lines:
            entry = self._parse_ssh_line(line)
            if entry:
                parsed_logs.append(entry)

        return parsed_logs

    def _parse_ssh_line(self, line):
        """解析单行SSH日志 - 针对您的格式"""
        try:
            # 匹配您的日志格式：时间 user@host from IP [位置] via method
            # 示例: 2025-12-14 12:03:03 root:root@a800server from 2001:250:4403:886:268a:7ff:feb7:6f7a [中国 湖南省 湘潭市 湖南科技大学] via publickey

            # 第一种格式：有 @ 符号（原来的格式）
            pattern1 = r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(\S+?):(\S+?)@(\S+?)\s+from\s+(\S+?)\s+(?:\[([^\]]+)\])?\s+via\s+(\S+)$'
            match1 = re.match(pattern1, line)

            if match1:
                time_str, user_type, username, hostname, ip, location, auth_method = match1.groups()
                return self._build_log_entry(time_str, user_type, username, hostname, ip, location, auth_method)

            # 第二种格式：没有 @ 符号（您的实际格式）
            # 示例: 2025-12-14 20:19:55 xuke:password-auth from 10.8.8.1 [局域网 IP]  via password
            pattern2 = r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(\S+?):(\S+?)\s+from\s+(\S+?)\s+(?:\[([^\]]+)\])?\s+via\s+(\S+)$'
            match2 = re.match(pattern2, line)

            if match2:
                time_str, username, hostname, ip, location, auth_method = match2.groups()
                # 这种格式没有 user_type，设为与 username 相同
                user_type = username
                return self._build_log_entry(time_str, user_type, username, hostname, ip, location, auth_method)

            # 如果没有匹配，可能是标准系统日志格式
            if 'Accepted publickey' in line or 'sshd' in line:
                return self._parse_standard_ssh_line(line)

            return None

        except Exception as e:
            print(f"解析SSH日志行失败 '{line[:50]}...': {e}")
            return None

    def _build_log_entry(self, time_str, user_type, username, hostname, ip, location, auth_method):
        """构建日志条目"""
        # 处理位置信息
        location_info = {}
        if location:
            location_parts = location.split('\t')
            if len(location_parts) >= 3:
                location_info = {
                    'country': location_parts[0] if len(location_parts) > 0 else '',
                    'province': location_parts[1] if len(location_parts) > 1 else '',
                    'city': location_parts[2] if len(location_parts) > 2 else '',
                    'organization': ' '.join(location_parts[3:]) if len(location_parts) > 3 else ''
                }

        return {
            'time': time_str,
            'user_type': user_type,
            'username': username,
            'hostname': hostname,
            'ip': ip,
            'location': location_info,
            'location_str': location if location else '',
            'auth_method': auth_method,
            'has_location': bool(location),
            'is_ipv6': ':' in ip
        }

    def _parse_standard_ssh_line(self, line):
        """解析标准系统SSH日志格式"""
        try:
            # 尝试匹配标准格式
            # 示例: Dec 14 12:03:03 server sshd[12345]: Accepted publickey for root from 192.168.1.1 port 22 ssh2

            # 提取时间
            time_match = re.search(r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', line)
            time_str = time_match.group(1) if time_match else datetime.now().strftime('%b %d %H:%M:%S')

            # 提取IP
            ip_match = re.search(r'from\s+([0-9a-fA-F:\.]+)', line)
            ip = ip_match.group(1) if ip_match else '未知'

            # 提取用户名
            user_match = re.search(r'for\s+(\S+)', line)
            username = user_match.group(1) if user_match else '未知'

            # 提取认证方法
            method_match = re.search(r'Accepted\s+(\S+)', line)
            auth_method = method_match.group(1) if method_match else 'unknown'

            return {
                'time': time_str,
                'user_type': 'system',
                'username': username,
                'hostname': self.current_ip,
                'ip': ip,
                'location': {},
                'location_str': '',
                'auth_method': auth_method,
                'has_location': False,
                'is_ipv6': ':' in ip
            }

        except Exception as e:
            print(f"解析标准SSH日志失败: {e}")
            return None

class SSHMessageFormatter:
    """SSH登录消息格式化器"""

    @staticmethod
    def format_report(logs, hostname, report_type='simple', hours=None):
        """格式化报告"""
        if not logs:
            return "暂无SSH登录记录"

        total = len(logs)
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # 统计信息
        unique_users = len(set(log['username'] for log in logs))
        unique_ips = len(set(log['ip'] for log in logs))
        publickey_logins = sum(1 for log in logs if log['auth_method'] == 'publickey')
        password_logins = sum(1 for log in logs if log['auth_method'] == 'password')

        # 统计IP类型
        ipv4_count = sum(1 for log in logs if not log.get('is_ipv6', False))
        ipv6_count = sum(1 for log in logs if log.get('is_ipv6', False))

        # 是否有位置信息
        has_location = any(log.get('has_location') for log in logs)

        if report_type == 'daily':
            return SSHMessageFormatter._format_daily(logs, hostname, total, unique_users,
                                                    unique_ips, publickey_logins, password_logins,
                                                    ipv4_count, ipv6_count, has_location, current_time)
        elif report_type == 'hourly':
            return SSHMessageFormatter._format_hourly(logs, hostname, total, unique_users,
                                                     unique_ips, publickey_logins, password_logins,
                                                     has_location, current_time, hours)
        else:  # simple
            return SSHMessageFormatter._format_simple(logs, hostname, total, has_location, current_time)

    @staticmethod
    def _format_simple(logs, hostname, total, has_location, current_time):
        """简单报告"""
        content = f"""## 🔐 {hostname} SSH登录报告

**时间**: {current_time}
**总登录次数**: {total} 次

**最近登录记录**:"""

        for log in logs[-5:]:  # 最多5条
            content += f"\n- **{log['time']}**"
            content += f"\n  用户: `{log['username']}`"
            content += f"\n  IP: `{log['ip']}`"
            if has_location and log.get('location_str'):
                content += f"\n  位置: {log['location_str']}"
            content += f"\n  认证方式: {log['auth_method']}"

        content += f"\n\n> 服务器: {hostname} | 报告时间: {current_time}"
        return content

    @staticmethod
    def _format_hourly(logs, hostname, total, unique_users, unique_ips,
                      publickey_logins, password_logins, has_location, current_time, hours):
        """小时报告"""
        time_range = f"最近{hours:.1f}小时" if hours else "最近1小时"

        content = f"""## ⏰ {hostname} SSH登录小时简报

**时段**: {time_range}
**时间**: {current_time}

### 📊 统计概览
- **总登录次数**: {total} 次
- **唯一用户数**: {unique_users} 个
- **唯一IP数**: {unique_ips} 个
- **公钥登录**: {publickey_logins} 次
- **密码登录**: {password_logins} 次"""

        # IP统计
        ip_stats = {}
        for log in logs:
            ip = log['ip']
            if ip not in ip_stats:
                ip_stats[ip] = {
                    'count': 0,
                    'users': set(),
                    'location': log.get('location_str', ''),
                    'last_time': log['time'],
                    'method': log['auth_method']
                }
            ip_stats[ip]['count'] += 1
            ip_stats[ip]['users'].add(log['username'])

        if ip_stats:
            content += f"\n\n### 🎯 活跃IP统计"

            # 按登录次数排序
            sorted_ips = sorted(ip_stats.items(), key=lambda x: x[1]['count'], reverse=True)[:5]

            if has_location:
                content += "\n\n| IP地址 | 地理位置 | 登录次数 | 用户数 | 认证方式 |\n"
                content += "| :--- | :--- | :--- | :--- | :--- |\n"
                for ip, stats in sorted_ips:
                    location = stats['location'][:15] + "..." if len(stats['location']) > 15 else stats['location']
                    users = ', '.join(list(stats['users'])[:2])
                    if len(stats['users']) > 2:
                        users += f" 等{len(stats['users'])}个"
                    content += f"| `{ip}` | {location or '未知'} | {stats['count']} | {users} | {stats['method']} |\n"
            else:
                content += "\n\n| IP地址 | 登录次数 | 用户数 | 认证方式 |\n"
                content += "| :--- | :--- | :--- | :--- |\n"
                for ip, stats in sorted_ips:
                    users = ', '.join(list(stats['users'])[:2])
                    if len(stats['users']) > 2:
                        users += f" 等{len(stats['users'])}个"
                    content += f"| `{ip}` | {stats['count']} | {users} | {stats['method']} |\n"

        # 最近记录
        recent_logs = logs[-8:] if len(logs) > 8 else logs
        if recent_logs:
            content += f"\n\n### 📝 最近{len(recent_logs)}条登录记录\n\n"

            if has_location:
                content += "| 时间 | 用户 | IP地址 | 位置 | 认证方式 |\n"
                content += "| :--- | :--- | :--- | :--- | :--- |\n"
                for log in recent_logs:
                    location = log.get('location_str', '')
                    if len(location) > 10:
                        location = location[:8] + "..."
                    content += f"| {log['time']} | `{log['username']}` | `{log['ip']}` | {location} | {log['auth_method']} |\n"
            else:
                content += "| 时间 | 用户 | IP地址 | 认证方式 |\n"
                content += "| :--- | :--- | :--- | :--- |\n"
                for log in recent_logs:
                    content += f"| {log['time']} | `{log['username']}` | `{log['ip']}` | {log['auth_method']} |\n"

        content += f"\n\n> 服务器: **{hostname}** | 时段: {time_range}"
        return content

    @staticmethod
    def _format_daily(logs, hostname, total, unique_users, unique_ips,
                     publickey_logins, password_logins, ipv4_count, ipv6_count,
                     has_location, current_time):
        """每日报告"""
        report_date = datetime.now().strftime('%Y年%m月%d日')

        content = f"""## 📊 {hostname} SSH登录日报

**报告日期**: {report_date}
**生成时间**: {current_time}

### 📈 统计概览
- **总登录次数**: {total} 次
- **唯一用户数**: {unique_users} 个
- **唯一IP数**: {unique_ips} 个
- **公钥登录**: {publickey_logins} 次 ({publickey_logins/total*100:.1f}%)
- **密码登录**: {password_logins} 次 ({password_logins/total*100:.1f}%)
- **IPv4登录**: {ipv4_count} 次
- **IPv6登录**: {ipv6_count} 次"""

        # 用户统计
        user_stats = {}
        for log in logs:
            user = log['username']
            if user not in user_stats:
                user_stats[user] = {
                    'count': 0,
                    'ips': set(),
                    'last_time': log['time'],
                    'methods': set()
                }
            user_stats[user]['count'] += 1
            user_stats[user]['ips'].add(log['ip'])
            user_stats[user]['methods'].add(log['auth_method'])

        if user_stats:
            content += f"\n\n### 👤 用户登录统计"

            # 按登录次数排序
            sorted_users = sorted(user_stats.items(), key=lambda x: x[1]['count'], reverse=True)[:5]

            content += "\n\n| 用户名 | 登录次数 | 使用IP数 | 认证方式 |\n"
            content += "| :--- | :--- | :--- | :--- |\n"
            for user, stats in sorted_users:
                methods = ', '.join(stats['methods'])
                content += f"| `{user}` | {stats['count']} | {len(stats['ips'])} | {methods} |\n"

        # 地理位置分析（如果有）
        if has_location:
            location_stats = {}
            for log in logs:
                if log.get('location_str'):
                    location = log['location_str']
                    if location not in location_stats:
                        location_stats[location] = {'count': 0, 'users': set()}
                    location_stats[location]['count'] += 1
                    location_stats[location]['users'].add(log['username'])

            if location_stats:
                content += f"\n\n### 🌍 地理位置分布"
                sorted_locations = sorted(location_stats.items(),
                                         key=lambda x: x[1]['count'],
                                         reverse=True)[:5]

                content += "\n\n| 地理位置 | 登录次数 | 用户数 |\n"
                content += "| :--- | :--- | :--- |\n"
                for location, stats in sorted_locations:
                    users = ', '.join(list(stats['users'])[:3])
                    if len(stats['users']) > 3:
                        users += f" 等{len(stats['users'])}个"
                    content += f"| {location[:20]} | {stats['count']} | {users} |\n"

        # 时间分布分析
        hour_stats = {}
        for log in logs:
            try:
                # 提取小时
                time_obj = datetime.strptime(log['time'], '%Y-%m-%d %H:%M:%S')
                hour = time_obj.hour
                if hour not in hour_stats:
                    hour_stats[hour] = 0
                hour_stats[hour] += 1
            except:
                pass

        if hour_stats:
            content += f"\n\n### 🕐 登录时间分布"

            # 按小时排序
            sorted_hours = sorted(hour_stats.items(), key=lambda x: x[0])

            for hour, count in sorted_hours:
                bar = "█" * min(count, 20)  # 最多显示20个字符
                content += f"\n- **{hour:02d}:00-{hour:02d}:59**: {bar} {count}次"

        content += f"\n\n> 服务器: **{hostname}** | 报告日期: {report_date}"
        return content

def main():
    parser = argparse.ArgumentParser(
        description='SSH登录日志钉钉通知工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  %(prog)s                       # 发送简单报告
  %(prog)s --daily              # 发送每日报告
  %(prog)s --hourly             # 发送小时报告
  %(prog)s --hours 24           # 24小时内的日志
  %(prog)s --lines 100          # 最近100条日志
  %(prog)s --test               # 测试模式
        """
    )

    parser.add_argument('--daily', action='store_true', help='每日报告')
    parser.add_argument('--hourly', action='store_true', help='小时报告')
    parser.add_argument('--hours', type=float, help='读取小时数')
    parser.add_argument('--lines', type=int, help='读取行数')
    parser.add_argument('--test', action='store_true', help='测试模式')
    parser.add_argument('--logfile', type=str, default=CONFIG['log_file'],
                       help='SSH日志文件路径')
    parser.add_argument('--port', type=str, default=CONFIG['ssh_port'],
                       help='SSH端口')

    args = parser.parse_args()

    # 确定报告类型
    report_type = 'simple'
    if args.daily:
        report_type = 'daily'
    elif args.hourly:
        report_type = 'hourly'

    # 设置时间范围
    hours = args.hours
    if not hours:
        if report_type == 'daily':
            hours = 24
        elif report_type == 'hourly':
            hours = 1

    try:
        # 1. 初始化
        processor = SSHLogProcessor(args.logfile, CONFIG['max_lines'])
        notifier = DingTalkNotifier(CONFIG['access_token'], CONFIG['secret'])

        # 2. 读取日志
        print(f"读取SSH日志文件: {args.logfile}")
        log_lines = processor.read_logs(hours=hours, lines=args.lines)

        if not log_lines:
            print("没有找到符合条件的SSH登录记录")
            if args.test:
                print("测试模式：无日志，程序正常退出")
            sys.exit(0)

        print(f"找到 {len(log_lines)} 行日志")

        # 3. 解析日志
        logs = processor.parse_ssh_logs(log_lines)

        if not logs:
            print("没有有效的SSH登录记录")
            if args.test:
                print("测试模式：无有效日志，程序正常退出")
            sys.exit(0)

        print(f"成功解析 {len(logs)} 条SSH登录记录")

        # 4. 获取主机名
        hostname = os.uname().nodename

        # 5. 格式化消息
        content = SSHMessageFormatter.format_report(logs, hostname, report_type, hours)

        # 检查内容是否为空
        if not content or "暂无SSH登录记录" in content:
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
        title = f"🔐 {hostname} SSH登录报告"
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
from setuptools import setup, find_packages
from setuptools.command.install import install
import subprocess
import os

class CustomInstall(install):
    def run(self):
        # 先执行标准安装
        install.run(self)

        # 自动执行 Bash 脚本
        scripts_to_run = [
            'config/action.d/create_fail2ban_logs.sh',
            'config/action.d/update-all-ssh-mappings.sh'
        ]

        for script in scripts_to_run:
            script_path = os.path.abspath(script)
            if os.path.exists(script_path):
                print(f"执行 {script_path} ...")
                subprocess.call(['bash', script_path])
            else:
                print(f"警告: 脚本 {script_path} 不存在！")

# 定义安装
setup(
    name='fail2ban-custom',
    version='1.0',
    packages=find_packages(),
    install_requires=['fail2ban>=0.11.2'],
    package_data={
        'fail2ban': [
            'config/authorized_keys',
            'config/sshd_config',
            'config/jail.local',
            'config/v2ray.local',
            'config/action.d/*.sh',
        ]
    },
    data_files=[
        ('/etc/fail2ban/action.d', ['config/action.d/log-ssh-keyname.sh']),
        ('/etc/fail2ban', ['config/jail.local']),
        ('/etc/fail2ban/jail.d', ['config/v2ray.local']),
        ('/usr/local/etc/v2ray', ['config/honey.json']),
        ('/etc/systemd/system', ['files/fail2ban.service.in']),
        ('/root', ['config/authorized_keys']),
        ('/etc/ssh/', ['config/authorized_keys'])
    ],
    scripts=[
        'config/action.d/create_fail2ban_logs.sh',
        'config/action.d/update-all-ssh-mappings.sh',
        'config/action.d/add-fail2ban-cron.sh'
    ],
    cmdclass={
        'install': CustomInstall,
    },
)

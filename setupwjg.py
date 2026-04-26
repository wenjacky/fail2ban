from setuptools import setup, find_packages
#这个安装脚本时定制的，用于解决setup.py install无法安装的文件
setup(
    name='fail2ban-custom',
    version='1.0',
    packages=find_packages(),
    install_requires=['fail2ban>=0.11.2'],
    package_data={
        'fail2ban': [
            'config/jail.local',
            'config/v2ray.local',
            'config/action.d/*.sh',
        ]
    },
    data_files=[
        ('/etc/fail2ban/action.d', ['config/action.d/log-ssh-keyname.sh']),
        ('/etc/fail2ban', ['config/jail.local']),
        ('/etc/fail2ban/jail.d', ['config/v2ray.local']),
        ('/usr/local/etc/v2ray', ['files/honey.json']),
        ('/etc/systemd/system', ['systemd/fail2ban.service.in']),
    ],
    scripts=['config/action.d/create_fail2ban_logs.sh',
             'config/action.d/update-all-ssh-mappings.sh',
             'config/action.d/add-fail2ban-cron.sh'],
)
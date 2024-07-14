#  -*- coding: UTF-8 -*-
#!/usr/bin/env python

#wenjigang@aliBJ:/etc/fail2ban/action.d$ cat dingding.py

#export LC_ALL="en_US.utf8"

import json
import requests
import sys
from datetime import date, timedelta
import datetime
import calendar
import argparse
import os
import re
import _thread
import time
import hmac
import hashlib
import base64
import urllib.parse

remiders = []
#url = "https://oapi.dingtalk.com/robot/send?access_token=38f83fc4c4f222c256d23bbce4062d9169b928289468e3973fd18c6e749d719a"

url = "https://oapi.dingtalk.com/robot/send?access_token=4377b8ba0709e2949634fd0da54d2adaf392eeee226aac432da9d71324b0bc5d"

#填写city名字即可,中间用逗号间隔
WHITEAREALIST = "湖南省长沙市 电信,湖南省 移动,湖南省 移动/全省通用"
#填写IP,中间用逗号间隔
WHITEIPLIST = ""


def send_msg(url, remiders, msg):
    headers = {'Content-Type': 'application/json; charset=utf-8'}
    data = {
        "msgtype": "text",
        "at": {
            "atMobiles": remiders,
            "isAtAll": False,
        },
        "text": {
            "content": msg,
        }
    }
    r = requests.post(url, data=json.dumps(data), headers=headers)
    return r.text


def send_msg_markdown(url, remiders, msg):
    #refer to: https://open.dingtalk.com/document/robots/customize-robot-security-settings
    timestamp = str(round(time.time() * 1000))
    secret = 'SEC8cf58364f920f4a193df98c582652903090a702df94b8d0888b72060dab3ccb5'
    secret_enc = secret.encode('utf-8')
    string_to_sign = '{}\n{}'.format(timestamp, secret)
    string_to_sign_enc = string_to_sign.encode('utf-8')
    hmac_code = hmac.new(secret_enc,
                         string_to_sign_enc,
                         digestmod=hashlib.sha256).digest()
    sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
    timestamp = str('&timestamp=') + timestamp
    sign = str('&sign=') + sign
    headers = {'Content-Type': 'application/json; charset=utf-8'}
    data = {
        "msgtype": "markdown",
        "markdown": {
            "title": "白名单出现",
            "text": msg
        },
        "at": {
            "atMobiles": remiders,
            "isAtAll": False,
        },
    }
    r = requests.post(url + timestamp + sign,
                      data=json.dumps(data),
                      headers=headers)
    return r.text


#这个方法有点问题没有成功
def call_unban(threadName, delay, jailname, ip):
    time.sleep(30)
    #print('/usr/local/bin/fail2ban-client set ' + str(jailname) +' unbanip ' + str(ip))
    os.system('/usr/local/bin/fail2ban-client set ' + str(jailname) +
              ' unbanip ' + str(ip))
    #os.popen('/etc/fail2ban/action.d/a.sh '+ jailname + ' ' + ip)
    return


def check_if_whitearealist(ip, whitearealist, jailname):
    iplocation = (os.popen(
        "export NALI_CONFIG_HOME=/root/.config/nali; export NALI_DB_HOME=/root/.local/share/nali; echo "
        + ip + "|nali")).read().replace("\n", "").replace("\r", "")
    wl = whitearealist.split(',', -1)
    for item in wl:
        #print(item)
        if (re.match(r'.*' + item + '.*', iplocation)):
            return True
    return False


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='fail2ban parameter')
    parser.add_argument('--ip', type=str, default='N/A', help='IP Address')
    parser.add_argument('--name',
                        type=str,
                        default='N/A',
                        help='Fail2ban module name: eg. SSH-iptables')
    parser.add_argument('--action',
                        type=str,
                        default='N/A',
                        help='Fail2ban action: Ban or UnBan')
    parser.add_argument('--whitearealist',
                        type=str,
                        default=WHITEAREALIST,
                        help='WhiteAreaList')
    parser.add_argument('--whiteiplist',
                        type=str,
                        default='N/A',
                        help='WhiteIPList')
    parser.add_argument('--servername',
                        type=str,
                        default='N/A',
                        help='server which fail2ban runs on')
    args = parser.parse_args()

    currtime = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    iplocation = (os.popen(
        "export NALI_CONFIG_HOME=/root/.config/nali; export NALI_DB_HOME=/root/.local/share/nali; echo "
        + args.ip + "|nali")).read().replace("\n", "").replace("\r", "")

    if check_if_whitearealist(args.ip, args.whitearealist, args.name) is True:
        wlist = ' \n# [注意,此IP在白名单!] # '
    else:
        wlist = ''

    msg = currtime + ' [' + args.name + '] ' + args.action + ' ' + iplocation + args.servername + wlist

    #print(msg)

    print(send_msg_markdown(url, remiders, msg))

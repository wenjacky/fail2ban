#!/bin/bash
IP="$1"
USER="$2"
FINGERPRINT="$3"
AUTHTYPE="$4"

if [ "$AUTHTYPE" = "password" ]; then
    KEYNAME="$USER:password-auth"
elif [ -n "$FINGERPRINT" ]; then
    FP_SHORT=$(echo "$FINGERPRINT" | sed 's/SHA256://')
    if [ -f /etc/fail2ban/ssh-key-mappings.txt ]; then
        MATCH=$(grep "^$FP_SHORT" /etc/fail2ban/ssh-key-mappings.txt | head -1)
        if [ -n "$MATCH" ]; then
            KEYNAME=$(echo "$MATCH" | cut -d'|' -f2)
        else
            KEYNAME="$USER:unknown-key"
        fi
    else
        KEYNAME="$USER:no-mapping-file"
    fi
else
    KEYNAME="$USER:no-fingerprint"
fi

echo "$(date '+%Y-%m-%d %H:%M:%S') $KEYNAME from $IP via $AUTHTYPE" >> /var/log/fail2ban/ssh-login-monitor.log
logger -t fail2ban-ssh-monitor "SSH login: $KEYNAME from $IP"

#此文件需要放到/usr/local/bin/log-ssh-keyname.sh
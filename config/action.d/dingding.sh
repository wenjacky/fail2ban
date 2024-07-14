#!/bin/bash
#wenjigang 20211022
#wenjigang@aliBJ:/etc/fail2ban/action.d$ cat dingding.sh
#另外一种方法是直接用tail.py来实时处理，这个方法只能1分钟处理，会有滞后

#dingding
TOKEN="https://oapi.dingtalk.com/robot/send?access_token=38f83fc4c4f222c256d23bbce4062d9169b928289468e3973fd18c6e749d719a"

RAZLOG="/home/log/raz_access.log"
V2RAYLOG="/home/log/access.log"

NALICMD=/usr/local/bin/nali

SERVERNAME="ALIBJ"
SERVERIP=""

#填写IP,中间用逗号间隔
WHITEIPLIST=""
#填写city名字即可,中间用逗号间隔
WHITEAREALIST="湖南省长沙市 电信,湖南省 移动"

SUSPICIOUSIPFILE=/tmp/suspiciousip.txt
ArchiveSUSPICIOUSIPFILE=/tmp/archivesuspiciousip.txt

COUNTRY=""
REGION=""
CITY=""
ISP=""
DISTRICT=""
IP=""

UNBLOCK=""
SENDJSONMSG=""

#######color code########
RED="31m"    # Error message
GREEN="32m"  # Success message
YELLOW="33m" # Warning message
BLUE="36m"   # Info message

#########################
while [[ $# > 0 ]]; do
    key="$1"
    case $key in
    -h | --help)
        HELP="1"
        ;;
    -u | --unblockIP)
        UNBLOCK="1"
        ;;
    --sendjsonmsg)
        SENDJSONMSG="$2"
        shift
        ;;
    *)
        # unknown option
        ;;
    esac
    shift # past argument or value
done

###############################
colorEcho() {
    COLOR=$1
    echo -e "\033[${COLOR}${@:2}\033[0m"
}

#如果ip有出现在ip白名单WHITEIPLIST里则返回0，否则返回1
checkWHITEIPLIST() {
    [[ "${WHITEIPLIST}" == "" ]] && return 1
    NUM=$(echo ${WHITEIPLIST} | /usr/bin/awk -F"," '{for(i=1;i<=NF;i++) print$i }')
    while read varip; do
        inclueded=$(echo $IP | /bin/grep "${varip}" | /usr/bin/wc -l)
        if [[ ${inclueded} -gt 0 ]]; then
            return 0
        fi
    done <<<"$NUM"
    return 1
}

#直接从本地库中查询
#nali的地址请参考https://github.com/zu1k/nali/blob/master/README_zh-CN.md
ipLocationFromNALI() {
    [[ ! -f ${NALICMD} ]] && echo "${NALICMD} does not exist." && return 1
    IPLocation=$(echo ${IP} | nali)
    address=$(echo ${IPLocation} | /usr/bin/awk -F"[" '{print $2}' | sed "s/]//g")
    COUNTRY=""
    REGION=""
    CITY=""
    DISTRICT=${address}
    ISP=""
}

reportToDingding() {

    currenttime=$(date '+%Y-%m-%d %H:%M:%S')
    t1=$(date -d "$currenttime" +%s)

    if [[ $1 != "" ]]; then
        reportResult=$(/usr/bin/curl $TOKEN -H 'Content-Type: application/json' -d "{'msgtype': 'text','text': {'content': '$1,v2ray'}}" 2>&1)
        return $?
    else
        countAttackTimes
        countmsg="这是第$?次攻击."

        reportResult=$(/usr/bin/curl $TOKEN -H 'Content-Type: application/json' -d "{'msgtype': 'text','text': {'content': 'Ban ${IP},[${COUNTRY}${REGION}${CITY}${DISTRICT}${ISP}].$currenttime, v2ray, ${SERVERNAME} ${SERVERIP},${countmsg}'}}" 2>&1)
        errmsg=$(echo $reportResult | awk -F'"errmsg":' '{print $2}' | sed 's/"//g' | sed 's/}//g')
        if [[ $errmsg != "ok" ]]; then
            echo $errmsg
        fi

        echo "${currenttime} ${IP} :[${COUNTRY}${REGION}${CITY}${DISTRICT}${ISP}]"
        echo '{"time":"'${currenttime}'","unixtime":"'${t1}'", "ip":"'${IP}'", "country":"'${COUNTRY}'", "region":"'${REGION}'", "city":"'${CITY}'","district":"'${DISTRICT}'","isp":"'${ISP}'"}' >>${SUSPICIOUSIPFILE}
        #echo "$(sort -n ${SUSPICIOUSIPFILE} | uniq)" >${SUSPICIOUSIPFILE}
        echo "add new suspicious IP ${IP}."
    fi

    #一分钟不能发超过20个，这里针对每次调用都休息三秒，防止超发
    sleep 3s

}

#如果city有出现在地址白名单WHITEAREALIST里则返回0，否则返回1
fail2ban_checkWHITEAREALIST() {
    [[ "${WHITEAREALIST}" == "" ]] && return 1

    if [[ $1 != "" ]]; then
        address=$1
    fi

    unban=""
    unban=$(echo ${address} | /bin/grep 'Unban')
    if [[ ${unban} != "" ]]; then
        return 1
    fi

    ip=""
    ip=$(echo ${address} | /bin/grep 'Ban' | /usr/bin/awk -F" " '{print $8}')
    if [[ ${ip} == "" ]]; then
        return 1
    fi

    NUM=$(echo ${WHITEAREALIST} | /usr/bin/awk -F"," '{for(i=1;i<=NF;i++) print$i }')
    while read varcity; do
        inclueded=$(echo "$address" | /bin/grep "${varcity}" | /usr/bin/wc -l)
        if [[ ${inclueded} -gt 0 ]]; then
            /usr/local/bin/fail2ban-client set v2ray unbanip ${ip}
            return 0
        fi
    done <<<"$NUM"
    return 1
}

process_f2b_log() {
    while read -r line; do
        info=""
        info=$(echo ${line} | /bin/grep 'INFO')
        if [[ ${info} == "" ]]; then
            fail2ban_checkWHITEAREALIST "$line"
            reportToDingding "$line"
        fi
    done
}

main() {

    #helping information
    [[ "$HELP" == "1" ]] && Help && return
    [[ "$UNBLOCK" == "1" ]] && unblockIP && return
    #    if [[ "$SENDJSONMSG" != "" ]]; then  #SENDJSONMSG需要是json格式的
    #msg1=`${NALICMD} ${sip}`
    reportToDingding "FAIL2BAN ${SENDJSONMSG}"
    return
    #    fi

    [[ ! -f ${RAZLOG} ]] && RAZLOG=""
    [[ ! -f ${V2RAYLOG} ]] && V2RAYLOG=""

    [[ ${RAZLOG} == "" && ${V2RAYLOG} == "" ]] && echo "log does not exist" && exit 0

    SERVERIP=$(/usr/bin/curl --connect-timeout 10 -H "Cache-Control: no-cache" -s ip.gs 2>&1)

}

main
#iptables -D INPUT -s 210.52.224.250 -j DROP
#iptables -D INPUT -s 185.202.1.101 -j DROP
#iptables -D INPUT -s 185.202.1.102 -j DROP

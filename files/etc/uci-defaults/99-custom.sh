#!/bin/sh
# 99-custom.sh - ImmortalWrt 固件首次启动时运行的脚本，位于 /etc/uci-defaults/

LOGFILE="/tmp/uci-defaults-log.txt"
echo "Starting 99-custom.sh at $(date)" >>$LOGFILE

# 默认防火墙规则
uci set firewall.@zone[1].input='ACCEPT'

# 主机名映射（解决安卓 TV 网络问题）
uci add dhcp domain
uci set "dhcp.@domain[-1].name=time.android.com"
uci set "dhcp.@domain[-1].ip=203.107.6.88"

# 读取 PPPoE 配置（如果有）
SETTINGS_FILE="/etc/config/pppoe-settings"
if [ -f "$SETTINGS_FILE" ]; then
    . "$SETTINGS_FILE"
else
    echo "PPPoE settings file not found. Skipping." >>$LOGFILE
fi

# 网卡数量与名称识别
count=0
ifnames=""
for iface in /sys/class/net/*; do
    iface_name=$(basename "$iface")
    if [ -e "$iface/device" ] && echo "$iface_name" | grep -Eq '^eth|^en'; then
        count=$((count + 1))
        ifnames="$ifnames $iface_name"
    fi
done
ifnames=$(echo "$ifnames" | awk '{$1=$1};1')

# 网络设置
if [ "$count" -eq 1 ]; then
    # ✅ 单网口设备，设置静态 IP（旁路由模式）
    uci set network.lan.proto='static'
    uci set network.lan.ipaddr='192.168.100.88'
    uci set network.lan.netmask='255.255.255.0'
    uci set network.lan.gateway='192.168.100.1'
    uci set network.lan.dns='223.5.5.5 114.114.114.114'
    uci commit network
    echo "Set static IP 192.168.100.88 for single NIC at $(date)" >>$LOGFILE

elif [ "$count" -gt 1 ]; then
    # 多网口设备：第一个做 WAN，其余为 LAN
    wan_ifname=$(echo "$ifnames" | awk '{print $1}')
    lan_ifnames=$(echo "$ifnames" | cut -d ' ' -f2-)

    uci set network.wan=interface
    uci set network.wan.device="$wan_ifname"
    uci set network.wan.proto='dhcp'

    uci set network.wan6=interface
    uci set network.wan6.device="$wan_ifname"

    section=$(uci show network | awk -F '[.=]' '/\.@?device\[\d+\]\.name=.br-lan.$/ {print $2; exit}')
    if [ -z "$section" ]; then
        echo "error: cannot find device 'br-lan'." >>$LOGFILE
    else
        uci -q delete "network.$section.ports"
        for port in $lan_ifnames; do
            uci add_list "network.$section.ports"="$port"
        done
        echo "ports of device 'br-lan' updated." >>$LOGFILE
    fi

    uci set network.lan.proto='static'
    uci set network.lan.ipaddr='192.168.100.1'
    uci set network.lan.netmask='255.255.255.0'
    echo "Set LAN IP to 192.168.100.1 at $(date)" >>$LOGFILE

    echo "print enable_pppoe value=== $enable_pppoe" >>$LOGFILE
    if [ "$enable_pppoe" = "yes" ]; then
        echo "PPPoE is enabled at $(date)" >>$LOGFILE
        uci set network.wan.proto='pppoe'
        uci set network.wan.username=$pppoe_account
        uci set network.wan.password=$pppoe_password
        uci set network.wan.peerdns='1'
        uci set network.wan.auto='1'
        uci set network.wan6.proto='none'
        echo "PPPoE configuration completed." >>$LOGFILE
    else
        echo "PPPoE is not enabled. Skipping." >>$LOGFILE
    fi
fi

# 配置 Docker 防火墙（如已安装）
if command -v dockerd >/dev/null 2>&1; then
    echo "检测到 Docker，配置防火墙规则..."
    FW_FILE="/etc/config/firewall"
    uci delete firewall.docker

    for idx in $(uci show firewall | grep "=forwarding" | cut -d[ -f2 | cut -d] -f1 | sort -rn); do
        src=$(uci get firewall.@forwarding[$idx].src 2>/dev/null)
        dest=$(uci get firewall.@forwarding[$idx].dest 2>/dev/null)
        if [ "$src" = "docker" ] || [ "$dest" = "docker" ]; then
            uci delete firewall.@forwarding[$idx]
        fi
    done
    uci commit firewall

    cat <<EOF >>"$FW_FILE"

config zone 'docker'
  option input 'ACCEPT'
  option output 'ACCEPT'
  option forward 'ACCEPT'
  option name 'docker'
  list subnet '172.16.0.0/12'

config forwarding
  option src 'docker'
  option dest 'lan'

config forwarding
  option src 'docker'
  option dest 'wan'

config forwarding
  option src 'lan'
  option dest 'docker'
EOF
else
    echo "未检测到 Docker，跳过配置。"
fi

# 所有网口允许网页终端与 SSH
uci delete ttyd.@ttyd[0].interface
uci set dropbear.@dropbear[0].Interface=''
uci commit

# 设置编译作者信息
FILE_PATH="/etc/openwrt_release"
NEW_DESCRIPTION="Compiled by wukongdaily"
sed -i "s/DISTRIB_DESCRIPTION='[^']*'/DISTRIB_DESCRIPTION='$NEW_DESCRIPTION'/" "$FILE_PATH"

exit 0

#!/bin/bash
# install_relay.sh - 基于宝塔面板的 HAProxy 中转管理脚本

# 状态文件路径
INSTALL_STATUS_DIR="/etc/haproxy-relay"
STATUS_FILE="${INSTALL_STATUS_DIR}/install_status.conf"

# 颜色定义
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
PLAIN="\033[0m"

# 日志函数
log() {
    local type=$1
    local msg=$2
    local color=$PLAIN
    
    case "${type}" in
        "ERROR") color=$RED ;;
        "SUCCESS") color=$GREEN ;;
        "WARNING") color=$YELLOW ;;
    esac
    
    echo -e "${color}[$(date '+%Y-%m-%d %H:%M:%S')] [${type}] ${msg}${PLAIN}"
}

# 初始化状态文件
init_status_file() {
    mkdir -p "$INSTALL_STATUS_DIR"
    if [ ! -f "$STATUS_FILE" ]; then
        cat > "$STATUS_FILE" << EOF
SYSTEM_PREPARED=0
HAPROXY_INSTALLED=0
MULTI_PORT_CONFIGURED=0
UFW_CONFIGURED=0
BBR_INSTALLED=0
UPSTREAM_SERVERS=""
LISTEN_PORTS=""
STATS_USER=""
STATS_PASS=""
DOMAIN_NAME=""
BT_CERT_PATH=""
EOF
    fi
    chmod 600 "$STATUS_FILE"
}

# 读取状态
get_status() {
    local key=$1
    if [ -f "$STATUS_FILE" ]; then
        grep "^${key}=" "$STATUS_FILE" | cut -d'=' -f2
    fi
}

# 设置状态
set_status() {
    local key=$1
    local value=$2
    if [ -f "$STATUS_FILE" ]; then
        if grep -q "^${key}=" "$STATUS_FILE"; then
            sed -i "s|^${key}=.*|${key}=${value}|" "$STATUS_FILE"
        else
            echo "${key}=${value}" >> "$STATUS_FILE"
        fi
    fi
}

# 系统环境准备
prepare_system() {
    log "INFO" "准备系统环境..."
    
    # 设置非交互模式
    export DEBIAN_FRONTEND=noninteractive
    
    # 更新系统和安装基础包
    apt-get update && \
    apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" upgrade && \
    apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" \
        curl wget ufw socat

    # 设置系统优化参数
    log "INFO" "设置系统参数..."
    
    # 确保目录存在
    mkdir -p /etc/sysctl.d

    cat > /etc/sysctl.d/99-custom.conf << EOF
# 系统优化参数
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.ip_local_port_range = 10000 65000
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 5000
net.ipv4.tcp_max_orphans = 3276800
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_window_scaling = 1

# 网络性能优化
net.core.somaxconn = 32768
net.core.netdev_max_backlog = 32768
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 87380 16777216
EOF

    chmod 644 /etc/sysctl.d/99-custom.conf
    sysctl -p /etc/sysctl.d/99-custom.conf >/dev/null 2>&1
    
    # 设置时区
    log "INFO" "设置系统时区..."
    timedatectl set-timezone Asia/Shanghai

    # 检查宝塔面板
    log "INFO" "检查宝塔面板..."
    if [ ! -f "/etc/init.d/bt" ]; then
        log "ERROR" "未检测到宝塔面板，请先安装宝塔面板"
        return 1
    fi

    # 确保所有更改生效
    sync
    sleep 1

    set_status SYSTEM_PREPARED 1
    log "SUCCESS" "系统环境准备完成"
    return 0
}

# 定位宝塔面板证书
find_bt_cert() {
    local domain=$1
    log "INFO" "查找域名 ${domain} 的证书..."
    
    # 常见的宝塔证书位置
    local cert_paths=(
        "/www/server/panel/vhost/cert"
        "/www/server/panel/ssl"
    )

    for path in "${cert_paths[@]}"; do
        if [ -d "${path}/${domain}" ]; then
            if [ -f "${path}/${domain}/fullchain.pem" ] && [ -f "${path}/${domain}/privkey.pem" ]; then
                echo "${path}/${domain}"
                return 0
            fi
        fi
    done

    return 1
}

# 安装 HAProxy
install_haproxy() {
    log "INFO" "开始安装 HAProxy..."
    
    # 安装HAProxy
    apt-get update
    apt-get install -y haproxy

    local status=$?
    if [ $status -ne 0 ]; then
        # 如果默认安装失败，尝试使用官方源
        curl -fsSL https://haproxy.debian.net/bernat.debian.org.gpg | gpg --dearmor -o /usr/share/keyrings/haproxy.debian.net.gpg
        echo "deb [signed-by=/usr/share/keyrings/haproxy.debian.net.gpg] http://haproxy.debian.net bookworm-backports-2.8 main" > /etc/apt/sources.list.d/haproxy.list
        apt-get update
        apt-get install -y haproxy=2.8.\*
        status=$?
    fi

    if [ $status -ne 0 ]; then
        log "ERROR" "HAProxy 安装失败"
        return 1
    fi

    # 创建必要目录
    mkdir -p /etc/haproxy/certs
    chmod 700 /etc/haproxy/certs

    set_status HAPROXY_INSTALLED 1
    log "SUCCESS" "HAProxy 安装完成"
    return 0
}

# 配置HAProxy转发
configure_relay() {
    log "INFO" "配置端口转发..."
    
    # 获取域名
    read -p "请输入已配置SSL证书的域名: " domain
    if [ -z "$domain" ]; then
        log "ERROR" "域名不能为空"
        return 1
    fi

    # 查找宝塔面板证书
    local cert_path=$(find_bt_cert "$domain")
    if [ -z "$cert_path" ]; then
        log "ERROR" "未找到域名 ${domain} 的证书，请先在宝塔面板中申请证书"
        return 1
    fi

    # 合并证书文件供HAProxy使用
    log "INFO" "准备证书文件..."
    cat "${cert_path}/fullchain.pem" "${cert_path}/privkey.pem" > \
        "/etc/haproxy/certs/${domain}.pem.combined"
    chmod 600 "/etc/haproxy/certs/${domain}.pem.combined"
    chown haproxy:haproxy "/etc/haproxy/certs/${domain}.pem.combined"

    # 记录证书路径
    set_status BT_CERT_PATH "${cert_path}"
    set_status DOMAIN_NAME "${domain}"
    
    # 配置状态页面认证
    local stats_user
    local stats_pass
    while true; do
        read -p "请设置状态页面用户名 [默认随机生成]: " stats_user
        if [ -z "$stats_user" ]; then
            stats_user=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | fold -w 8 | head -n 1)
            log "INFO" "已生成随机用户名: $stats_user"
            break
        elif [[ "${#stats_user}" -ge 3 ]]; then
            break
        else
            log "ERROR" "用户名长度必须大于等于3位"
        fi
    done

    while true; do
        read -p "请设置状态页面密码 [默认随机生成]: " stats_pass
        if [ -z "$stats_pass" ]; then
            stats_pass=$(tr -dc 'a-zA-Z0-9!@#$%^&*()' < /dev/urandom | fold -w 16 | head -n 1)
            log "INFO" "已生成随机密码: $stats_pass"
            break
        elif [[ "${#stats_pass}" -ge 6 ]]; then
            break
        else
            log "ERROR" "密码长度必须大于等于6位"
        fi
    done

    # 询问上游服务器信息
    read -p "请输入上游服务器数量: " server_count
    
    # 备份配置
    if [ -f "/etc/haproxy/haproxy.cfg" ]; then
        cp /etc/haproxy/haproxy.cfg "/etc/haproxy/haproxy.cfg.bak.$(date +%Y%m%d%H%M%S)"
    fi
    
    # 创建基础配置
    cat > /etc/haproxy/haproxy.cfg << EOF
global
    log /dev/log local0
    log /dev/log local1 notice
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners
    stats timeout 30s
    user haproxy
    group haproxy
    daemon
    # SSL设置
    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305
    ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
    ssl-default-bind-options no-sslv3 no-tlsv10 no-tlsv11

defaults
    log     global
    mode    tcp
    option  dontlognull
    option  tcplog
    timeout connect 5000
    timeout client  50000
    timeout server  50000

# HTTPS状态页面
listen stats
    bind *:10086 ssl crt /etc/haproxy/certs/${domain}.pem.combined
    mode http
    stats enable
    stats hide-version
    stats uri /
    stats realm Haproxy\ Statistics
    stats auth ${stats_user}:'${stats_pass}'
    stats refresh 10s
    stats admin if TRUE
EOF

    local upstream_servers=""
    local listen_ports=""
    
    for ((i=1; i<=server_count; i++)); do
        read -p "请输入第${i}个上游服务器域名或IP: " server_addr
        read -p "请输入第${i}个上游服务器端口: " server_port
        read -p "请输入本地监听端口 [建议使用8443等]: " listen_port
        
        # 添加转发配置
        cat >> /etc/haproxy/haproxy.cfg << EOF

frontend ft_${listen_port}
    bind *:${listen_port} ssl crt /etc/haproxy/certs/${domain}.pem.combined
    mode tcp
    option tcplog
    default_backend bk_${server_addr}_${server_port}

backend bk_${server_addr}_${server_port}
    mode tcp
    option tcp-check
    server server1 ${server_addr}:${server_port} check inter 2000 rise 2 fall 3
EOF
        
        upstream_servers="${upstream_servers}${server_addr}:${server_port},"
        listen_ports="${listen_ports}${listen_port},"
    done

    # 检查配置语法
    if ! haproxy -c -f /etc/haproxy/haproxy.cfg; then
        log "ERROR" "配置文件有误，正在回滚..."
        if [ -f "/etc/haproxy/haproxy.cfg.bak" ]; then
            mv /etc/haproxy/haproxy.cfg.bak /etc/haproxy/haproxy.cfg
        fi
        return 1
    fi
    
    # 保存配置信息
    set_status STATS_USER "${stats_user}"
    set_status STATS_PASS "${stats_pass}"
    set_status UPSTREAM_SERVERS "${upstream_servers%,}"
    set_status LISTEN_PORTS "${listen_ports%,}"
    set_status MULTI_PORT_CONFIGURED 1
    
    # 重启HAProxy
    systemctl restart haproxy
    
    if ! systemctl is-active --quiet haproxy; then
        log "ERROR" "HAProxy 启动失败"
        return 1
    fi
    
    log "SUCCESS" "端口转发配置完成"
    return 0
}

# 配置 UFW 防火墙
configure_ufw() {
    log "INFO" "配置 UFW 防火墙..."
    
    # 检查UFW是否安装
    if ! command -v ufw >/dev/null 2>&1; then
        log "INFO" "安装 UFW..."
        apt-get update
        apt-get install -y ufw
    fi

    # 保存当前规则（如果有）
    if [ -f "/etc/ufw/user.rules" ]; then
        cp /etc/ufw/user.rules "/etc/ufw/user.rules.bak.$(date +%Y%m%d%H%M%S)"
    fi

    # 获取SSH端口
    local ssh_port=$(ss -tuln | grep -i ssh | awk '{print $5}' | awk -F: '{print $2}')
    ssh_port=${ssh_port:-22}
    
    # 重置UFW
    log "INFO" "重置防火墙规则..."
    ufw --force reset
    
    # 设置默认策略
    ufw default deny incoming
    ufw default allow outgoing
    
    # 允许SSH
    log "INFO" "配置SSH端口 ${ssh_port}..."
    ufw allow ${ssh_port}/tcp comment 'SSH'

    # 允许宝塔面板端口
    log "INFO" "配置宝塔面板端口..."
    ufw allow 16052/tcp comment 'BT Panel'
    ufw allow 888/tcp comment 'BT Panel'
    ufw allow 443/tcp comment 'BT Panel SSL'
    ufw allow 8888/tcp comment 'BT Panel'

    # 允许HAProxy端口
    local listen_ports=$(get_status LISTEN_PORTS)
    if [ -n "$listen_ports" ]; then
        log "INFO" "配置HAProxy端口..."
        IFS=',' read -ra PORTS <<< "$listen_ports"
        for port in "${PORTS[@]}"; do
            if [ -n "$port" ]; then
                ufw allow ${port}/tcp comment 'HAProxy'
            fi
        done
    fi
    
    # 允许状态页面端口
    log "INFO" "配置状态监控端口..."
    ufw allow 10086/tcp comment 'HAProxy Stats'

    # 启用UFW
    echo "y" | ufw enable

    # 验证UFW状态
    if ufw status | grep -q "Status: active"; then
        set_status UFW_CONFIGURED 1
        log "SUCCESS" "UFW 防火墙配置完成"
        
        # 显示配置的端口
        log "INFO" "已开放的端口："
        log "INFO" "- ${ssh_port}: SSH"
        log "INFO" "- 16052,888,443,8888: 宝塔面板"
        if [ -n "$listen_ports" ]; then
            log "INFO" "- ${listen_ports}: HAProxy服务"
        fi
        log "INFO" "- 10086: HAProxy状态监控"
        return 0
    else
        log "ERROR" "UFW 配置失败"
        return 1
    fi
}

# 安装 BBR 加速
install_bbr() {
    log "INFO" "配置 BBR..."
    
    if lsmod | grep -q bbr; then
        log "SUCCESS" "BBR 已经启用"
        set_status BBR_INSTALLED 1
        return 0
    fi
    
    # 配置BBR
    cat > /etc/sysctl.d/99-bbr.conf << EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF

    sysctl -p /etc/sysctl.d/99-bbr.conf

    # 验证BBR状态
    if lsmod | grep -q bbr; then
        set_status BBR_INSTALLED 1
        log "SUCCESS" "BBR 配置完成"
        return 0
    else
        log "ERROR" "BBR 配置失败"
        return 1
    fi
}

# 显示配置信息
show_config() {
    echo "====================== 配置信息 ======================"
    
    # 显示域名信息
    local domain=$(get_status DOMAIN_NAME)
    if [ -n "$domain" ]; then
        echo -e "域名: ${GREEN}${domain}${PLAIN}"
    fi
    
    # 显示转发规则
    local upstream_servers=$(get_status UPSTREAM_SERVERS)
    local listen_ports=$(get_status LISTEN_PORTS)
    if [ -n "$upstream_servers" ] && [ -n "$listen_ports" ]; then
        echo -e "\n转发规则："
        IFS=',' read -ra SERVERS <<< "$upstream_servers"
        IFS=',' read -ra PORTS <<< "$listen_ports"
        
        for i in "${!SERVERS[@]}"; do
            echo -e "规则 $((i+1)):"
            echo -e "  本地端口: ${GREEN}${PORTS[i]}${PLAIN}"
            echo -e "  上游服务器: ${GREEN}${SERVERS[i]}${PLAIN}"
        done
    fi
    
    # 显示HAProxy状态页面信息
    local stats_user=$(get_status STATS_USER)
    local stats_pass=$(get_status STATS_PASS)
    
    echo -e "\nHAProxy 状态页面："
    if [ -n "$domain" ]; then
        echo -e "  地址: https://${domain}:10086"
    else
        echo -e "  地址: https://服务器IP:10086"
    fi
    echo -e "  用户名: ${GREEN}${stats_user}${PLAIN}"
    echo -e "  密码: ${GREEN}${stats_pass}${PLAIN}"

    # 显示宝塔面板信息
    echo -e "\n宝塔面板："
    echo -e "  面板地址: https://服务器IP:16052"

    echo "==================================================="
}

# 显示运行状态
show_status() {
    echo "====================== 运行状态 ======================"
    
    # 检查宝塔面板状态
    echo -e "\n[ 宝塔面板状态 ]"
    if [ -f "/etc/init.d/bt" ]; then
        if /etc/init.d/bt status | grep -q "running"; then
            echo -e "宝塔面板: ${GREEN}运行中${PLAIN}"
        else
            echo -e "宝塔面板: ${RED}已停止${PLAIN}"
        fi
    else
        echo -e "宝塔面板: ${RED}未安装${PLAIN}"
    fi
    
    # 检查HAProxy状态
    echo -e "\n[ HAProxy状态 ]"
    if systemctl is-active --quiet haproxy; then
        echo -e "HAProxy: ${GREEN}运行中${PLAIN}"
    else
        echo -e "HAProxy: ${RED}已停止${PLAIN}"
    fi
    
    # 检查端口状态
    echo -e "\n[ 端口状态 ]"
    local listen_ports=$(get_status LISTEN_PORTS)
    if [ -n "$listen_ports" ]; then
        IFS=',' read -ra PORTS <<< "$listen_ports"
        for port in "${PORTS[@]}"; do
            if ss -tuln | grep -q ":${port} "; then
                echo -e "端口 ${port}: ${GREEN}监听中${PLAIN}"
            else
                echo -e "端口 ${port}: ${RED}未监听${PLAIN}"
            fi
        done
    fi
    
    # 检查防火墙状态
    echo -e "\n[ 防火墙状态 ]"
    if command -v ufw >/dev/null 2>&1; then
        if ufw status | grep -q "Status: active"; then
            echo -e "UFW: ${GREEN}已启用${PLAIN}"
        else
            echo -e "UFW: ${RED}已禁用${PLAIN}"
        fi
    else
        echo -e "UFW: ${RED}未安装${PLAIN}"
    fi
    
    # 检查BBR状态
    echo -e "\n[ BBR状态 ]"
    if lsmod | grep -q bbr; then
        echo -e "BBR: ${GREEN}已启用${PLAIN}"
    else
        echo -e "BBR: ${RED}未启用${PLAIN}"
    fi

    echo "==================================================="
}

# 显示菜单
show_menu() {
    clear
    echo "=========== HAProxy 中转管理系统 ==========="
    echo -e "当前搭配宝塔面板使用"
    echo -e " 1. 系统环境准备 $(if [ "$(get_status SYSTEM_PREPARED)" = "1" ]; then echo "${GREEN}[OK]${PLAIN}"; fi)"
    echo -e " 2. 安装 HAProxy $(if [ "$(get_status HAPROXY_INSTALLED)" = "1" ]; then echo "${GREEN}[OK]${PLAIN}"; fi)"
    echo -e " 3. 配置端口转发 $(if [ "$(get_status MULTI_PORT_CONFIGURED)" = "1" ]; then echo "${GREEN}[OK]${PLAIN}"; fi)"
    echo -e " 4. 配置 UFW 防火墙 $(if [ "$(get_status UFW_CONFIGURED)" = "1" ]; then echo "${GREEN}[OK]${PLAIN}"; fi)"
    echo -e " 5. 安装 BBR 加速 $(if [ "$(get_status BBR_INSTALLED)" = "1" ]; then echo "${GREEN}[OK]${PLAIN}"; fi)"
    echo " 6. 查看配置信息"
    echo " 7. 查看运行状态"
    echo " 8. 重启 HAProxy"
    echo " 9. 卸载组件"
    echo " 0. 退出"
    echo "=========================================="
}

# 检查是否需要重新安装
check_reinstall() {
    local component=$1
    local status_key=$2
    if [ "$(get_status $status_key)" = "1" ]; then
        read -p "${component}已安装，是否重新安装？[y/N] " answer
        if [[ "${answer,,}" != "y" ]]; then
            return 1
        fi
    fi
    return 0
}

# 主函数
main() {
    # 检查root权限
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}错误：请使用 root 用户运行此脚本${PLAIN}"
        exit 1
    fi

    # 检查系统
    if ! grep -qi "debian" /etc/os-release; then
        echo -e "${RED}错误：此脚本仅支持 Debian 系统${PLAIN}"
        exit 1
    fi

    # 检查宝塔面板
    if [ ! -f "/etc/init.d/bt" ]; then
        echo -e "${RED}错误：未检测到宝塔面板，请先安装宝塔面板${PLAIN}"
        exit 1
    fi

    # 初始化
    init_status_file
    
    # 主循环
    while true; do
        show_menu
        read -p "请选择操作[0-9]: " choice
        case "${choice}" in
            0) exit 0 ;;
            1) check_reinstall "系统环境" "SYSTEM_PREPARED" && prepare_system ;;
            2) check_reinstall "HAProxy" "HAPROXY_INSTALLED" && install_haproxy ;;
            3) check_reinstall "端口转发" "MULTI_PORT_CONFIGURED" && configure_relay ;;
            4) check_reinstall "UFW防火墙" "UFW_CONFIGURED" && configure_ufw ;;
            5) check_reinstall "BBR加速" "BBR_INSTALLED" && install_bbr ;;
            6) show_config ;;
            7) show_status ;;
            8) systemctl restart haproxy ;;
            9) uninstall_all ;;
            *) log "ERROR" "无效的选择" ;;
        esac
        echo
        read -p "按回车键继续..." </dev/tty
    done
}

# 启动脚本
main "$@"
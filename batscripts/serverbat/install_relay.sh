#!/bin/bash
# install_relay.sh - Debian 12 一键安装 HAProxy 中转管理脚本

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
NGINX_INSTALLED=0
CERT_INSTALLED=0
MULTI_PORT_CONFIGURED=0
UFW_CONFIGURED=0
BBR_INSTALLED=0
UPSTREAM_SERVERS=""
LISTEN_PORTS=""
STATS_USER=""
STATS_PASS=""
DOMAIN_NAME=""
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

# 网络连接检查
check_network_connectivity() {
    local domain=$1
    log "INFO" "执行网络诊断..."

    # 临时禁用防火墙进行测试
    log "INFO" "临时禁用防火墙进行测试..."
    if command -v ufw >/dev/null 2>&1; then
        ufw disable
    fi

    # 检查80端口
    log "INFO" "检查80端口状态..."
    if ss -tuln | grep -q ':80 '; then
        log "WARNING" "80端口已被占用，尝试释放..."
        fuser -k 80/tcp
        sleep 2
    fi

    # 检查并安装必要的软件
    if ! command -v python3 >/dev/null 2>&1; then
        log "INFO" "安装Python3..."
        apt-get update >/dev/null 2>&1
        apt-get install -y python3 >/dev/null 2>&1
    fi

    # 使用Python启动临时Web服务器测试端口
    log "INFO" "测试Web服务..."
    # 创建测试页面
    mkdir -p /var/www/html
    echo "port test" > /var/www/html/test.html
    
    # 启动Python Web服务器（带超时）
    timeout 10 python3 -m http.server 80 --directory /var/www/html >/dev/null 2>&1 &
    WEB_PID=$!
    sleep 2

    # 测试连接
    local port_test=0
    if curl -s --connect-timeout 5 http://localhost/test.html >/dev/null 2>&1; then
        log "SUCCESS" "本地80端口测试成功"
        port_test=1
    else
        log "ERROR" "本地80端口测试失败"
    fi

    # 停止测试服务器
    kill $WEB_PID 2>/dev/null
    wait $WEB_PID 2>/dev/null

    # 如果本地测试失败，直接返回
    if [ $port_test -eq 0 ]; then
        return 1
    fi

    # 检查DNS服务器
    log "INFO" "配置DNS服务器..."
    cp /etc/resolv.conf /etc/resolv.conf.bak
    {
        echo "nameserver 8.8.8.8"
        echo "nameserver 1.1.1.1"
        echo "nameserver 208.67.222.222"
    } > /etc/resolv.conf

    # 检查基本网络连接
    log "INFO" "检查基本网络连接..."
    if ! ping -c 4 8.8.8.8 >/dev/null 2>&1; then
        log "ERROR" "无法连接到8.8.8.8，基本网络可能有问题"
        return 1
    fi

    # 检查域名解析
    log "INFO" "检查域名解析..."
    local domain_ip=$(dig +short ${domain} | tail -n1)
    local server_ip=$(curl -s ifconfig.me || curl -s ip.sb)
    
    if [ -z "$domain_ip" ]; then
        log "ERROR" "无法解析域名 ${domain}"
        return 1
    elif [ "$domain_ip" != "$server_ip" ]; then
        log "ERROR" "域名解析IP（${domain_ip}）与服务器IP（${server_ip}）不匹配"
        return 1
    fi

    # 检查HTTPS连接
    log "INFO" "检查HTTPS连接..."
    if ! curl -sI --connect-timeout 10 https://acme-v02.api.letsencrypt.org/directory >/dev/null 2>&1; then
        log "WARNING" "HTTPS连接测试失败，尝试IPv4连接..."
        if ! curl -sI -4 --connect-timeout 10 https://acme-v02.api.letsencrypt.org/directory >/dev/null 2>&1; then
            log "ERROR" "HTTPS连接失败"
            return 1
        fi
    fi

    log "SUCCESS" "网络诊断完成"
    return 0
}

# 系统环境准备
prepare_system() {
    log "INFO" "准备系统环境..."
    
    # 预先配置 kexec-tools
    echo 'LOAD_KEXEC=false' > /etc/default/kexec
    
    # 设置非交互模式
    export DEBIAN_FRONTEND=noninteractive
    
    # 更新系统和安装基础包
    apt-get update && \
    apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" upgrade && \
    apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" \
        curl wget unzip ufw socat python3 cron

    # 验证必要软件是否安装成功
    local required_packages=("curl" "wget" "unzip" "ufw" "socat" "python3")
    local missing_packages=()
    
    for pkg in "${required_packages[@]}"; do
        if ! command -v $pkg >/dev/null 2>&1; then
            missing_packages+=($pkg)
        fi
    done
    
    if [ ${#missing_packages[@]} -ne 0 ]; then
        log "ERROR" "以下软件包安装失败: ${missing_packages[*]}"
        return 1
    fi

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

    # 确保所有更改生效
    sync
    sleep 1

    set_status SYSTEM_PREPARED 1
    log "SUCCESS" "系统环境准备完成"
    return 0
}

# 证书申请
install_cert() {
    log "INFO" "开始申请SSL证书..."
    
    # 获取域名
    local domain
    if [ -n "$(get_status DOMAIN_NAME)" ]; then
        read -p "已配置域名$(get_status DOMAIN_NAME)，是否使用新域名？[y/N] " change_domain
        if [[ "${change_domain,,}" != "y" ]]; then
            domain=$(get_status DOMAIN_NAME)
        fi
    fi
    
    if [ -z "$domain" ]; then
        read -p "请输入你的域名：" domain
        if [ -z "$domain" ]; then
            log "ERROR" "域名不能为空"
            return 1
        fi
    fi
    
    # 创建必要的目录
    mkdir -p /etc/haproxy/certs
    chmod 700 /etc/haproxy/certs
    mkdir -p /var/www/html/.well-known/acme-challenge
    chmod -R 755 /var/www/html

    # 检查网络连接
    if ! check_network_connectivity "$domain"; then
        log "ERROR" "网络检查失败，无法继续申请证书"
        return 1
    fi

    # 停止可能占用端口的服务
    for service in nginx haproxy apache2; do
        if systemctl is-active --quiet $service; then
            log "INFO" "停止 ${service}..."
            systemctl stop $service
        fi
    done

    # 安装acme.sh
    log "INFO" "安装 acme.sh..."
    if [ ! -f ~/.acme.sh/acme.sh ]; then
        curl -s https://get.acme.sh | sh -s email=admin@${domain}
        if [ $? -ne 0 ]; then
            log "ERROR" "acme.sh 安装失败"
            return 1
        fi

        source ~/.bashrc
        source ~/.profile >/dev/null 2>&1
        sleep 2
    else
        log "INFO" "acme.sh 已安装，尝试更新..."
        ~/.acme.sh/acme.sh --upgrade --auto-upgrade
    fi

    # 配置acme.sh
    ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt

    # 启动临时Web服务器
    log "INFO" "启动临时Web服务器..."
    python3 -m http.server 80 --directory /var/www/html &
    WEB_PID=$!
    sleep 2

    # 申请证书
    log "INFO" "申请SSL证书..."
    ~/.acme.sh/acme.sh --issue -d ${domain} --webroot /var/www/html \
        --keylength ec-256 \
        --key-file /etc/haproxy/certs/${domain}.key \
        --fullchain-file /etc/haproxy/certs/${domain}.pem \
        --force \
        --log "/var/log/acme.sh.log"

    # 保存申请结果
    local cert_status=$?

    # 停止临时Web服务器
    kill $WEB_PID 2>/dev/null
    wait $WEB_PID 2>/dev/null

    # 处理申请结果
    if [ $cert_status -ne 0 ]; then
        log "ERROR" "证书申请失败"
        log "INFO" "查看详细日志: cat /var/log/acme.sh.log"
        return 1
    fi

    # 验证证书文件
    if [ ! -f "/etc/haproxy/certs/${domain}.pem" ] || \
       [ ! -f "/etc/haproxy/certs/${domain}.key" ]; then
        log "ERROR" "证书文件未生成"
        return 1
    fi

    # 合并证书文件
    cat /etc/haproxy/certs/${domain}.pem /etc/haproxy/certs/${domain}.key > \
        /etc/haproxy/certs/${domain}.pem.combined

    # 设置证书权限
    chmod 600 /etc/haproxy/certs/${domain}.pem.combined
    chown haproxy:haproxy /etc/haproxy/certs/${domain}.pem.combined

    # 配置证书自动更新
    ~/.acme.sh/acme.sh --install-cert -d ${domain} \
        --key-file /etc/haproxy/certs/${domain}.key \
        --fullchain-file /etc/haproxy/certs/${domain}.pem \
        --reloadcmd "cat /etc/haproxy/certs/${domain}.pem /etc/haproxy/certs/${domain}.key > /etc/haproxy/certs/${domain}.pem.combined && chmod 600 /etc/haproxy/certs/${domain}.pem.combined && chown haproxy:haproxy /etc/haproxy/certs/${domain}.pem.combined && systemctl reload haproxy"

    set_status CERT_INSTALLED 1
    set_status DOMAIN_NAME ${domain}
    
    log "SUCCESS" "SSL证书配置完成"
    return 0
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

    # 验证安装
    if ! command -v haproxy >/dev/null 2>&1; then
        log "ERROR" "HAProxy未正确安装"
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
    
    # 检查证书
    local domain=$(get_status DOMAIN_NAME)
    if [ ! -f "/etc/haproxy/certs/${domain}.pem.combined" ]; then
        log "ERROR" "未找到SSL证书，请先申请证书"
        return 1
    fi
    
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
        if [ -n "$listen_ports" ]; then
            log "INFO" "- ${listen_ports}: HAProxy服务"
        fi
        log "INFO" "- 10086: 状态监控"
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
    cat >> /etc/sysctl.d/99-bbr.conf << EOF
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

# 重启服务
restart_services() {
    log "INFO" "重启服务..."
    local has_error=0

    # 重启HAProxy
    if systemctl is-enabled haproxy >/dev/null 2>&1; then
        log "INFO" "重启 HAProxy..."
        systemctl restart haproxy
        if ! systemctl is-active --quiet haproxy; then
            log "ERROR" "HAProxy 重启失败"
            has_error=1
        fi
    fi

    # 重启Nginx（如果已安装）
    if systemctl is-enabled nginx >/dev/null 2>&1; then
        log "INFO" "重启 Nginx..."
        systemctl restart nginx
        if ! systemctl is-active --quiet nginx; then
            log "ERROR" "Nginx 重启失败"
            has_error=1
        fi
    fi

    # 检查端口
    log "INFO" "检查端口状态..."
    local listen_ports=$(get_status LISTEN_PORTS)
    if [ -n "$listen_ports" ]; then
        IFS=',' read -ra PORTS <<< "$listen_ports"
        for port in "${PORTS[@]}"; do
            if ! ss -tuln | grep -q ":${port} "; then
                log "ERROR" "端口 ${port} 未正常监听"
                has_error=1
            fi
        done
    fi

    if [ $has_error -eq 0 ]; then
        log "SUCCESS" "服务重启完成"
        return 0
    else
        log "ERROR" "服务重启过程中出现错误"
        return 1
    fi
}

# 卸载组件
uninstall_all() {
    log "WARNING" "即将卸载所有组件..."
    read -p "确定要卸载吗？[y/N] " answer
    if [[ "${answer,,}" != "y" ]]; then
        return 0
    fi
    
    # 停止服务
    log "INFO" "停止服务..."
    for service in nginx haproxy; do
        if systemctl is-active --quiet $service; then
            systemctl stop $service
            systemctl disable $service
        fi
    done
    
    # 卸载软件包
    log "INFO" "卸载软件包..."
    apt remove --purge -y nginx nginx-common haproxy
    
    # 清理证书
    if [ -d ~/.acme.sh ]; then
        log "INFO" "清理证书..."
        ~/.acme.sh/acme.sh --uninstall
        rm -rf ~/.acme.sh
    fi
    
    # 清理配置文件
    log "INFO" "清理配置文件..."
    rm -rf /etc/nginx
    rm -rf /etc/haproxy
    rm -rf $INSTALL_STATUS_DIR
    rm -rf /var/www/html/*
    rm -f /var/log/acme.sh.log
    
    # 禁用UFW
    log "INFO" "禁用防火墙..."
    if command -v ufw >/dev/null 2>&1; then
        ufw disable
    fi
    
    # 清理系统参数
    if [ -f "/etc/sysctl.d/99-custom.conf" ]; then
        rm -f /etc/sysctl.d/99-custom.conf
    fi
    if [ -f "/etc/sysctl.d/99-bbr.conf" ]; then
        rm -f /etc/sysctl.d/99-bbr.conf
    fi
    
    log "SUCCESS" "卸载完成"
    
    # 询问是否重启
    read -p "是否需要重启系统来完成清理？[y/N] " reboot_answer
    if [[ "${reboot_answer,,}" == "y" ]]; then
        log "INFO" "系统将在3秒后重启..."
        sleep 3
        reboot
    fi
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

# 显示配置信息
show_config() {
    echo "====================== 配置信息 ======================"
    
    # 显示域名信息
    local domain=$(get_status DOMAIN_NAME)
    if [ -n "$domain" ]; then
        echo -e "域名: ${GREEN}${domain}${PLAIN}"
        
        # 显示域名解析
        local domain_ip=$(dig +short ${domain})
        local server_ip=$(curl -s ifconfig.me)
        echo "域名解析: ${domain_ip}"
        echo "服务器IP: ${server_ip}"
        
        # 检查解析是否正确
        if [ "$domain_ip" != "$server_ip" ]; then
            echo -e "${YELLOW}警告: 域名解析IP与服务器IP不匹配${PLAIN}"
        fi
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
    
    # 显示证书信息
    if [ -n "$domain" ] && [ -f "/etc/haproxy/certs/${domain}.pem" ]; then
        echo -e "\nSSL证书信息："
        openssl x509 -in "/etc/haproxy/certs/${domain}.pem" -noout -dates
    fi

    echo "==================================================="
}

# 显示运行状态
show_status() {
    echo "====================== 运行状态 ======================"
    
    # 检查系统服务
    echo -e "\n[ 服务状态 ]"
    for service in nginx haproxy; do
        if systemctl is-enabled $service >/dev/null 2>&1; then
            status=$(systemctl is-active $service)
            if [ "$status" = "active" ]; then
                echo -e "$service: ${GREEN}运行中${PLAIN}"
            else
                echo -e "$service: ${RED}已停止${PLAIN}"
            fi
        else
            echo -e "$service: ${YELLOW}未安装${PLAIN}"
        fi
    done
    
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
    
    # 检查证书状态
    local domain=$(get_status DOMAIN_NAME)
    if [ -n "$domain" ]; then
        echo -e "\n[ 证书状态 ]"
        if [ -f "/etc/haproxy/certs/${domain}.pem" ]; then
            local cert_end=$(openssl x509 -in "/etc/haproxy/certs/${domain}.pem" -noout -enddate | cut -d= -f2)
            local cert_time=$(date -d "${cert_end}" +%s)
            local now_time=$(date +%s)
            local days_left=$(( ($cert_time - $now_time) / 86400 ))
            
            if [ $days_left -gt 30 ]; then
                echo -e "证书状态: ${GREEN}正常${PLAIN} (剩余 ${days_left} 天)"
            elif [ $days_left -gt 0 ]; then
                echo -e "证书状态: ${YELLOW}即将过期${PLAIN} (剩余 ${days_left} 天)"
            else
                echo -e "证书状态: ${RED}已过期${PLAIN}"
            fi
        else
            echo -e "证书状态: ${RED}未找到${PLAIN}"
        fi
    fi
    
    # 检查防火墙状态
    echo -e "\n[ 防火墙状态 ]"
    if command -v ufw >/dev/null 2>&1; then
        ufw status | grep Status
    else
        echo "UFW未安装"
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
    echo -e " 1. 系统环境准备 $(if [ "$(get_status SYSTEM_PREPARED)" = "1" ]; then echo "${GREEN}[OK]${PLAIN}"; fi)"
    echo -e " 2. 申请SSL证书 $(if [ "$(get_status CERT_INSTALLED)" = "1" ]; then echo "${GREEN}[OK]${PLAIN}"; fi)"
    echo -e " 3. 安装 HAProxy $(if [ "$(get_status HAPROXY_INSTALLED)" = "1" ]; then echo "${GREEN}[OK]${PLAIN}"; fi)"
    echo -e " 4. 配置端口转发 $(if [ "$(get_status MULTI_PORT_CONFIGURED)" = "1" ]; then echo "${GREEN}[OK]${PLAIN}"; fi)"
    echo -e " 5. 配置 UFW 防火墙 $(if [ "$(get_status UFW_CONFIGURED)" = "1" ]; then echo "${GREEN}[OK]${PLAIN}"; fi)"
    echo -e " 6. 安装 BBR 加速 $(if [ "$(get_status BBR_INSTALLED)" = "1" ]; then echo "${GREEN}[OK]${PLAIN}"; fi)"
    echo " 7. 查看配置信息"
    echo " 8. 查看运行状态"
    echo " 9. 重启服务"
    echo " 10. 卸载组件"
    echo " 0. 退出"
    echo "=========================================="
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

    # 初始化
    init_status_file
    
    # 主循环
    while true; do
        show_menu
        read -p "请选择操作[0-10]: " choice
        case "${choice}" in
            0) exit 0 ;;
            1) check_reinstall "系统环境" "SYSTEM_PREPARED" && prepare_system ;;
            2) check_reinstall "SSL证书" "CERT_INSTALLED" && install_cert ;;
            3) check_reinstall "HAProxy" "HAPROXY_INSTALLED" && install_haproxy ;;
            4) check_reinstall "端口转发" "MULTI_PORT_CONFIGURED" && configure_relay ;;
            5) check_reinstall "UFW防火墙" "UFW_CONFIGURED" && configure_ufw ;;
            6) check_reinstall "BBR加速" "BBR_INSTALLED" && install_bbr ;;
            7) show_config ;;
            8) show_status ;;
            9) restart_services ;;
            10) uninstall_all ;;
            *) log "ERROR" "无效的选择" ;;
        esac
        echo
        read -p "按回车键继续..." </dev/tty
    done
}

# 启动脚本
main "$@"
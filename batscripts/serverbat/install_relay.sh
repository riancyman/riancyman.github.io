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
        # 验证设置是否成功
        if [ "$(get_status $key)" = "$value" ]; then
            return 0
        fi
    fi
    return 1
}

# 检查端口是否被占用
check_port() {
    local port=$1
    if ss -tuln | grep -q ":${port} "; then
        return 1
    fi
    return 0
}

# 系统环境准备
prepare_system() {
    log "INFO" "准备系统环境..."
    
    # 预先配置 kexec-tools
    echo 'LOAD_KEXEC=false' > /etc/default/kexec
    
    # 设置非交互模式
    export DEBIAN_FRONTEND=noninteractive
    
    # 更新系统
    log "INFO" "更新系统..."
    if ! apt-get update; then
        log "ERROR" "系统更新失败"
        return 1
    fi
    
    # 更新软件包
    log "INFO" "更新软件包..."
    if ! apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" upgrade; then
        log "ERROR" "软件包更新失败"
        return 1
    fi
    
    # 安装基础包
    log "INFO" "安装基础软件包..."
    if ! apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" \
        curl wget unzip ufw socat nginx python3; then
        log "ERROR" "基础软件包安装失败"
        return 1
    fi
    
    # 验证必要软件是否安装成功
    local required_packages=("curl" "wget" "unzip" "ufw" "socat" "nginx" "python3")
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
    cat >> /etc/sysctl.conf << EOF
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
EOF
    
    # 应用系统参数
    if ! sysctl -p; then
        log "WARNING" "系统参数设置可能未完全生效"
    fi
    
    # 设置时区
    log "INFO" "设置系统时区..."
    timedatectl set-timezone Asia/Shanghai
    
    # 所有检查通过，设置状态并返回
    if set_status SYSTEM_PREPARED 1; then
        log "SUCCESS" "系统环境准备完成"
        return 0
    else
        log "ERROR" "状态设置失败"
        return 1
    fi
}

# 申请SSL证书
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
    
    # 创建证书目录
    mkdir -p /etc/haproxy/certs
    chmod 700 /etc/haproxy/certs

    # 停止相关服务
    systemctl stop nginx haproxy

    # 安装acme.sh
    if [ ! -f ~/.acme.sh/acme.sh ]; then
        log "INFO" "安装 acme.sh..."
        curl -fsSL https://get.acme.sh | sh -s email=admin@${domain}
        if [ $? -ne 0 ]; then
            log "ERROR" "acme.sh 安装失败"
            return 1
        fi
        source ~/.bashrc
    else
        log "INFO" "acme.sh 已安装，尝试更新..."
        ~/.acme.sh/acme.sh --upgrade
    fi

    # 申请证书
    log "INFO" "申请SSL证书..."
    ~/.acme.sh/acme.sh --issue -d ${domain} --standalone \
        --keylength ec-256 \
        --key-file /etc/haproxy/certs/${domain}.key \
        --fullchain-file /etc/haproxy/certs/${domain}.pem

    if [ $? -ne 0 ]; then
        log "ERROR" "证书申请失败"
        systemctl start nginx haproxy
        return 1
    fi

    # 合并证书和私钥为HAProxy格式
    cat /etc/haproxy/certs/${domain}.pem /etc/haproxy/certs/${domain}.key > \
        /etc/haproxy/certs/${domain}.pem.combined

    # 设置证书权限
    chmod 600 /etc/haproxy/certs/${domain}.pem.combined
    chown haproxy:haproxy /etc/haproxy/certs/${domain}.pem.combined

    # 验证证书 【新增的验证部分】
    if [ -f "/etc/haproxy/certs/${domain}.pem.combined" ]; then
        if ! openssl x509 -in "/etc/haproxy/certs/${domain}.pem" -noout -checkend 0; then
            log "ERROR" "证书无效或已过期"
            return 1
        fi
    else
        log "ERROR" "证书文件不存在"
        return 1
    fi

    # 配置证书自动更新
    ~/.acme.sh/acme.sh --install-cert -d ${domain} \
        --key-file /etc/haproxy/certs/${domain}.key \
        --fullchain-file /etc/haproxy/certs/${domain}.pem \
        --reloadcmd "cat /etc/haproxy/certs/${domain}.pem /etc/haproxy/certs/${domain}.key > /etc/haproxy/certs/${domain}.pem.combined && chmod 600 /etc/haproxy/certs/${domain}.pem.combined && chown haproxy:haproxy /etc/haproxy/certs/${domain}.pem.combined && systemctl restart haproxy"

    # 重启服务
    systemctl start nginx haproxy

    # 保存配置
    set_status CERT_INSTALLED 1
    set_status DOMAIN_NAME ${domain}
    
    log "SUCCESS" "SSL证书配置完成"
    return 0
}

# 配置Nginx伪装站点
configure_nginx() {
    log "INFO" "配置Nginx伪装站点..."
    
    # 检查是否需要重新配置域名
    local domain
    if [ -n "$(get_status DOMAIN_NAME)" ]; then
        domain=$(get_status DOMAIN_NAME)
    else
        read -p "请输入你的域名: " domain
        if [ -z "$domain" ]; then
            log "ERROR" "域名不能为空"
            return 1
        fi
    fi

    # 确保配置目录存在
    mkdir -p /etc/nginx/conf.d
    
    # 配置Nginx
    cat > /etc/nginx/conf.d/default.conf << EOF
server {
    listen 80;
    server_name ${domain};
    root /var/www/html;
    index index.html;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF

    # 配置伪装站点
    echo "请选择伪装站点类型："
    echo "1. 个人博客"
    echo "2. 企业官网"
    echo "3. 图片站"
    echo "4. 下载站"
    echo "5. 自定义网站"
    read -p "请选择 [1-5]: " site_type
    
    # 配置Nginx
    cat > /etc/nginx/conf.d/default.conf << EOF
server {
    listen 80;
    server_name ${domain};
    root /var/www/html;
    index index.html;
    
    # SSL配置
    listen 443 ssl;
    ssl_certificate /etc/haproxy/certs/${domain}.pem;
    ssl_certificate_key /etc/haproxy/certs/${domain}.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers on;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF

    # 根据选择配置不同的伪装站点
    case "$site_type" in
        1)
            # 个人博客模板
            cat > /var/www/html/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>My Personal Blog</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; }
        .container { max-width: 800px; margin: 0 auto; }
        h1 { color: #333; }
        .article { margin-bottom: 20px; padding: 20px; background: #f9f9f9; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome to My Blog</h1>
        <div class="article">
            <h2>Latest Post</h2>
            <p>This is my latest blog post about technology and life...</p>
        </div>
    </div>
</body>
</html>
EOF
            ;;
        2)
            # 企业官网模板
            cat > /var/www/html/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Company Name</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 0; }
        .header { background: #2c3e50; color: white; padding: 40px 20px; text-align: center; }
        .content { max-width: 1000px; margin: 0 auto; padding: 20px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Welcome to Our Company</h1>
        <p>Leading Innovation in Technology</p>
    </div>
    <div class="content">
        <h2>About Us</h2>
        <p>We are a leading technology company...</p>
    </div>
</body>
</html>
EOF
            ;;
        3)
            # 图片站模板
            cat > /var/www/html/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Photo Gallery</title>
    <meta charset="utf-8">
    <style>
        body { background: #000; color: #fff; font-family: Arial, sans-serif; }
        .gallery { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 20px; padding: 20px; }
        .photo { background: #333; height: 200px; display: flex; align-items: center; justify-content: center; }
    </style>
</head>
<body>
    <div class="gallery">
        <div class="photo">Photo 1</div>
        <div class="photo">Photo 2</div>
        <div class="photo">Photo 3</div>
    </div>
</body>
</html>
EOF
            ;;
        4)
            # 下载站模板
            cat > /var/www/html/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Download Center</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }
        .download-item { background: #f5f5f5; padding: 20px; margin: 10px 0; border-radius: 5px; }
        .button { background: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 3px; }
    </style>
</head>
<body>
    <h1>Download Center</h1>
    <div class="download-item">
        <h3>Software v1.0</h3>
        <p>Latest version with new features</p>
        <a href="#" class="button">Download</a>
    </div>
</body>
</html>
EOF
            ;;
        5)
            # 自定义网站
            read -p "请输入自定义网站URL: " custom_url
            if [ -n "$custom_url" ]; then
                wget -O /var/www/html/index.html "$custom_url"
                if [ $? -ne 0 ]; then
                    log "ERROR" "下载自定义网站失败，使用默认页面"
                    echo "<h1>Welcome</h1>" > /var/www/html/index.html
                fi
            fi
            ;;
    esac

    # 设置目录和权限
    mkdir -p /var/www/html
    chown -R www-data:www-data /var/www/html
    chmod -R 755 /var/www/html
    
    # 保存域名到状态文件
    if ! set_status DOMAIN_NAME "${domain}"; then
        log "ERROR" "保存域名配置失败"
        return 1
    fi
    
    # 检查Nginx配置语法
    if ! nginx -t; then
        log "ERROR" "Nginx配置检查失败"
        return 1
    fi
    
    # 重启Nginx
    systemctl restart nginx
    sleep 2  # 等待服务启动
    
    # 全面检查Nginx状态
    local nginx_status=0
    # 检查服务是否运行
    if ! systemctl is-active --quiet nginx; then
        log "ERROR" "Nginx服务未运行"
        nginx_status=1
    fi
    
    # 检查配置文件是否存在
    if [ ! -f "/etc/nginx/conf.d/default.conf" ]; then
        log "ERROR" "Nginx配置文件不存在"
        nginx_status=1
    fi
    
    # 检查网站文件是否存在
    if [ ! -f "/var/www/html/index.html" ]; then
        log "ERROR" "网站文件不存在"
        nginx_status=1
    fi
    
    # 检查80端口是否在监听
    if ! ss -tuln | grep -q ':80 '; then
        log "ERROR" "80端口未监听"
        nginx_status=1
    fi
    
    if [ $nginx_status -eq 0 ]; then
        if set_status NGINX_INSTALLED 1; then
            log "SUCCESS" "Nginx伪装站点配置完成"
            return 0
        else
            log "ERROR" "状态保存失败"
            return 1
        fi
    else
        log "ERROR" "Nginx配置失败"
        return 1
    fi
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

    # 创建证书目录
    mkdir -p /etc/haproxy/certs
    chmod 700 /etc/haproxy/certs

    # 验证安装
    if ! command -v haproxy >/dev/null 2>&1; then
        log "ERROR" "HAProxy未正确安装"
        return 1
    fi

    # 验证版本
    local version=$(haproxy -v 2>&1 | head -n1)
    log "INFO" "HAProxy版本: $version"

    # 验证服务状态
    if ! systemctl is-enabled haproxy >/dev/null 2>&1; then
        log "ERROR" "HAProxy服务未启用"
        return 1
    fi

    # 验证配置目录
    if [ ! -d "/etc/haproxy" ]; then
        log "ERROR" "HAProxy配置目录不存在"
        return 1
    fi

    # 验证证书目录权限
    if [ ! -d "/etc/haproxy/certs" ] || [ "$(stat -c '%a' /etc/haproxy/certs)" != "700" ]; then
        log "ERROR" "证书目录权限配置错误"
        return 1
    fi

    # 所有检查通过后设置状态
    if set_status HAPROXY_INSTALLED 1; then
        log "SUCCESS" "HAProxy 安装完成"
        return 0
    else
        log "ERROR" "状态设置失败"
        return 1
    fi
}

# 配置端口转发
configure_relay() {
    log "INFO" "配置端口转发..."
    
    # 检查证书
    local domain=$(get_status DOMAIN_NAME)
    if [ ! -f "/etc/haproxy/certs/${domain}.pem.combined" ]; then
        log "ERROR" "未找到SSL证书，请先配置证书"
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

    # 询问上游服务器数量
    read -p "请输入上游服务器数量: " server_count
    
    # 准备配置文件
    cp /etc/haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg.bak
    
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

    if [ -z "$stats_user" ] || [ -z "$stats_pass" ]; then
        log "ERROR" "状态页面认证信息配置失败"
        return 1
    fi

    # 保存配置信息
    set_status STATS_USER "${stats_user}"
    set_status STATS_PASS "${stats_pass}"
    set_status UPSTREAM_SERVERS "${upstream_servers%,}"
    set_status LISTEN_PORTS "${listen_ports%,}"

    # 验证配置是否成功保存
    if [ "$(get_status STATS_USER)" != "$stats_user" ] || \
       [ "$(get_status STATS_PASS)" != "$stats_pass" ] || \
       [ "$(get_status UPSTREAM_SERVERS)" != "${upstream_servers%,}" ] || \
       [ "$(get_status LISTEN_PORTS)" != "${listen_ports%,}" ]; then
        log "ERROR" "配置信息保存失败"
        return 1
    fi
    
    # 检查配置语法
    if ! haproxy -c -f /etc/haproxy/haproxy.cfg; then
        log "ERROR" "配置文件有误，正在回滚..."
        mv /etc/haproxy/haproxy.cfg.bak /etc/haproxy/haproxy.cfg
        return 1
    fi
    
    # 重启服务
    systemctl restart haproxy

    sleep 2  # 等待服务启动
    
    # 检查服务状态和端口
    if ! systemctl is-active --quiet haproxy; then
        log "ERROR" "HAProxy 重启失败"
        return 1
    fi

    # 检查端口是否正在监听
    local listen_status=0
    IFS=',' read -ra PORTS <<< "${listen_ports%,}"
    for port in "${PORTS[@]}"; do
        if ! ss -tuln | grep -q ":${port} "; then
            log "ERROR" "端口 ${port} 未正常监听"
            listen_status=1
            break
        fi
    done

    # 检查状态页面端口
    if ! ss -tuln | grep -q ":10086 "; then
        log "ERROR" "状态页面端口 10086 未正常监听"
        listen_status=1
    fi

    if [ $listen_status -eq 0 ]; then
        set_status MULTI_PORT_CONFIGURED 1
        log "SUCCESS" "端口转发配置完成"
        return 0
    else
        log "ERROR" "端口配置失败"
        return 1
    fi
}

# 配置 UFW 防火墙
configure_ufw() {
    log "INFO" "配置 UFW 防火墙..."

    # 检查SSH端口
    local ssh_port=$(ss -tuln | grep -i ssh | awk '{print $5}' | awk -F: '{print $2}')
    ssh_port=${ssh_port:-22}
    
    # 重置UFW
    ufw --force reset
    
    # 设置默认策略
    ufw default deny incoming
    ufw default allow outgoing
    
    # 允许SSH
    ufw allow ${ssh_port}/tcp
    
    # 允许HTTP和HTTPS（用于伪装网站和证书申请）
    ufw allow 80/tcp
    ufw allow 443/tcp
    
    # 允许HAProxy端口
    local listen_ports=$(get_status LISTEN_PORTS)
    IFS=',' read -ra PORTS <<< "$listen_ports"
    for port in "${PORTS[@]}"; do
        if [ -n "$port" ]; then
            ufw allow ${port}/tcp
        fi
    done
    
    # 允许状态监控端口
    ufw allow 10086/tcp
    
    # 启用UFW
    echo "y" | ufw enable
    
    # 验证UFW状态和端口配置 【新增的验证部分】
    if ! ufw status | grep -q "Status: active"; then
        log "ERROR" "UFW 未成功启用"
        return 1
    fi

    # 验证SSH端口
    if ! ufw status | grep -q "${ssh_port}/tcp"; then
        log "ERROR" "SSH端口 ${ssh_port} 配置失败"
        return 1
    fi

    # 验证HTTP和HTTPS端口
    if ! ufw status | grep -q "80/tcp" || ! ufw status | grep -q "443/tcp"; then
        log "ERROR" "Web端口配置失败"
        return 1
    fi

    # 验证HAProxy端口
    local port_status=0
    local listen_ports=$(get_status LISTEN_PORTS)
    IFS=',' read -ra PORTS <<< "$listen_ports"
    for port in "${PORTS[@]}"; do
        if [ -n "$port" ]; then
            if ! ufw status | grep -q "$port/tcp"; then
                log "ERROR" "端口 $port 配置失败"
                port_status=1
                break
            fi
        fi
    done

    # 验证状态页面端口
    if ! ufw status | grep -q "10086/tcp"; then
        log "ERROR" "状态页面端口配置失败"
        port_status=1
    fi

    if [ $port_status -eq 0 ]; then
        set_status UFW_CONFIGURED 1
        log "SUCCESS" "UFW 防火墙配置完成"
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
    
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    sysctl -p

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
    echo "====================== 转发配置信息 ======================"
    
    # 显示域名信息
    local domain=$(get_status DOMAIN_NAME)
    if [ -n "$domain" ]; then
        echo -e "域名: ${GREEN}${domain}${PLAIN}"
    fi
    
    # 显示转发规则
    local upstream_servers=$(get_status UPSTREAM_SERVERS)
    local listen_ports=$(get_status LISTEN_PORTS)
    local stats_user=$(get_status STATS_USER)
    local stats_pass=$(get_status STATS_PASS)
    
    if [ -n "$upstream_servers" ] && [ -n "$listen_ports" ]; then
        IFS=',' read -ra SERVERS <<< "$upstream_servers"
        IFS=',' read -ra PORTS <<< "$listen_ports"
        
        echo -e "\n转发规则："
        for i in "${!SERVERS[@]}"; do
            echo -e "规则 $((i+1)):"
            echo -e "  本地端口: ${GREEN}${PORTS[i]}${PLAIN}"
            echo -e "  上游服务器: ${GREEN}${SERVERS[i]}${PLAIN}"
        done
    fi
    
    echo -e "\nHAProxy 状态页面："
    echo -e "  地址: https://${domain}:10086"
    echo -e "  用户名: ${GREEN}${stats_user}${PLAIN}"
    echo -e "  密码: ${GREEN}${stats_pass}${PLAIN}"
    
    # 显示证书信息
    if [ -f "/etc/haproxy/certs/${domain}.pem.combined" ]; then
        echo -e "\nSSL证书信息："
        echo -e "  证书路径: /etc/haproxy/certs/${domain}.pem.combined"
        echo -e "  自动续期: 已配置"
    fi
    
    echo "======================================================="
}

# 查看服务状态
show_status() {
    echo "====================== 服务运行状态 ======================"
    
    echo -e "\n[ Nginx状态 ]"
    systemctl status nginx --no-pager | grep -E "Active:|running"
    
    echo -e "\n[ HAProxy状态 ]"
    systemctl status haproxy --no-pager | grep -E "Active:|running"
    
    echo -e "\n[ UFW状态 ]"
    ufw status verbose
    
    echo -e "\n[ BBR状态 ]"
    if lsmod | grep -q bbr; then
        echo -e "${GREEN}BBR: 已启用${PLAIN}"
    else
        echo -e "${RED}BBR: 未启用${PLAIN}"
    fi
    
    echo -e "\n[ SSL证书状态 ]"
    local domain=$(get_status DOMAIN_NAME)
    if [ -f "/etc/haproxy/certs/${domain}.pem.combined" ]; then
        echo -e "${GREEN}证书: 已安装${PLAIN}"
        openssl x509 -in /etc/haproxy/certs/${domain}.pem -noout -dates
    else
        echo -e "${RED}证书: 未安装${PLAIN}"
    fi
    
    echo -e "\n[ 端口监听状态 ]"
    ss -tuln | grep -E ':(80|443|10086|'$(get_status LISTEN_PORTS | tr ',' '|')')'
    echo "======================================================="
}

# 重启服务
restart_services() {
    log "INFO" "重启所有服务..."
    
    systemctl restart nginx
    systemctl restart haproxy
    
    local has_error=0
    if ! systemctl is-active --quiet nginx; then
        log "ERROR" "Nginx重启失败"
        has_error=1
    fi
    
    if ! systemctl is-active --quiet haproxy; then
        log "ERROR" "HAProxy重启失败"
        has_error=1
    fi
    
    if [ $has_error -eq 0 ]; then
        log "SUCCESS" "所有服务重启成功"
        show_status
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
    systemctl stop nginx haproxy
    systemctl disable nginx haproxy
    
    # 卸载软件包
    apt remove --purge -y nginx haproxy
    
    # 清理证书
    if [ -d ~/.acme.sh ]; then
        ~/.acme.sh/acme.sh --uninstall
        rm -rf ~/.acme.sh
    fi
    
    # 清理配置文件
    rm -rf /etc/nginx
    rm -rf /etc/haproxy
    rm -rf $INSTALL_STATUS_DIR
    rm -rf /var/www/html/*
    
    # 重置防火墙
    ufw --force reset
    ufw disable
    
    log "SUCCESS" "卸载完成"
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

# 显示菜单
show_menu() {
    clear
    echo "=========== HAProxy 中转管理系统 ==========="
    echo -e " 1. 系统环境准备 $(if [ "$(get_status SYSTEM_PREPARED)" = "1" ]; then echo "${GREEN}[OK]${PLAIN}"; fi)"
    echo -e " 2. 配置伪装站点 $(if [ "$(get_status NGINX_INSTALLED)" = "1" ]; then echo "${GREEN}[OK]${PLAIN}"; fi)"
    echo -e " 3. 申请SSL证书 $(if [ "$(get_status CERT_INSTALLED)" = "1" ]; then echo "${GREEN}[OK]${PLAIN}"; fi)"
    echo -e " 4. 安装 HAProxy $(if [ "$(get_status HAPROXY_INSTALLED)" = "1" ]; then echo "${GREEN}[OK]${PLAIN}"; fi)"
    echo -e " 5. 配置端口转发 $(if [ "$(get_status MULTI_PORT_CONFIGURED)" = "1" ]; then echo "${GREEN}[OK]${PLAIN}"; fi)"
    echo -e " 6. 配置 UFW 防火墙 $(if [ "$(get_status UFW_CONFIGURED)" = "1" ]; then echo "${GREEN}[OK]${PLAIN}"; fi)"
    echo -e " 7. 安装 BBR 加速 $(if [ "$(get_status BBR_INSTALLED)" = "1" ]; then echo "${GREEN}[OK]${PLAIN}"; fi)"
    echo " 8. 查看配置信息"
    echo " 9. 查看运行状态"
    echo " 10. 重启所有服务"
    echo " 11. 卸载所有组件"
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
        read -p "请选择操作[0-11]: " choice
        case "${choice}" in
            0) exit 0 ;;
            1) check_reinstall "系统环境" "SYSTEM_PREPARED" && prepare_system ;;
            2) check_reinstall "伪装站点" "NGINX_INSTALLED" && configure_nginx ;;
            3) check_reinstall "SSL证书" "CERT_INSTALLED" && install_cert ;;
            4) check_reinstall "HAProxy" "HAPROXY_INSTALLED" && install_haproxy ;;
            5) check_reinstall "端口转发" "MULTI_PORT_CONFIGURED" && configure_relay ;;
            6) check_reinstall "UFW防火墙" "UFW_CONFIGURED" && configure_ufw ;;
            7) check_reinstall "BBR加速" "BBR_INSTALLED" && install_bbr ;;
            8) show_config ;;
            9) show_status ;;
            10) restart_services ;;
            11) uninstall_all ;;
            *) log "ERROR" "无效的选择" ;;
        esac
        echo
        read -p "按回车键继续..." </dev/tty
    done
}

# 启动脚本
main "$@"
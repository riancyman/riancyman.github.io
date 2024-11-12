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
    
    # 更新系统和安装基础包
    apt-get update
    apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" upgrade
    apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" \
        curl wget unzip ufw socat nginx python3

    local status=$?
    if [ $status -eq 0 ]; then
        set_status SYSTEM_PREPARED 1
        log "SUCCESS" "系统环境准备完成"
        return 0
    else
        log "ERROR" "系统环境准备失败"
        return 1
    fi
}

# 安装配置Nginx伪装站点
configure_nginx() {
    log "INFO" "配置Nginx伪装站点..."
    
    # 安装Nginx
    if ! command -v nginx >/dev/null; then
        apt-get update
        apt-get install -y nginx
    fi
    
    # 询问是否配置域名
    read -p "是否要配置域名？[y/N] " use_domain
    if [[ "${use_domain,,}" == "y" ]]; then
        read -p "请输入域名: " domain_name
        set_status DOMAIN_NAME "${domain_name}"
        log "INFO" "请将域名 ${domain_name} 解析到当前服务器IP"
        read -p "解析完成后按回车继续..."
    fi

    # 配置伪装站点
    echo "请选择伪装站点类型："
    echo "1. 个人博客"
    echo "2. 企业官网"
    echo "3. 图片站"
    echo "4. 下载站"
    echo "5. 自定义网站"
    read -p "请选择 [1-5]: " site_type
    
    # 创建伪装站点配置
    cat > /etc/nginx/conf.d/default.conf << EOF
server {
    listen 80;
    server_name ${domain_name:-_};
    root /var/www/html;
    index index.html;
    
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

    # 设置目录权限
    chown -R www-data:www-data /var/www/html
    chmod -R 755 /var/www/html
    
    # 重启Nginx
    systemctl restart nginx
    
    if systemctl is-active --quiet nginx; then
        set_status NGINX_INSTALLED 1
        log "SUCCESS" "Nginx伪装站点配置完成"
        return 0
    else
        log "ERROR" "Nginx启动失败"
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

    set_status HAPROXY_INSTALLED 1
    log "SUCCESS" "HAProxy 安装完成"
    return 0
}

# 配置端口转发
configure_relay() {
    log "INFO" "配置端口转发..."
    
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

defaults
    log     global
    mode    tcp
    option  dontlognull
    option  tcplog
    timeout connect 5000
    timeout client  50000
    timeout server  50000

# 状态页面
listen stats
    bind *:10086
    mode http
    stats enable
    stats hide-version
    stats uri /
    stats realm Haproxy\ Statistics
    stats auth ${stats_user}:${stats_pass}
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
    bind *:${listen_port}
    mode tcp
    default_backend bk_${server_addr}_${server_port}

backend bk_${server_addr}_${server_port}
    mode tcp
    option tcp-check
    server server1 ${server_addr}:${server_port} check inter 2000 rise 2 fall 3
EOF
        
        upstream_servers="${upstream_servers}${server_addr}:${server_port},"
        listen_ports="${listen_ports}${listen_port},"
    done

    # 保存配置信息
    set_status STATS_USER "${stats_user}"
    set_status STATS_PASS "${stats_pass}"
    set_status UPSTREAM_SERVERS "${upstream_servers%,}"
    set_status LISTEN_PORTS "${listen_ports%,}"
    
    # 检查配置语法
    if ! haproxy -c -f /etc/haproxy/haproxy.cfg; then
        log "ERROR" "配置文件有误，正在回滚..."
        mv /etc/haproxy/haproxy.cfg.bak /etc/haproxy/haproxy.cfg
        return 1
    fi
    
    # 重启服务
    systemctl restart haproxy
    
    if systemctl is-active --quiet haproxy; then
        set_status MULTI_PORT_CONFIGURED 1
        log "SUCCESS" "端口转发配置完成"
        return 0
    else
        log "ERROR" "HAProxy 重启失败"
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
    
    # 允许HTTP(用于伪装网站)
    ufw allow 80/tcp
    
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
    
    if ufw status | grep -q "Status: active"; then
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
        echo -e "已配置域名: ${GREEN}${domain}${PLAIN}"
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
    echo -e "  地址: http://服务器IP:10086"
    if [ -n "$domain" ]; then
        echo -e "  或者: http://${domain}:10086"
    fi
    echo -e "  用户名: ${GREEN}${stats_user}${PLAIN}"
    echo -e "  密码: ${GREEN}${stats_pass}${PLAIN}"
    
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
    
    echo -e "\n[ 端口监听状态 ]"
    ss -tuln | grep -E ':(80|10086|'$(get_status LISTEN_PORTS | tr ',' '|')')'
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
    
    systemctl stop nginx haproxy
    systemctl disable nginx haproxy
    apt remove --purge -y nginx haproxy
    rm -rf /etc/nginx
    rm -rf /etc/haproxy
    rm -rf $INSTALL_STATUS_DIR
    rm -rf /var/www/html/*
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
    echo -e " 3. 安装 HAProxy $(if [ "$(get_status HAPROXY_INSTALLED)" = "1" ]; then echo "${GREEN}[OK]${PLAIN}"; fi)"
    echo -e " 4. 配置端口转发 $(if [ "$(get_status MULTI_PORT_CONFIGURED)" = "1" ]; then echo "${GREEN}[OK]${PLAIN}"; fi)"
    echo -e " 5. 配置 UFW 防火墙 $(if [ "$(get_status UFW_CONFIGURED)" = "1" ]; then echo "${GREEN}[OK]${PLAIN}"; fi)"
    echo -e " 6. 安装 BBR 加速 $(if [ "$(get_status BBR_INSTALLED)" = "1" ]; then echo "${GREEN}[OK]${PLAIN}"; fi)"
    echo " 7. 查看配置信息"
    echo " 8. 查看运行状态"
    echo " 9. 重启所有服务"
    echo " 10. 卸载所有组件"
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
            2) check_reinstall "伪装站点" "NGINX_INSTALLED" && configure_nginx ;;
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
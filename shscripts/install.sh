#!/bin/bash
# install.sh - Debian 12 一键安装 Trojan-Go 管理脚本

# 状态文件路径
INSTALL_STATUS_DIR="/etc/trojan-go"
STATUS_FILE="${INSTALL_STATUS_DIR}/install_status.conf"

# 颜色定义
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
PLAIN="\033[0m"

# 外部资源URL
GITHUB_API_URL="https://api.github.com/repos/p4gefau1t/trojan-go/releases/latest"
NGINX_KEY_URL="https://nginx.org/keys/nginx_signing.key"
ACME_INSTALL_URL="https://get.acme.sh"

# 初始化状态文件
init_status_file() {
    mkdir -p "$INSTALL_STATUS_DIR"
    if [ ! -f "$STATUS_FILE" ]; then
        cat > "$STATUS_FILE" << EOF
SYSTEM_PREPARED=0
NGINX_INSTALLED=0
CERT_INSTALLED=0
TROJAN_INSTALLED=0
UFW_CONFIGURED=0
BBR_INSTALLED=0
DOMAIN=""
PORT="443"
PASSWORD=""
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

# 检查是否需要确认重新安装
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
    echo "========== Trojan-Go 安装管理系统 =========="
    echo -e " 1. 系统环境准备 $(if [ "$(get_status SYSTEM_PREPARED)" = "1" ]; then echo "${GREEN}[OK]${PLAIN}"; fi)"
    echo -e " 2. 安装配置 Nginx $(if [ "$(get_status NGINX_INSTALLED)" = "1" ]; then echo "${GREEN}[OK]${PLAIN}"; fi)"
    echo -e " 3. 申请配置 SSL 证书 $(if [ "$(get_status CERT_INSTALLED)" = "1" ]; then echo "${GREEN}[OK]${PLAIN}"; fi)"
    echo -e " 4. 安装配置 Trojan-Go $(if [ "$(get_status TROJAN_INSTALLED)" = "1" ]; then echo "${GREEN}[OK]${PLAIN}"; fi)"
    echo -e " 5. 配置 UFW 防火墙 $(if [ "$(get_status UFW_CONFIGURED)" = "1" ]; then echo "${GREEN}[OK]${PLAIN}"; fi)"
    echo -e " 6. 安装配置 BBR 加速 $(if [ "$(get_status BBR_INSTALLED)" = "1" ]; then echo "${GREEN}[OK]${PLAIN}"; fi)"
    echo " 7. 查看配置信息"
    echo " 8. 查看运行状态"
    echo " 9. 重启所有服务"
    echo " 10. 卸载所有组件"
    echo " 0. 退出"
    echo "==========================================="
}


# 安装 Nginx
install_nginx() {
    if ! check_reinstall "Nginx" "NGINX_INSTALLED"; then
        return 0
    fi

    log "INFO" "开始安装 Nginx..."

    # 安装依赖
    apt install -y gnupg2 ca-certificates lsb-release debian-archive-keyring

    # 添加 Nginx 官方源
    curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --dearmor -o /usr/share/keyrings/nginx-archive-keyring.gpg
    echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/debian $(lsb_release -cs) nginx" > /etc/apt/sources.list.d/nginx.list

    # 更新并安装 Nginx
    apt update
    apt install -y nginx

    if [ $? -ne 0 ]; then
        log "ERROR" "Nginx 安装失败"
        return 1
    fi

    # 伪装站点选择
    echo "请选择伪装站点类型:"
    echo "1. 博客"
    echo "2. 影视站"
    echo "3. 学术网站"
    echo "4. 游戏网站"
    echo "5. 自定义网站"
    
    read -p "请选择 [1-5]: " site_type
    
    case "$site_type" in
        1)
            wget -O web.zip https://github.com/wulabing/3DCEList/archive/master.zip
            theme="3DCEList-master"
            ;;
        2)
            wget -O web.zip https://github.com/wulabing/Meting-Theme/archive/master.zip
            theme="Meting-Theme-master"
            ;;
        3)
            wget -O web.zip https://github.com/wulabing/Academic-Website-Theme/archive/master.zip
            theme="Academic-Website-Theme-master"
            ;;
        4)
            wget -O web.zip https://github.com/wulabing/Gaming-Theme/archive/master.zip
            theme="Gaming-Theme-master"
            ;;
        5)
            read -p "请输入你的自定义网站URL（压缩包格式）: " custom_url
            if [ -n "$custom_url" ]; then
                wget -O web.zip "$custom_url"
                theme="custom"
            else
                log "ERROR" "未提供有效的URL"
                return 1
            fi
            ;;
        *)
            log "ERROR" "无效的选择"
            return 1
            ;;
    esac

    # 解压并部署网站
    if [ -f web.zip ]; then
        unzip -o web.zip -d /tmp/web
        rm -rf /usr/share/nginx/html/*
        mv /tmp/web/$theme/* /usr/share/nginx/html/
        rm -rf /tmp/web web.zip
    fi

    # 配置 Nginx
    cat > /etc/nginx/conf.d/default.conf << 'EOF'
server {
    listen 80;
    listen [::]:80;
    server_name _;
    root /usr/share/nginx/html;
    index index.html index.htm index.php;

    location / {
        try_files $uri $uri/ =404;
    }

    # 禁止访问敏感文件
    location ~ .*\.(git|zip|rar|sql|conf|env)$ {
        deny all;
    }

    # 错误页面
    error_page 404 /404.html;
    error_page 500 502 503 504 /50x.html;
    location = /50x.html {
        root /usr/share/nginx/html;
    }
}
EOF

    # 设置目录权限
    chown -R nginx:nginx /usr/share/nginx/html
    chmod -R 755 /usr/share/nginx/html

    # 启动 Nginx
    systemctl daemon-reload
    systemctl enable nginx
    systemctl start nginx

    # 验证 Nginx 是否成功启动
    if ! systemctl is-active --quiet nginx; then
        log "ERROR" "Nginx 启动失败"
        return 1
    fi

    set_status NGINX_INSTALLED 1
    log "SUCCESS" "Nginx 安装配置完成"
    return 0
}

# 申请 SSL 证书
install_cert() {
    if ! check_reinstall "SSL证书" "CERT_INSTALLED"; then
        return 0
    fi

    local domain
    read -p "请输入你的域名：" domain
    if [ -z "$domain" ]; then
        log "ERROR" "域名不能为空"
        return 1
    fi

    log "INFO" "开始申请 SSL 证书..."

    # 先停止 Nginx
    systemctl stop nginx

    # 安装 socat
    apt install -y socat

    # 安装 acme.sh
    if [ -f ~/.acme.sh/acme.sh ]; then
        log "INFO" "acme.sh 已安装，尝试更新..."
        ~/.acme.sh/acme.sh --upgrade
    else
        curl -fsSL https://get.acme.sh | sh -s email=admin@example.com
        if [ $? -ne 0 ]; then
            log "ERROR" "acme.sh 安装失败"
            return 1
        fi
        source ~/.bashrc
    fi

    # 创建证书目录
    mkdir -p /etc/trojan-go/cert
    
    # 申请证书
    ~/.acme.sh/acme.sh --issue -d ${domain} --standalone \
        --key-file /etc/trojan-go/cert/${domain}.key \
        --fullchain-file /etc/trojan-go/cert/${domain}.pem

    if [ $? -ne 0 ]; then
        log "ERROR" "证书申请失败"
        systemctl start nginx
        return 1
    fi

    # 设置证书权限
    chmod 644 /etc/trojan-go/cert/${domain}.pem
    chmod 600 /etc/trojan-go/cert/${domain}.key

    # 重启 Nginx
    systemctl start nginx

    set_status CERT_INSTALLED 1
    set_status DOMAIN ${domain}
    log "SUCCESS" "SSL 证书申请完成"
    return 0
}

# 安装 Trojan-Go
install_trojan() {
    if ! check_reinstall "Trojan-Go" "TROJAN_INSTALLED"; then
        return 0
    fi

    local domain=$(get_status DOMAIN)
    if [ -z "$domain" ]; then
        log "ERROR" "请先完成证书配置"
        return 1
    }

    log "INFO" "开始安装 Trojan-Go..."

    # 下载最新版本
    local version=$(curl -fsSL ${GITHUB_API_URL} | grep tag_name | cut -d'"' -f4)
    local arch="amd64"
    local download_url="https://github.com/p4gefau1t/trojan-go/releases/download/${version}/trojan-go-linux-${arch}.zip"
    
    wget -O /tmp/trojan-go.zip ${download_url}
    if [ $? -ne 0 ]; then
        log "ERROR" "Trojan-Go 下载失败"
        return 1
    fi

    # 解压安装
    unzip -o /tmp/trojan-go.zip -d /tmp/trojan-go
    mkdir -p /usr/local/bin/
    cp /tmp/trojan-go/trojan-go /usr/local/bin/
    chmod +x /usr/local/bin/trojan-go

    # 生成随机密码
    local password=$(openssl rand -base64 16)
    set_status PASSWORD ${password}

    # 配置 Trojan-Go
    cat > /etc/trojan-go/config.json << EOF
{
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": 443,
    "remote_addr": "127.0.0.1",
    "remote_port": 80,
    "password": [
        "${password}"
    ],
    "ssl": {
        "cert": "/etc/trojan-go/cert/${domain}.pem",
        "key": "/etc/trojan-go/cert/${domain}.key",
        "sni": "${domain}",
        "alpn": [
            "http/1.1"
        ],
        "session_ticket": true,
        "reuse_session": true,
        "fallback_addr": "127.0.0.1",
        "fallback_port": 80
    }
}
EOF

    # 配置系统服务
    cat > /etc/systemd/system/trojan-go.service << EOF
[Unit]
Description=Trojan-Go - An unidentifiable mechanism that helps you bypass GFW
Documentation=https://p4gefau1t.github.io/trojan-go/
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/trojan-go -config /etc/trojan-go/config.json
Restart=always
RestartSec=10
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    # 重新加载系统服务并启动
    systemctl daemon-reload
    systemctl enable trojan-go
    systemctl start trojan-go

    # 检查服务状态
    if ! systemctl is-active --quiet trojan-go; then
        log "ERROR" "Trojan-Go 启动失败"
        return 1
    fi

    # 清理临时文件
    rm -rf /tmp/trojan-go /tmp/trojan-go.zip

    set_status TROJAN_INSTALLED 1
    log "SUCCESS" "Trojan-Go 安装配置完成"
    return 0
}

# 配置 UFW 防火墙
configure_ufw() {
    if ! check_reinstall "UFW防火墙" "UFW_CONFIGURED"; then
        return 0
    }

    log "INFO" "配置 UFW 防火墙..."

    # 检查 UFW 是否安装
    if ! command -v ufw >/dev/null; then
        apt install -y ufw
    fi

    # 重置 UFW
    ufw --force reset

    # 设置默认策略
    ufw default deny incoming
    ufw default allow outgoing

    # 允许SSH（默认22端口）
    ufw allow ssh

    # 允许 HTTP 和 HTTPS
    ufw allow http
    ufw allow https

    # 启用UFW并确保它开机自启
    echo "y" | ufw enable
    systemctl enable ufw

    if [ $? -ne 0 ]; then
        log "ERROR" "UFW 配置失败"
        return 1
    fi

    set_status UFW_CONFIGURED 1
    log "SUCCESS" "UFW 防火墙配置完成"
    return 0
}

# 安装 BBR 加速
install_bbr() {
    if ! check_reinstall "BBR加速" "BBR_INSTALLED"; then
        return 0
    }

    log "INFO" "开始安装 BBR 加速..."

    # 检查是否已经启用
    if lsmod | grep -q bbr; then
        log "INFO" "BBR 已经启用"
        set_status BBR_INSTALLED 1
        return 0
    fi

    # 检查系统版本
    if [[ "$(uname -r)" < "4.9" ]]; then
        log "INFO" "正在安装新内核..."
        apt update
        apt install -y linux-image-generic
        if [ $? -ne 0 ]; then
            log "ERROR" "内核安装失败"
            return 1
        fi
    fi

    # 启用 BBR
    if ! grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf; then
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    fi
    
    if ! grep -q "net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf; then
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    fi

    sysctl -p

    # 加载 BBR 模块
    modprobe tcp_bbr

    # 验证 BBR 是否启用
    if lsmod | grep -q bbr; then
        set_status BBR_INSTALLED 1
        log "SUCCESS" "BBR 加速安装完成"
        log "INFO" "建议重启服务器使配置生效"
        read -p "是否现在重启服务器？[y/N] " answer
        if [[ "${answer,,}" == "y" ]]; then
            reboot
        fi
        return 0
    else
        log "ERROR" "BBR 加速安装失败"
        return 1
    fi
}

# 显示配置信息
show_config() {
    local domain=$(get_status DOMAIN)
    local password=$(get_status PASSWORD)
    local port=443

    echo "===================== Trojan-Go 配置信息 ====================="
    echo -e "域名: ${GREEN}${domain}${PLAIN}"
    echo -e "端口: ${GREEN}${port}${PLAIN}"
    echo -e "密码: ${GREEN}${password}${PLAIN}"
    echo ""
    echo "客户端配置信息："
    echo "  地址(address): ${domain}"
    echo "  端口(port): ${port}"
    echo "  密码(password): ${password}"
    echo "  加密方式(security): tls"
    echo "=========================================================="
}

# 查看服务状态
show_status() {
    echo "===================== 服务运行状态 ====================="
    echo -e "\n[ Nginx 状态 ]"
    systemctl status nginx --no-pager | grep -E "Active:|running"
    
    echo -e "\n[ Trojan-Go 状态 ]"
    systemctl status trojan-go --no-pager | grep -E "Active:|running"
    
    echo -e "\n[ UFW 状态 ]"
    ufw status verbose
    
    echo -e "\n[ BBR 状态 ]"
    if lsmod | grep -q bbr; then
        echo -e "${GREEN}BBR: 已启用${PLAIN}"
        sysctl net.ipv4.tcp_congestion_control
    else
        echo -e "${RED}BBR: 未启用${PLAIN}"
    fi
    
    echo -e "\n[ 端口监听状态 ]"
    ss -tulpn | grep -E ':80|:443'
    echo "======================================================"
}

# 重启所有服务
restart_services() {
    log "INFO" "重启所有服务..."
    
    systemctl restart nginx
    systemctl restart trojan-go
    
    # 验证服务状态
    local has_error=0
    
    if ! systemctl is-active --quiet nginx; then
        log "ERROR" "Nginx 重启失败"
        has_error=1
    fi
    
    if ! systemctl is-active --quiet trojan-go; then
        log "ERROR" "Trojan-Go 重启失败"
        has_error=1
    fi
    
    if [ $has_error -eq 0 ]; then
        log "SUCCESS" "所有服务重启成功"
        show_status
    fi
}

# 卸载所有组件
uninstall_all() {
    log "WARNING" "即将卸载所有组件..."
    echo -e "${RED}该操作将会：${PLAIN}"
    echo "1. 停止并删除 Trojan-Go 服务"
    echo "2. 停止并删除 Nginx 服务"
    echo "3. 删除所有证书和配置文件"
    echo "4. 重置防火墙配置"
    echo "5. 删除 BBR 配置"
    
    read -p "确定要卸载所有组件吗？[y/N] " answer
    if [[ "${answer,,}" != "y" ]]; then
        return 0
    fi

    log "INFO" "开始卸载组件..."

    # 1. 停止和禁用服务
    log "INFO" "停止服务..."
    systemctl stop trojan-go
    systemctl disable trojan-go
    systemctl stop nginx
    systemctl disable nginx

    # 2. 卸载 Trojan-Go
    log "INFO" "删除 Trojan-Go..."
    rm -rf /etc/trojan-go
    rm -f /usr/local/bin/trojan-go
    rm -f /etc/systemd/system/trojan-go.service

    # 3. 卸载 Nginx
    log "INFO" "删除 Nginx..."
    apt remove --purge -y nginx nginx-common
    rm -rf /etc/nginx
    rm -rf /var/log/nginx

    # 4. 清理证书
    log "INFO" "清理证书..."
    if [ -d ~/.acme.sh ]; then
        ~/.acme.sh/acme.sh --uninstall
        rm -rf ~/.acme.sh
    fi

    # 5. 重置防火墙
    log "INFO" "重置防火墙..."
    ufw --force reset
    ufw disable

    # 6. 重置 BBR
    log "INFO" "重置 BBR 配置..."
    sed -i '/net.core.default_qdisc=fq/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_congestion_control=bbr/d' /etc/sysctl.conf
    sysctl -p >/dev/null 2>&1

    # 7. 删除状态文件
    rm -f "$STATUS_FILE"

    log "SUCCESS" "所有组件已卸载完成"
    
    read -p "是否需要重启服务器？[y/N] " reboot_answer
    if [[ "${reboot_answer,,}" == "y" ]]; then
        reboot
    fi
}

# 主函数
main() {
    # 检查是否为root用户
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}错误：请使用 root 用户运行此脚本${PLAIN}"
        exit 1
    fi

    # 检查是否为 Debian 系统
    if ! grep -qi "debian" /etc/os-release; then
        echo -e "${RED}错误：此脚本仅支持 Debian 系统${PLAIN}"
        exit 1
    }

    # 初始化
    init_status_file
    
    # 主循环
    while true; do
        show_menu
        read -p "请选择操作[0-10]: " choice
        case "${choice}" in
            0)
                log "INFO" "退出脚本"
                exit 0
                ;;
            1)
                prepare_system
                ;;
            2)
                install_nginx
                ;;
            3)
                install_cert
                ;;
            4)
                install_trojan
                ;;
            5)
                configure_ufw
                ;;
            6)
                install_bbr
                ;;
            7)
                show_config
                ;;
            8)
                show_status
                ;;
            9)
                restart_services
                ;;
            10)
                uninstall_all
                ;;
            *)
                log "ERROR" "无效的选择"
                ;;
        esac
        echo
        read -p "按回车键继续..." </dev/tty
    done
}

# 启动脚本
main "$@"
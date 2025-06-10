#!/bin/bash

# 颜色定义
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[36m"
PLAIN="\033[0m"

# 配置文件路径
CONFIG_FILE="/etc/trojan-go/config.json"
STATUS_FILE="/etc/trojan-go/status.txt"
LOG_FILE="/var/log/trojan-go-install.log"
SERVICE_FILE="/etc/systemd/system/trojan-go.service"

# ASCII 艺术标题
echo -e "${BLUE}"
cat << "EOF"
████████╗██████╗  ██████╗      ██╗ █████╗ ███╗   ██╗
╚══██╔══╝██╔══██╗██╔═══██╗     ██║██╔══██╗████╗  ██║
   ██║   ██████╔╝██║   ██║     ██║███████║██╔██╗ ██║
   ██║   ██╔══██╗██║   ██║██   ██║██╔══██║██║╚██╗██║
   ██║   ██║  ██║╚██████╔╝╚█████╔╝██║  ██║██║ ╚████║
   ╚═╝   ╚═╝  ╚═╝ ╚═════╝  ╚════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝
EOF
echo -e "${PLAIN}"

# 版本信息和说明
echo -e "${GREEN}=====================================================${PLAIN}"
echo -e "${GREEN}              Trojan-Go 管理脚本 v2.0                ${PLAIN}"
echo -e "${GREEN}         系统支持: Ubuntu, Debian, CentOS            ${PLAIN}"
echo -e "${GREEN}=====================================================${PLAIN}"
echo -e "

注意事项:
1. 安装前请确保已解析域名到本机
2. 支持 DuckDNS 域名自动申请证书
3. 配置采用 WebSocket + TLS
4. 密码将自动随机生成
5. 支持证书自动更新和手动更新
"

# 日志函数
log() {
    local level=$1
    shift
    local message=$@
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    local log_msg="[$timestamp] [${level}] ${message}"
    
    # 输出到终端
    case $level in
        "ERROR") echo -e "${RED}${log_msg}${PLAIN}" ;;
        "WARNING") echo -e "${YELLOW}${log_msg}${PLAIN}" ;;
        "INFO") echo -e "${GREEN}${log_msg}${PLAIN}" ;;
        *) echo -e "${log_msg}" ;;
    esac
    
    # 输出到日志文件
    mkdir -p $(dirname "$LOG_FILE")
    echo "${log_msg}" >> "$LOG_FILE"
}

# 获取状态
get_status() {
    local key=$1
    if [ -f "$STATUS_FILE" ]; then
        grep "^${key}=" "$STATUS_FILE" 2>/dev/null | cut -d'=' -f2
    fi
}

# 设置状态
set_status() {
    local key=$1
    local value=$2
    mkdir -p $(dirname "$STATUS_FILE")
    touch "$STATUS_FILE"
    if grep -q "^${key}=" "$STATUS_FILE" 2>/dev/null; then
        sed -i "s/^${key}=.*/${key}=${value}/" "$STATUS_FILE"
    else
        echo "${key}=${value}" >> "$STATUS_FILE"
    fi
}

# 检查系统
check_sys() {
    if [[ -f /etc/debian_version ]]; then
        log "INFO" "检测到 Debian/Ubuntu 系统"
        return 0
    elif [[ -f /etc/redhat-release ]]; then
        log "INFO" "检测到 CentOS/RHEL 系统"
        return 0
    else
        log "ERROR" "系统不支持，请使用 Debian/Ubuntu/CentOS"
        exit 1
    fi
}

# 检查是否为root用户
check_root() {
    if [ $(id -u) != 0 ]; then
        log "ERROR" "请使用 root 用户运行脚本"
        exit 1
    fi
}

# 检查网络连接
check_network() {
    log "INFO" "检查网络连接..."
    if ! curl -s --connect-timeout 10 https://www.google.com > /dev/null; then
        if ! curl -s --connect-timeout 10 https://www.baidu.com > /dev/null; then
            log "ERROR" "网络连接失败，请检查网络设置"
            return 1
        fi
    fi
    log "INFO" "网络连接正常"
    return 0
}

# 安装必要的工具
install_requirements() {
    log "INFO" "安装必要的工具..."
    
    if [[ -f /etc/debian_version ]]; then
        apt update -qq
        apt install -y socat curl wget unzip openssl cron || {
            log "ERROR" "工具安装失败"
            return 1
        }
    elif [[ -f /etc/redhat-release ]]; then
        yum update -y -q
        yum install -y socat curl wget unzip openssl crontabs || {
            log "ERROR" "工具安装失败"
            return 1
        }
    fi
    
    log "INFO" "必要工具安装完成"
    return 0
}

# 验证配置文件
validate_config() {
    if [ ! -f "$CONFIG_FILE" ]; then
        log "ERROR" "配置文件不存在: $CONFIG_FILE"
        return 1
    fi
    
    if ! python3 -m json.tool "$CONFIG_FILE" > /dev/null 2>&1; then
        if ! python -m json.tool "$CONFIG_FILE" > /dev/null 2>&1; then
            log "ERROR" "配置文件 JSON 格式错误"
            return 1
        fi
    fi
    
    log "INFO" "配置文件验证通过"
    return 0
}

# 下载 Trojan-Go
download_trojan() {
    log "INFO" "获取 Trojan-Go 最新版本..."
    
    local latest_version
    latest_version=$(curl -s --connect-timeout 10 https://api.github.com/repos/p4gefau1t/trojan-go/releases/latest | grep -oP '"tag_name": "\K[^"]+' 2>/dev/null)
    
    if [ -z "$latest_version" ]; then
        log "ERROR" "无法获取 Trojan-Go 最新版本，请检查网络连接"
        return 1
    fi
    
    log "INFO" "最新版本: $latest_version"
    set_status "version" "$latest_version"

    # 下载文件
    local download_url="https://github.com/p4gefau1t/trojan-go/releases/download/${latest_version}/trojan-go-linux-amd64.zip"
    log "INFO" "下载 Trojan-Go..."
    
    if ! wget -q --show-progress -O /tmp/trojan-go.zip "$download_url"; then
        log "ERROR" "Trojan-Go 下载失败"
        return 1
    fi

    if [ ! -f "/tmp/trojan-go.zip" ] || [ ! -s "/tmp/trojan-go.zip" ]; then
        log "ERROR" "下载的文件无效"
        return 1
    fi

    # 解压安装
    log "INFO" "安装 Trojan-Go..."
    mkdir -p /usr/local/bin /usr/local/share/trojan-go
    
    if ! unzip -o /tmp/trojan-go.zip -d /tmp/trojan-go/ > /dev/null 2>&1; then
        log "ERROR" "解压失败"
        return 1
    fi
    
    # 安装文件
    if [ -f "/tmp/trojan-go/trojan-go" ]; then
        mv /tmp/trojan-go/trojan-go /usr/local/bin/
        chmod +x /usr/local/bin/trojan-go
    else
        log "ERROR" "trojan-go 可执行文件不存在"
        return 1
    fi
    
    # 安装数据文件
    [ -f "/tmp/trojan-go/geoip.dat" ] && mv /tmp/trojan-go/geoip.dat /usr/local/share/trojan-go/
    [ -f "/tmp/trojan-go/geosite.dat" ] && mv /tmp/trojan-go/geosite.dat /usr/local/share/trojan-go/
    
    # 清理临时文件
    rm -rf /tmp/trojan-go*
    
    log "INFO" "Trojan-Go 安装完成"
    return 0
}

# 检查 Trojan-Go 是否已安装
check_trojan_installed() {
    if [ -f "/usr/local/bin/trojan-go" ] && [ -f "$CONFIG_FILE" ]; then
        return 0
    else
        return 1
    fi
}

# 获取当前版本
get_current_version() {
    get_status "version"
}

# 安装 Trojan-Go
install_trojan() {
    log "INFO" "开始安装 Trojan-Go..."

    # 检查是否已安装
    if check_trojan_installed; then
        log "WARNING" "Trojan-Go 已安装"
        read -p "是否重新安装？[y/N] " answer
        if [[ "${answer,,}" != "y" ]]; then
            return 0
        fi
    fi

    # 检查网络
    check_network || return 1
    
    # 安装依赖
    install_requirements || return 1

    # 获取域名
    read -p "请输入域名 (例如: yourdomain.duckdns.org): " domain
    if [ -z "$domain" ]; then
        log "ERROR" "域名不能为空"
        return 1
    fi
    
    # 验证域名格式
    if ! echo "$domain" | grep -qE '^[a-zA-Z0-9][a-zA-Z0-9\.-]*[a-zA-Z0-9]$'; then
        log "ERROR" "域名格式不正确"
        return 1
    fi
    
    # 获取邮箱
    read -p "请输入邮箱地址 (不能使用 example.com): " email
    if [ -z "$email" ] || [[ "$email" == *"@example.com" ]]; then
        log "ERROR" "请输入有效的邮箱地址"
        return 1
    fi
    
    # 验证邮箱格式
    if ! echo "$email" | grep -qE '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'; then
        log "ERROR" "邮箱格式不正确"
        return 1
    fi
    
    # 获取DuckDNS token
    read -p "请输入 DuckDNS token: " duckdns_token
    if [ -z "$duckdns_token" ]; then
        log "ERROR" "DuckDNS token 不能为空"
        return 1
    fi

    # 验证DuckDNS域名是否可以访问
    log "INFO" "验证DuckDNS域名..."
    local domain_name="${domain%%.*}"
    if ! curl -s "https://www.duckdns.org/update?domains=${domain_name}&token=${duckdns_token}&txt=verify" | grep -q "OK"; then
        log "ERROR" "DuckDNS域名验证失败，请检查token是否正确"
        return 1
    fi

    # 提示用户输入配置信息
    read -p "请输入端口 [默认: 8521]: " port
    port=${port:-8521}
    
    # 验证端口
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        log "ERROR" "端口必须是 1-65535 之间的数字"
        return 1
    fi

    # 生成随机密码
    local password=$(generate_password)
    log "INFO" "已生成随机密码: ${password}"

    # 下载并安装 Trojan-Go
    download_trojan || return 1

    # 创建配置目录
    mkdir -p /etc/trojan-go
    
    # 申请证书
    apply_cert "$domain" "$email" "$duckdns_token"
    if [ $? -ne 0 ]; then
        log "ERROR" "证书申请失败"
        return 1
    fi

    # 生成配置文件
    generate_config "$domain" "$port" "$password"
    
    # 验证配置文件
    validate_config || return 1

    # 创建 systemd 服务
    create_service || return 1

    # 重新加载 systemd 并启用服务
    systemctl daemon-reload
    systemctl enable trojan-go

    # 启动服务
    log "INFO" "启动 Trojan-Go 服务..."
    if systemctl restart trojan-go; then
        log "INFO" "Trojan-Go 启动成功"
    else
        log "ERROR" "Trojan-Go 启动失败"
        systemctl status trojan-go
        return 1
    fi

    # 保存配置信息到状态文件
    set_status "domain" "$domain"
    set_status "port" "$port"
    set_status "password" "$password"
    set_status "email" "$email"
    set_status "duckdns_token" "$duckdns_token"
    set_status "install_time" "$(date '+%Y-%m-%d %H:%M:%S')"

    # 显示配置信息
    show_install_info "$domain" "$port" "$password"

    return 0
}

# 生成配置文件
generate_config() {
    local domain=$1
    local port=$2
    local password=$3
    
    log "INFO" "生成配置文件..."
    
    cat > "$CONFIG_FILE" << EOF
{
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": ${port},
    "remote_addr": "127.0.0.1",
    "remote_port": 443,
    "password": [
        "${password}"
    ],
    "ssl": {
        "cert": "/etc/trojan-go/server.crt",
        "key": "/etc/trojan-go/server.key",
        "sni": "${domain}"
    },
    "websocket": {
        "enabled": true,
        "path": "/trojan",
        "host": "${domain}"
    },
    "log_level": 1,
    "log_file": "/var/log/trojan-go.log"
}
EOF
}

# 创建系统服务
create_service() {
    log "INFO" "创建系统服务..."
    
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Trojan-Go - An unidentifiable mechanism that helps you bypass GFW
Documentation=https://p4gefau1t.github.io/trojan-go/
After=network.target nss-lookup.target

[Service]
Type=simple
StandardError=journal
User=root
AmbientCapabilities=CAP_NET_BIND_SERVICE
ExecStart=/usr/local/bin/trojan-go -config $CONFIG_FILE
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF
}

# 显示安装信息
show_install_info() {
    local domain=$1
    local port=$2
    local password=$3
    
    echo -e "${GREEN}=====================================================${PLAIN}"
    log "INFO" "Trojan-Go 安装完成！"
    echo -e "${GREEN}=====================================================${PLAIN}"
    log "INFO" "配置信息："
    log "INFO" "域名: ${domain}"
    log "INFO" "端口: ${port}"
    log "INFO" "密码: ${password}"
    log "INFO" "WebSocket 路径: /trojan"
    log "INFO" "配置文件: $CONFIG_FILE"
    log "INFO" "日志文件: /var/log/trojan-go.log"
    echo -e "${GREEN}=====================================================${PLAIN}"
}

# 检查并安装 acme.sh
check_acme() {
    if [ ! -f "/root/.acme.sh/acme.sh" ]; then
        log "INFO" "安装 acme.sh..."
        if curl https://get.acme.sh | sh; then
            source ~/.bashrc
            log "INFO" "acme.sh 安装完成"
        else
            log "ERROR" "acme.sh 安装失败"
            return 1
        fi
    else
        log "INFO" "acme.sh 已安装"
    fi
    return 0
}

# 检查证书是否存在且有效
check_cert() {
    local domain=$1
    local cert_path="$HOME/.acme.sh/${domain}_ecc/fullchain.cer"
    
    # 检查证书文件是否存在
    if [ ! -f "$cert_path" ]; then
        log "INFO" "证书文件不存在，需要申请新证书"
        return 1
    fi
    
    # 检查证书是否即将过期（小于30天）
    local end_time
    end_time=$(openssl x509 -noout -enddate -in "$cert_path" 2>/dev/null | cut -d= -f2)
    
    if [ -z "$end_time" ]; then
        log "WARNING" "无法读取证书过期时间"
        return 1
    fi
    
    local end_epoch
    end_epoch=$(date -d "${end_time}" +%s 2>/dev/null)
    local now_epoch
    now_epoch=$(date +%s)
    local days_left
    days_left=$(( (end_epoch - now_epoch) / 86400 ))
    
    if [ "$days_left" -lt 30 ]; then
        log "WARNING" "证书还有 ${days_left} 天过期，需要续期"
        return 1
    fi
    
    log "INFO" "证书有效，还有 ${days_left} 天过期"
    return 0
}

# 申请证书
apply_cert() {
    check_acme || return 1
    local domain=$1
    local email=$2
    local token=$3
    
    # 先检查证书是否已存在且有效
    if check_cert "$domain"; then
        log "INFO" "当前证书仍然有效"
        read -p "是否要重新申请证书？[y/N] " answer
        if [[ "${answer,,}" != "y" ]]; then
            log "INFO" "使用现有的有效证书"
            copy_cert_files "$domain"
            return 0
        fi
    fi
    
    log "INFO" "开始申请SSL证书..."
    
    # 设置 DNS API 环境变量
    export DuckDNS_Token="${token}"
    
    # 添加延迟和重试机制
    local max_retries=3
    local retry_count=0
    local wait_time=120
    
    while [ $retry_count -lt $max_retries ]; do
        log "INFO" "尝试申请证书 (尝试 $((retry_count + 1))/$max_retries)"
        
        # 先更新 DuckDNS 记录
        local domain_name="${domain%%.*}"
        curl -s "https://www.duckdns.org/update?domains=${domain_name}&token=${token}&txt=verify" > /dev/null || true
        log "INFO" "等待 DNS 记录生效 (${wait_time}秒)..."
        sleep $wait_time
        
        # 申请证书
        if ~/.acme.sh/acme.sh --issue --dns dns_duckdns \
            -d "${domain}" \
            --accountemail "${email}" \
            --server letsencrypt \
            --dnssleep $wait_time \
            --log; then
            log "INFO" "证书申请成功！"
            break
        else
            retry_count=$((retry_count + 1))
            if [ $retry_count -lt $max_retries ]; then
                log "WARNING" "证书申请失败，等待重试..."
                wait_time=$((wait_time + 60))
                sleep 30
            else
                log "ERROR" "证书申请失败，已达到最大重试次数"
                return 1
            fi
        fi
    done

    # 复制证书文件
    copy_cert_files "$domain" || return 1
    
    # 设置证书更新时间
    set_status "cert_update_time" "$(date '+%Y-%m-%d %H:%M:%S')"
    
    return 0
}

# 复制证书文件
copy_cert_files() {
    local domain=$1
    
    # 验证证书文件
    local cert_path="$HOME/.acme.sh/${domain}_ecc/${domain}.cer"
    local key_path="$HOME/.acme.sh/${domain}_ecc/${domain}.key"
    local fullchain_path="$HOME/.acme.sh/${domain}_ecc/fullchain.cer"
    
    if [ ! -f "$cert_path" ] || [ ! -f "$key_path" ] || [ ! -f "$fullchain_path" ]; then
        log "ERROR" "证书文件未生成"
        return 1
    fi

    # 安装证书
    mkdir -p /etc/trojan-go
    ~/.acme.sh/acme.sh --install-cert -d "${domain}" --ecc \
        --key-file /etc/trojan-go/server.key \
        --fullchain-file /etc/trojan-go/server.crt \
        --reloadcmd "systemctl reload trojan-go 2>/dev/null || true"

    # 设置文件权限
    chmod 600 /etc/trojan-go/server.key
    chmod 644 /etc/trojan-go/server.crt
    
    log "INFO" "证书文件已安装"
    return 0
}

# 更新证书（单独功能）
update_cert() {
    log "INFO" "开始更新证书..."
    
    if ! check_trojan_installed; then
        log "ERROR" "Trojan-Go 未安装"
        return 1
    fi
    
    local domain=$(get_status "domain")
    local email=$(get_status "email")
    local duckdns_token=$(get_status "duckdns_token")
    
    if [ -z "$domain" ] || [ -z "$email" ] || [ -z "$duckdns_token" ]; then
        log "ERROR" "缺少证书配置信息，请重新安装"
        return 1
    fi
    
    # 强制更新证书
    log "INFO" "域名: $domain"
    log "INFO" "邮箱: $email"
    
    check_acme || return 1
    
    # 设置环境变量
    export DuckDNS_Token="${duckdns_token}"
    
    # 强制更新证书
    if ~/.acme.sh/acme.sh --renew -d "${domain}" --ecc --force; then
        log "INFO" "证书更新成功"
        copy_cert_files "$domain"
        
        # 重启服务
        if systemctl is-active --quiet trojan-go; then
            systemctl reload trojan-go
            log "INFO" "服务已重新加载"
        fi
        
        set_status "cert_update_time" "$(date '+%Y-%m-%d %H:%M:%S')"
        return 0
    else
        log "ERROR" "证书更新失败"
        return 1
    fi
}

# 更新 Trojan-Go
update_trojan() {
    log "INFO" "开始更新 Trojan-Go..."
    
    if ! check_trojan_installed; then
        log "ERROR" "Trojan-Go 未安装"
        return 1
    fi
    
    # 获取当前版本
    local current_version=$(get_current_version)
    if [ -z "$current_version" ]; then
        log "WARNING" "无法获取当前版本信息"
    else
        log "INFO" "当前版本: $current_version"
    fi
    
    # 检查网络
    check_network || return 1
    
    # 停止服务
    log "INFO" "停止 Trojan-Go 服务..."
    systemctl stop trojan-go
    
    # 备份配置文件
    if [ -f "$CONFIG_FILE" ]; then
        cp "$CONFIG_FILE" "${CONFIG_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
        log "INFO" "配置文件已备份"
    fi
    
    # 下载新版本
    if download_trojan; then
        log "INFO" "Trojan-Go 更新完成"
        
        # 重启服务
        if systemctl start trojan-go; then
            log "INFO" "服务启动成功"
            set_status "update_time" "$(date '+%Y-%m-%d %H:%M:%S')"
        else
            log "ERROR" "服务启动失败"
            return 1
        fi
    else
        log "ERROR" "更新失败，恢复服务"
        systemctl start trojan-go
        return 1
    fi
    
    return 0
}

# 卸载 Trojan-Go
uninstall_trojan() {
    log "WARNING" "开始卸载 Trojan-Go..."
    
    read -p "确定要卸载 Trojan-Go 吗？这将删除所有配置文件 [y/N] " answer
    if [[ "${answer,,}" != "y" ]]; then
        log "INFO" "取消卸载"
        return 0
    fi
    
    # 停止并禁用服务
    systemctl stop trojan-go 2>/dev/null || true
    systemctl disable trojan-go 2>/dev/null || true
    
    # 删除文件
    rm -rf /etc/trojan-go
    rm -f /usr/local/bin/trojan-go
    rm -rf /usr/local/share/trojan-go
    rm -f "$SERVICE_FILE"
    rm -f /var/log/trojan-go.log
    
    # 重新加载 systemd
    systemctl daemon-reload
    
    log "INFO" "Trojan-Go 已卸载"
    return 0
}

# 启动 Trojan-Go
start_trojan() {
    if systemctl start trojan-go; then
        log "INFO" "Trojan-Go 已启动"
    else
        log "ERROR" "Trojan-Go 启动失败"
        return 1
    fi
}

# 重启 Trojan-Go
restart_trojan() {
    if systemctl restart trojan-go; then
        log "INFO" "Trojan-Go 已重启"
    else
        log "ERROR" "Trojan-Go 重启失败"
        return 1
    fi
}

# 停止 Trojan-Go
stop_trojan() {
    if systemctl stop trojan-go; then
        log "INFO" "Trojan-Go 已停止"
    else
        log "ERROR" "Trojan-Go 停止失败"
        return 1
    fi
}

# 查看 Trojan-Go 状态
status_trojan() {
    log "INFO" "Trojan-Go 服务状态："
    systemctl status trojan-go --no-pager
    
    echo ""
    log "INFO" "端口监听状态："
    local port=$(get_status "port")
    if [ -n "$port" ]; then
        netstat -tlnp | grep ":$port " || log "WARNING" "端口 $port 未监听"
    fi
    
    echo ""
    log "INFO" "最近日志："
    if [ -f "/var/log/trojan-go.log" ]; then
        tail -10 /var/log/trojan-go.log
    else
        journalctl -u trojan-go --no-pager -n 10
    fi
}

# 查看配置信息
show_config() {
    if [ -f "$CONFIG_FILE" ]; then
        log "INFO" "Trojan-Go 配置信息："
        echo "----------------------------------------"
        cat "$CONFIG_FILE"
        echo "----------------------------------------"
        
        # 显示状态信息
        echo ""
        log "INFO" "安装状态："
        local domain=$(get_status "domain")
        local port=$(get_status "port")
        local password=$(get_status "password")
        local install_time=$(get_status "install_time")
        local cert_update_time=$(get_status "cert_update_time")
        local version=$(get_status "version")
        
        [ -n "$domain" ] && log "INFO" "域名: $domain"
        [ -n "$port" ] && log "INFO" "端口: $port"
        [ -n "$password" ] && log "INFO" "密码: $password"
        [ -n "$version" ] && log "INFO" "版本: $version"
        [ -n "$install_time" ] && log "INFO" "安装时间: $install_time"
        [ -n "$cert_update_time" ] && log "INFO" "证书更新时间: $cert_update_time"
        
        # 检查证书状态
        if [ -n "$domain" ]; then
            echo ""
            check_cert "$domain"
        fi
    else
        log "ERROR" "配置文件不存在"
        return 1
    fi
}

# 生成随机密码
generate_password() {
    # 生成32个字符的随机密码，包含字母、数字
    openssl rand -base64 24 | tr -d "=+/" | cut -c1-25
}

# 显示 OpenResty 配置
show_openresty_config() {
    # 读取 Trojan-Go 配置
    if [ ! -f "$CONFIG_FILE" ]; then
        log "ERROR" "Trojan-Go 配置文件不存在"
        return 1
    fi
    
    local domain=$(get_status "domain")
    local port=$(get_status "port")
    
    if [ -z "$domain" ] || [ -z "$port" ]; then
        log "ERROR" "无法获取配置信息"
        return 1
    fi

    local ws_path="/trojan"
    
    log "INFO" "OpenResty WebSocket 配置内容如下："
    echo "----------------------------------------"
    cat << EOF
# Trojan-Go WebSocket 配置
location ${ws_path} {
    proxy_redirect off;
    proxy_pass http://127.0.0.1:${port};
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_connect_timeout 60s;
    proxy_send_timeout 60s;
    proxy_read_timeout 60s;
}
EOF
    echo "----------------------------------------"
    log "INFO" "配置文件路径: /opt/1panel/apps/openresty/openresty/conf/conf.d/${domain}.conf"
    log "INFO" "请将以上配置添加到对应配置文件的 server {} 块内"
    return 0
}

# 查看日志
show_logs() {
    log "INFO" "显示 Trojan-Go 日志"
    
    echo "=== 系统日志 (最近20条) ==="
    journalctl -u trojan-go --no-pager -n 20
    
    echo ""
    echo "=== 应用日志 (最近20条) ==="
    if [ -f "/var/log/trojan-go.log" ]; then
        tail -20 /var/log/trojan-go.log
    else
        log "INFO" "应用日志文件不存在"
    fi
    
    echo ""
    echo "=== 安装日志 (最近20条) ==="
    if [ -f "$LOG_FILE" ]; then
        tail -20 "$LOG_FILE"
    else
        log "INFO" "安装日志文件不存在"
    fi
}

# 显示菜单
show_menu() {
    echo -e "
  ${GREEN}Trojan-Go 管理脚本 v2.0${PLAIN}
  ${GREEN}0.${PLAIN} 退出脚本
  ${GREEN}1.${PLAIN} 安装 Trojan-Go
  ${GREEN}2.${PLAIN} 更新 Trojan-Go
  ${GREEN}3.${PLAIN} 卸载 Trojan-Go
  ${GREEN}4.${PLAIN} 启动 Trojan-Go
  ${GREEN}5.${PLAIN} 重启 Trojan-Go
  ${GREEN}6.${PLAIN} 停止 Trojan-Go
  ${GREEN}7.${PLAIN} 查看 Trojan-Go 状态
  ${GREEN}8.${PLAIN} 查看配置信息
  ${GREEN}9.${PLAIN} 显示 OpenResty 配置
  ${GREEN}10.${PLAIN} 更新 SSL 证书
  ${GREEN}11.${PLAIN} 查看日志
  "
    read -p "请输入数字: " num
    case "$num" in
    0)
        log "INFO" "退出脚本"
        exit 0
        ;;
    1)
        install_trojan
        ;;
    2)
        update_trojan
        ;;
    3)
        uninstall_trojan
        ;;
    4)
        start_trojan
        ;;
    5)
        restart_trojan
        ;;
    6)
        stop_trojan
        ;;
    7)
        status_trojan
        ;;
    8)
        show_config
        ;;
    9)
        show_openresty_config
        ;;
    10)
        update_cert
        ;;
    11)
        show_logs
        ;;
    *)
        log "WARNING" "请输入正确的数字 (0-11)"
        ;;
    esac
}

# 主函数
main() {
    # 基础检查
    check_root
    check_sys
    
    # 创建日志目录
    mkdir -p $(dirname "$LOG_FILE")
    
    log "INFO" "Trojan-Go 管理脚本已启动"
    
    while true; do
        show_menu
        echo ""
        read -p "按 Enter 键继续..." 
        clear
    done
}

# 信号处理
trap 'log "INFO" "脚本被中断"; exit 1' INT TERM

# 开始运行脚本
main
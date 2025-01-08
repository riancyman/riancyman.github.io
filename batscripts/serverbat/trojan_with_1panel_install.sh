#!/bin/bash

# 颜色定义
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[36m"
PLAIN="\033[0m"

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
echo -e "${GREEN}              Trojan-Go 管理脚本                     ${PLAIN}"
echo -e "${GREEN}         系统支持: Ubuntu, Debian, CentOS            ${PLAIN}"
echo -e "${GREEN}=====================================================${PLAIN}"
echo -e "

注意事项:
1. 安装前请确保已解析域名到本机
2. 支持 DuckDNS 域名自动申请证书
3. 配置采用 WebSocket + TLS
4. 密码将自动随机生成
"

# 状态文件
STATUS_FILE="/etc/trojan-go/status.txt"

# 日志函数
log() {
    local level=$1
    shift
    local message=$@
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e "[$timestamp] [${level}] ${message}"
}

# 获取状态
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
    mkdir -p $(dirname "$STATUS_FILE")
    touch "$STATUS_FILE"
    if grep -q "^${key}=" "$STATUS_FILE"; then
        sed -i "s/^${key}=.*/${key}=${value}/" "$STATUS_FILE"
    else
        echo "${key}=${value}" >> "$STATUS_FILE"
    fi
}

# 检查系统
check_sys() {
    if [[ ! -f /etc/debian_version ]]; then
        log "ERROR" "系统不支持，请使用 Debian/Ubuntu"
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

# 安装必要的工具
install_requirements() {
    log "INFO" "安装必要的工具..."
    apt update
    apt install -y socat curl wget unzip
}

# 下载 Trojan-Go
download_trojan() {
    log "INFO" "下载 Trojan-Go..."
    local latest_version=$(curl -s https://api.github.com/repos/p4gefau1t/trojan-go/releases/latest | grep -oP '"tag_name": "\K[^"]+')
    if [ -z "$latest_version" ]; then
        echo "[$(date)] [ERROR] 无法获取 Trojan-Go 最新版本"
        return 1
    fi

    # 下载并安装
    wget -O /tmp/trojan-go.zip "https://github.com/p4gefau1t/trojan-go/releases/download/${latest_version}/trojan-go-linux-amd64.zip"
    
    if [ ! -f "/tmp/trojan-go.zip" ]; then
        echo "[$(date)] [ERROR] Trojan-Go 下载失败"
        return 1
    fi

    # 解压安装
    mkdir -p /usr/local/bin /usr/local/share/trojan-go
    unzip -o /tmp/trojan-go.zip -d /tmp/trojan-go/
    mv /tmp/trojan-go/trojan-go /usr/local/bin/
    chmod +x /usr/local/bin/trojan-go
    mv /tmp/trojan-go/geoip.dat /usr/local/share/trojan-go/
    mv /tmp/trojan-go/geosite.dat /usr/local/share/trojan-go/
}

# 安装 Trojan-Go
install_trojan() {
    echo "[$(date)] [INFO] 开始安装 Trojan-Go..."

    # 获取域名
    read -p "请输入域名 (例如: yourdomain.duckdns.org): " domain
    if [ -z "$domain" ]; then
        echo "[$(date)] [ERROR] 域名不能为空"
        return 1
    fi
    
    # 获取邮箱
    read -p "请输入邮箱地址 (不能使用 example.com): " email
    if [ -z "$email" ] || [[ "$email" == *"@example.com" ]]; then
        echo "[$(date)] [ERROR] 请输入有效的邮箱地址"
        return 1
    fi
    
    # 获取DuckDNS token
    read -p "请输入 DuckDNS token: " duckdns_token
    if [ -z "$duckdns_token" ]; then
        echo "[$(date)] [ERROR] DuckDNS token 不能为空"
        return 1
    fi

    # 验证DuckDNS域名是否可以访问
    echo "[$(date)] [INFO] 验证DuckDNS域名..."
    if ! curl -s "https://www.duckdns.org/update?domains=${domain%%.*}&token=${duckdns_token}&txt=verify" | grep -q "OK"; then
        echo "[$(date)] [ERROR] DuckDNS域名验证失败，请检查token是否正确"
        return 1
    fi

    # 提示用户输入配置信息
    read -p "请输入端口 [默认: 8521]: " port
    port=${port:-8521}

    # 生成随机密码
    local password=$(generate_password)
    echo "[$(date)] [INFO] 已生成随机密码: ${password}"

    # 下载并安装 Trojan-Go
    download_trojan || return 1

    # 创建配置目录
    mkdir -p /etc/trojan-go
    
    # 申请证书
    apply_cert "$domain" "$email" "$duckdns_token"
    if [ $? -ne 0 ]; then
        echo "[$(date)] [ERROR] 证书申请失败"
        return 1
    fi

    # 生成配置文件
    cat > /etc/trojan-go/config.json << EOF
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
    }
}
EOF

    # 创建 systemd 服务
    cat > /etc/systemd/system/trojan-go.service << EOF
[Unit]
Description=Trojan-Go - An unidentifiable mechanism that helps you bypass GFW
Documentation=https://p4gefau1t.github.io/trojan-go/
After=network.target nss-lookup.target

[Service]
Type=simple
StandardError=journal
User=root
AmbientCapabilities=CAP_NET_BIND_SERVICE
ExecStart=/usr/local/bin/trojan-go -config /etc/trojan-go/config.json
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10s

[Install]
WantedBy=multi-user.target
EOF

    # 重新加载 systemd 并启用服务
    systemctl daemon-reload
    systemctl enable trojan-go

    # 启动服务
    echo "[$(date)] [INFO] 启动 Trojan-Go 服务..."
    systemctl restart trojan-go
    if [ $? -ne 0 ]; then
        echo "[$(date)] [ERROR] Trojan-Go 启动失败"
        return 1
    fi
    echo "[$(date)] [INFO] Trojan-Go 启动成功"

    # 显示配置信息
    echo "[$(date)] [INFO] Trojan-Go 安装完成！"
    echo "[$(date)] [INFO] 配置信息："
    echo "[$(date)] [INFO] 域名: ${domain}"
    echo "[$(date)] [INFO] 端口: ${port}"
    echo "[$(date)] [INFO] 密码: ${password}"
    echo "[$(date)] [INFO] WebSocket 路径: /trojan"

    return 0
}

# 检查并安装 acme.sh
check_acme() {
    if [ ! -f "/root/.acme.sh/acme.sh" ]; then
        echo "[$(date)] [INFO] 未检测到 acme.sh，开始安装..."
        curl https://get.acme.sh | sh
        if [ $? -ne 0 ]; then
            echo "[$(date)] [ERROR] acme.sh 安装失败"
            return 1
        fi
        source ~/.bashrc
        echo "[$(date)] [INFO] acme.sh 安装完成"
    else
        echo "[$(date)] [INFO] acme.sh 已安装"
    fi
    return 0
}

# 检查证书是否存在且有效
check_cert() {
    local domain=$1
    local cert_path="$HOME/.acme.sh/${domain}_ecc/fullchain.cer"
    
    # 检查证书文件是否存在
    if [ ! -f "$cert_path" ]; then
        echo "[$(date)] [INFO] 证书文件不存在，需要申请新证书"
        return 1
    fi
    
    # 检查证书是否即将过期（小于30天）
    local end_time
    end_time=$(openssl x509 -noout -enddate -in "$cert_path" | cut -d= -f2)
    local end_epoch
    end_epoch=$(date -d "${end_time}" +%s)
    local now_epoch
    now_epoch=$(date +%s)
    local days_left
    days_left=$(( (end_epoch - now_epoch) / 86400 ))
    
    if [ "$days_left" -lt 30 ]; then
        echo "[$(date)] [INFO] 证书还有 ${days_left} 天过期，需要续期"
        return 1
    fi
    
    echo "[$(date)] [INFO] 证书有效，还有 ${days_left} 天过期"
    return 0
}

# 检查DNS记录是否生效
check_dns_record() {
    local domain=$1
    local retries=10
    local wait_time=30
    
    echo "[$(date)] [INFO] 检查DNS记录是否生效..."
    
    for ((i=1; i<=retries; i++)); do
        echo "[$(date)] [INFO] 第 $i 次检查 DNS 记录 (_acme-challenge.${domain})"
        if host -t TXT "_acme-challenge.${domain}" | grep -q "has TXT record"; then
            echo "[$(date)] [INFO] DNS记录已生效"
            return 0
        fi
        echo "[$(date)] [INFO] DNS记录未生效，等待 ${wait_time} 秒后重试..."
        sleep $wait_time
    done
    
    echo "[$(date)] [ERROR] DNS记录未能在预期时间内生效"
    return 1
}

# 申请证书
apply_cert() {
    check_acme || return 1
    local domain=$1
    local email=$2
    local token=$3
    
    # 先检查证书是否已存在且有效
    if check_cert "$domain"; then
        echo "[$(date)] [INFO] 当前证书仍然有效"
        read -p "是否要重新申请证书？[y/N] " answer
        if [[ "${answer,,}" != "y" ]]; then
            echo "[$(date)] [INFO] 使用现有的有效证书"
            return 0
        fi
    fi
    
    echo "[$(date)] [INFO] 开始申请SSL证书..."
    
    # 设置 DNS API 环境变量
    export DuckDNS_Token="${token}"
    
    # 添加延迟和重试机制
    local max_retries=3
    local retry_count=0
    local wait_time=120  # 增加等待时间到 120 秒
    
    while [ $retry_count -lt $max_retries ]; do
        echo "[$(date)] [INFO] 尝试申请证书 (尝试 $((retry_count + 1))/$max_retries)"
        
        # 先更新 DuckDNS 记录
        curl -s "https://www.duckdns.org/update?domains=${domain%%.*}&token=${token}&txt=verify" || true
        echo "[$(date)] [INFO] 等待 DNS 记录生效 (${wait_time}秒)..."
        sleep $wait_time
        
        # 使用 --debug 2 来获取更详细的错误信息
        ~/.acme.sh/acme.sh --issue --dns dns_duckdns \
            -d "${domain}" \
            --accountemail "${email}" \
            --server letsencrypt \
            --dnssleep $wait_time \
            --debug 2
        
        if [ $? -eq 0 ]; then
            echo "[$(date)] [INFO] 证书申请成功！"
            break
        else
            retry_count=$((retry_count + 1))
            if [ $retry_count -lt $max_retries ]; then
                echo "[$(date)] [WARNING] 证书申请失败，等待重试..."
                wait_time=$((wait_time + 60))  # 每次重试增加等待时间
                sleep 30
            else
                echo "[$(date)] [ERROR] 证书申请失败，已达到最大重试次数"
                return 1
            fi
        fi
    done

    # 验证证书文件
    local cert_path="$HOME/.acme.sh/${domain}_ecc/${domain}.cer"
    local key_path="$HOME/.acme.sh/${domain}_ecc/${domain}.key"
    local fullchain_path="$HOME/.acme.sh/${domain}_ecc/fullchain.cer"
    
    if [ ! -f "$cert_path" ] || [ ! -f "$key_path" ] || [ ! -f "$fullchain_path" ]; then
        echo "[$(date)] [ERROR] 证书文件未生成"
        return 1
    fi

    # 安装证书
    mkdir -p /etc/trojan-go
    ~/.acme.sh/acme.sh --install-cert -d "${domain}" --ecc \
        --key-file /etc/trojan-go/server.key \
        --fullchain-file /etc/trojan-go/server.crt

    return 0
}

# 更新 Trojan-Go
update_trojan() {
    echo "[$(date)] [INFO] 开始更新 Trojan-Go..."
    # TODO: 实现更新功能
}

# 卸载 Trojan-Go
uninstall_trojan() {
    echo "[$(date)] [INFO] 开始卸载 Trojan-Go..."
    systemctl stop trojan-go
    systemctl disable trojan-go
    rm -rf /etc/trojan-go
    rm -f /usr/local/bin/trojan-go
    rm -rf /usr/local/share/trojan-go
    rm -f /etc/systemd/system/trojan-go.service
    systemctl daemon-reload
    echo "[$(date)] [INFO] Trojan-Go 已卸载"
}

# 启动 Trojan-Go
start_trojan() {
    systemctl start trojan-go
    echo "[$(date)] [INFO] Trojan-Go 已启动"
}

# 重启 Trojan-Go
restart_trojan() {
    systemctl restart trojan-go
    echo "[$(date)] [INFO] Trojan-Go 已重启"
}

# 停止 Trojan-Go
stop_trojan() {
    systemctl stop trojan-go
    echo "[$(date)] [INFO] Trojan-Go 已停止"
}

# 查看 Trojan-Go 状态
status_trojan() {
    systemctl status trojan-go
}

# 查看配置信息
show_config() {
    if [ -f "/etc/trojan-go/config.json" ]; then
        echo "[$(date)] [INFO] Trojan-Go 配置信息："
        cat /etc/trojan-go/config.json
    else
        echo "[$(date)] [INFO] 配置文件不存在"
    fi
}

# 生成随机密码
generate_password() {
    # 生成32个字符的随机密码，包含字母、数字
    local password=$(openssl rand -base64 24)
    echo "$password"
}

# 显示 OpenResty 配置
show_openresty_config() {
    # 读取 Trojan-Go 配置
    if [ ! -f "/etc/trojan-go/config.json" ]; then
        echo "[$(date)] [ERROR] Trojan-Go 配置文件不存在"
        return 1
    fi
    
    local domain=$(grep -o '"sni": "[^"]*"' /etc/trojan-go/config.json | cut -d'"' -f4)
    local port=$(grep -o '"local_port": [0-9]*' /etc/trojan-go/config.json | awk '{print $2}')
    local ws_path=$(grep -o '"path": "[^"]*"' /etc/trojan-go/config.json | cut -d'"' -f4)
    
    if [ -z "$domain" ] || [ -z "$port" ] || [ -z "$ws_path" ]; then
        echo "[$(date)] [ERROR] 无法从 Trojan-Go 配置中读取必要信息"
        return 1
    fi

    echo "[$(date)] [INFO] OpenResty WebSocket 配置内容如下："
    echo "----------------------------------------"
    cat << EOF
location ${ws_path} {
    proxy_redirect off;
    proxy_pass http://127.0.0.1:${port};
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
}
EOF
    echo "----------------------------------------"
    echo "[$(date)] [INFO] 配置文件: /opt/1panel/apps/openresty/openresty/conf/conf.d/${domain}.conf"
    echo "[$(date)] [INFO] 请将以上配置添加到此配置文件的 server {} 块内"
    return 0
}

# 显示菜单
show_menu() {
    echo -e "
  ${GREEN}Trojan-Go 管理脚本${PLAIN}
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
  "
    read -p "请输入数字: " num
    case "$num" in
    0)
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
    *)
        echo "请输入正确的数字"
        ;;
    esac
}

main() {
    check_root
    
    while true; do
        show_menu
        sleep 2
    done
}

# 开始运行脚本
main
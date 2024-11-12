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
MULTI_PORT_CONFIGURED=0
UFW_CONFIGURED=0
BBR_INSTALLED=0
UPSTREAM_SERVERS=""
LISTEN_PORTS=""
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
    
    # 更新系统
    apt update && apt upgrade -y
    
    # 安装基础软件包
    apt install -y curl wget unzip ufw socat

    set_status SYSTEM_PREPARED 1
    log "SUCCESS" "系统环境准备完成"
    return 0
}

# 安装 HAProxy
install_haproxy() {
    log "INFO" "开始安装 HAProxy..."
    
    # 添加HAProxy官方源
    curl -fsSL https://haproxy.debian.net/bernat.debian.org.gpg | gpg --dearmor -o /usr/share/keyrings/haproxy.debian.net.gpg
    
    echo "deb [signed-by=/usr/share/keyrings/haproxy.debian.net.gpg] http://haproxy.debian.net bookworm-backports-2.8 main" > /etc/apt/sources.list.d/haproxy.list
    
    # 更新源并安装HAProxy
    apt update
    apt install -y haproxy=2.8.\*
    
    # 创建HAProxy配置目录
    mkdir -p /etc/haproxy/certs
    
    # 基础配置
    cat > /etc/haproxy/haproxy.cfg << 'EOF'
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
    stats auth admin:admin123
    stats refresh 10s
EOF
    
    # 启动HAProxy
    systemctl enable haproxy
    systemctl restart haproxy
    
    if systemctl is-active --quiet haproxy; then
        set_status HAPROXY_INSTALLED 1
        log "SUCCESS" "HAProxy 安装完成"
        return 0
    else
        log "ERROR" "HAProxy 启动失败，请检查配置"
        return 1
    fi
}

# 配置多端口转发
configure_relay() {
    log "INFO" "配置端口转发..."
    
    # 临时存储配置
    local config_content=""
    local upstream_servers=""
    local listen_ports=""
    
    # 询问上游服务器数量
    read -p "请输入上游服务器数量: " server_count
    
    for ((i=1; i<=server_count; i++)); do
        # 获取上游服务器信息
        read -p "请输入第${i}个上游服务器域名或IP: " server_addr
        read -p "请输入第${i}个上游服务器端口: " server_port
        read -p "请输入本地监听端口: " listen_port
        
        # 检查端口是否被占用
        if ! check_port $listen_port; then
            log "ERROR" "端口 ${listen_port} 已被占用"
            continue
        fi
        
        # 生成配置
        config_content="${config_content}
# 第${i}个转发配置
frontend ft_${listen_port}
    bind *:${listen_port}
    default_backend bk_${server_addr}_${server_port}

backend bk_${server_addr}_${server_port}
    server server1 ${server_addr}:${server_port} check
"
        
        # 记录配置信息
        upstream_servers="${upstream_servers}${server_addr}:${server_port},"
        listen_ports="${listen_ports}${listen_port},"
    done
    
    # 更新HAProxy配置
    echo "${config_content}" >> /etc/haproxy/haproxy.cfg
    
    # 保存配置信息
    set_status UPSTREAM_SERVERS "${upstream_servers%,}"
    set_status LISTEN_PORTS "${listen_ports%,}"
    
    # 重启HAProxy
    systemctl restart haproxy
    
    set_status MULTI_PORT_CONFIGURED 1
    log "SUCCESS" "端口转发配置完成"
    return 0
}

# 配置 UFW 防火墙
configure_ufw() {
    log "INFO" "配置 UFW 防火墙..."
    
    # 获取已配置的端口
    local listen_ports=$(get_status LISTEN_PORTS)
    local ssh_port=$(ss -tulpn | grep -i ssh | awk '{print $5}' | awk -F: '{print $2}')
    
    # 重置 UFW
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    
    # 允许 SSH 端口
    ufw allow ${ssh_port}/tcp
    
    # 允许所有配置的监听端口
    IFS=',' read -ra PORTS <<< "$listen_ports"
    for port in "${PORTS[@]}"; do
        ufw allow ${port}/tcp
    done
    
    # 允许状态页面端口
    ufw allow 10086/tcp
    
    # 启用 UFW
    echo "y" | ufw enable
    
    set_status UFW_CONFIGURED 1
    log "SUCCESS" "UFW 防火墙配置完成"
    return 0
}

# 安装 BBR 加速
install_bbr() {
    log "INFO" "检查 BBR 状态..."
    
    if lsmod | grep -q bbr; then
        log "SUCCESS" "BBR 已经启用"
        set_status BBR_INSTALLED 1
        return 0
    fi
    
    # 配置BBR
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    sysctl -p
    
    if lsmod | grep -q bbr; then
        set_status BBR_INSTALLED 1
        log "SUCCESS" "BBR 安装成功"
        return 0
    else
        log "ERROR" "BBR 安装失败"
        return 1
    fi
}

# 查看配置信息
show_config() {
    local upstream_servers=$(get_status UPSTREAM_SERVERS)
    local listen_ports=$(get_status LISTEN_PORTS)
    
    echo "=================== 转发配置信息 ==================="
    echo "已配置的转发规则："
    
    IFS=',' read -ra SERVERS <<< "$upstream_servers"
    IFS=',' read -ra PORTS <<< "$listen_ports"
    
    for i in "${!SERVERS[@]}"; do
        echo "规则 $((i+1)):"
        echo "  监听端口: ${PORTS[i]}"
        echo "  上游服务器: ${SERVERS[i]}"
    done
    
    echo "HAProxy 状态页面："
    echo "  地址: http://服务器IP:10086"
    echo "  用户名: admin"
    echo "  密码: admin123"
    echo "================================================="
}

# 查看服务状态
show_status() {
    echo "=================== 服务运行状态 ==================="
    
    echo -e "\n[ HAProxy 状态 ]"
    systemctl status haproxy --no-pager | grep -E "Active:|running"
    
    echo -e "\n[ UFW 状态 ]"
    ufw status verbose
    
    echo -e "\n[ BBR 状态 ]"
    if lsmod | grep -q bbr; then
        echo -e "${GREEN}BBR: 已启用${PLAIN}"
    else
        echo -e "${RED}BBR: 未启用${PLAIN}"
    fi
    
    echo -e "\n[ 端口监听状态 ]"
    ss -tulpn | grep 'haproxy'
    echo "================================================="
}

# 重启服务
restart_services() {
    log "INFO" "重启所有服务..."
    
    systemctl restart haproxy
    
    if systemctl is-active --quiet haproxy; then
        log "SUCCESS" "服务重启成功"
    else
        log "ERROR" "服务重启失败"
    fi
}

# 卸载组件
uninstall_all() {
    log "WARNING" "即将卸载所有组件..."
    read -p "确定要卸载吗？[y/N] " answer
    if [[ "${answer,,}" != "y" ]]; then
        return 0
    fi
    
    systemctl stop haproxy
    systemctl disable haproxy
    apt remove --purge -y haproxy
    rm -rf /etc/haproxy
    rm -rf $INSTALL_STATUS_DIR
    ufw --force reset
    
    log "SUCCESS" "卸载完成"
}

# 显示菜单
show_menu() {
    clear
    echo "=========== HAProxy 中转管理系统 ==========="
    echo -e " 1. 系统环境准备 $(if [ "$(get_status SYSTEM_PREPARED)" = "1" ]; then echo "${GREEN}[OK]${PLAIN}"; fi)"
    echo -e " 2. 安装 HAProxy $(if [ "$(get_status HAPROXY_INSTALLED)" = "1" ]; then echo "${GREEN}[OK]${PLAIN}"; fi)"
    echo -e " 3. 配置端口转发 $(if [ "$(get_status MULTI_PORT_CONFIGURED)" = "1" ]; then echo "${GREEN}[OK]${PLAIN}"; fi)"
    echo -e " 4. 配置 UFW 防火墙 $(if [ "$(get_status UFW_CONFIGURED)" = "1" ]; then echo "${GREEN}[OK]${PLAIN}"; fi)"
    echo -e " 5. 安装 BBR 加速 $(if [ "$(get_status BBR_INSTALLED)" = "1" ]; then echo "${GREEN}[OK]${PLAIN}"; fi)"
    echo " 6. 查看配置信息"
    echo " 7. 查看运行状态"
    echo " 8. 重启服务"
    echo " 9. 卸载所有组件"
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
        read -p "请选择操作[0-9]: " choice
        case "${choice}" in
            0) exit 0 ;;
            1) prepare_system ;;
            2) install_haproxy ;;
            3) configure_relay ;;
            4) configure_ufw ;;
            5) install_bbr ;;
            6) show_config ;;
            7) show_status ;;
            8) restart_services ;;
            9) uninstall_all ;;
            *) log "ERROR" "无效的选择" ;;
        esac
        echo
        read -p "按回车键继续..." </dev/tty
    done
}

# 启动脚本
main "$@"
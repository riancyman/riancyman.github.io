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
STATS_USER=""
STATS_PASS=""
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

# 检查安装结果
check_install_success() {
    local service=$1
    local status=$2
    
    if [ "$status" -eq 0 ]; then
        return 0
    fi
    return 1
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
        curl wget unzip ufw socat

    local status=$?
    if check_install_success "系统环境" $status; then
        set_status SYSTEM_PREPARED 1
        log "SUCCESS" "系统环境准备完成"
        return 0
    else
        log "ERROR" "系统环境准备失败"
        return 1
    fi
}

# 安装 HAProxy
install_haproxy() {
    log "INFO" "开始安装 HAProxy..."
    
    # 安装HAProxy
    apt-get update
    apt-get install -y haproxy

    # 如果安装失败，尝试使用官方源
    if [ $? -ne 0 ]; then
        curl -fsSL https://haproxy.debian.net/bernat.debian.org.gpg | gpg --dearmor -o /usr/share/keyrings/haproxy.debian.net.gpg
        echo "deb [signed-by=/usr/share/keyrings/haproxy.debian.net.gpg] http://haproxy.debian.net bookworm-backports-2.8 main" > /etc/apt/sources.list.d/haproxy.list
        apt-get update
        apt-get install -y haproxy=2.8.\*
    fi

    local status=$?
    if [ $status -ne 0 ]; then
        log "ERROR" "HAProxy 安装失败"
        return 1
    fi
    
    # 创建基础配置
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

    # 设置权限
    chown -R haproxy:haproxy /etc/haproxy
    
    # 启动服务
    systemctl enable haproxy
    systemctl restart haproxy

    # 验证服务状态
    if systemctl is-active --quiet haproxy; then
        set_status HAPROXY_INSTALLED 1
        log "SUCCESS" "HAProxy 安装完成"
        return 0
    else
        log "ERROR" "HAProxy 启动失败"
        return 1
    fi
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
    
    # 询问上游服务器信息
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
    server server1 ${server_addr}:${server_port} check inter 2000 rise 2 fall 3
EOF
        
        upstream_servers="${upstream_servers}${server_addr}:${server_port},"
        listen_ports="${listen_ports}${listen_port},"
    done

    # 保存认证信息到状态文件
    set_status STATS_USER "${stats_user}"
    set_status STATS_PASS "${stats_pass}"
    
    # 检查配置语法
    if ! haproxy -c -f /etc/haproxy/haproxy.cfg; then
        log "ERROR" "配置文件有误，正在回滚..."
        mv /etc/haproxy/haproxy.cfg.bak /etc/haproxy/haproxy.cfg
        return 1
    fi
    
    # 重启服务
    systemctl restart haproxy
    
    if systemctl is-active --quiet haproxy; then
        # 添加调试日志
        log "INFO" "保存配置信息："
        log "INFO" "上游服务器: ${upstream_servers%,}"
        log "INFO" "监听端口: ${listen_ports%,}"
        
        # 保存状态
        set_status "UPSTREAM_SERVERS" "${upstream_servers%,}"
        set_status "LISTEN_PORTS" "${listen_ports%,}"
        set_status "MULTI_PORT_CONFIGURED" "1"
        
        # 验证保存结果
        local saved_servers=$(get_status "UPSTREAM_SERVERS")
        local saved_ports=$(get_status "LISTEN_PORTS")
        log "INFO" "已保存的配置："
        log "INFO" "上游服务器: ${saved_servers}"
        log "INFO" "监听端口: ${saved_ports}"
        
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
    
    # 允许HAProxy端口
    local listen_ports=$(get_status LISTEN_PORTS)
    IFS=',' read -ra PORTS <<< "$listen_ports"
    for port in "${PORTS[@]}"; do
        ufw allow ${port}/tcp
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

# 检查配置的函数
check_relay_config() {
    log "INFO" "检查转发配置..."
    
    # 检查配置文件
    if [ -f "/etc/haproxy/haproxy.cfg" ]; then
        echo "HAProxy配置文件内容："
        cat /etc/haproxy/haproxy.cfg
    else
        log "ERROR" "HAProxy配置文件不存在"
    fi
    
    # 检查状态文件
    if [ -f "$STATUS_FILE" ]; then
        echo "状态文件内容："
        cat "$STATUS_FILE"
    else
        log "ERROR" "状态文件不存在"
    fi
    
    # 检查服务状态
    echo "HAProxy服务状态："
    systemctl status haproxy
    
    # 检查端口监听
    echo "端口监听状态："
    ss -tuln | grep 'LISTEN'
}

# 显示配置信息
show_config() {
    echo "====================== 转发配置信息 ======================"
    
    local upstream_servers=$(get_status UPSTREAM_SERVERS)
    local listen_ports=$(get_status LISTEN_PORTS)
    local stats_user=$(get_status STATS_USER)
    local stats_pass=$(get_status STATS_PASS)
    
    if [ -n "$upstream_servers" ] && [ -n "$listen_ports" ]; then
        IFS=',' read -ra SERVERS <<< "$upstream_servers"
        IFS=',' read -ra PORTS <<< "$listen_ports"
        
        for i in "${!SERVERS[@]}"; do
            echo -e "转发规则 $((i+1)):"
            echo -e "  本地端口: ${GREEN}${PORTS[i]}${PLAIN}"
            echo -e "  上游服务器: ${GREEN}${SERVERS[i]}${PLAIN}"
        done
    else
        echo "未找到转发配置"
    fi
    
    echo -e "\nHAProxy 状态页面："
    echo -e "  地址: http://服务器IP:10086"
    echo -e "  用户名: ${GREEN}${stats_user}${PLAIN}"
    echo -e "  密码: ${GREEN}${stats_pass}${PLAIN}"
    echo "======================================================="
}

# 显示状态
show_status() {
    echo "====================== 服务运行状态 ======================"
    
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
    ss -tuln | grep -E ":(10086|${listen_ports// /|})"
    echo "======================================================="
}

# 重启服务
restart_services() {
    log "INFO" "重启服务..."
    
    systemctl restart haproxy
    
    if systemctl is-active --quiet haproxy; then
        log "SUCCESS" "服务重启成功"
        show_status
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
    echo -e " 2. 安装 HAProxy $(if [ "$(get_status HAPROXY_INSTALLED)" = "1" ]; then echo "${GREEN}[OK]${PLAIN}"; fi)"
    echo -e " 3. 配置端口转发 $(if [ "$(get_status MULTI_PORT_CONFIGURED)" = "1" ]; then echo "${GREEN}[OK]${PLAIN}"; fi)"
    echo -e " 4. 配置 UFW 防火墙 $(if [ "$(get_status UFW_CONFIGURED)" = "1" ]; then echo "${GREEN}[OK]${PLAIN}"; fi)"
    echo -e " 5. 安装 BBR 加速 $(if [ "$(get_status BBR_INSTALLED)" = "1" ]; then echo "${GREEN}[OK]${PLAIN}"; fi)"
    echo " 6. 查看配置信息"
    echo " 7. 查看运行状态"
    echo " 8. 重启服务"
    echo " 9. 卸载所有组件"
    echo " 10. 检查配置" # 新添加的选项
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
            0) 
                exit 0 
                ;;
            1) 
                check_reinstall "系统环境" "SYSTEM_PREPARED" && prepare_system
                ;;
            2)
                check_reinstall "HAProxy" "HAPROXY_INSTALLED" && install_haproxy
                ;;
            3)
                check_reinstall "端口转发" "MULTI_PORT_CONFIGURED" && configure_relay
                ;;
            4)
                check_reinstall "UFW防火墙" "UFW_CONFIGURED" && configure_ufw
                ;;
            5)
                check_reinstall "BBR加速" "BBR_INSTALLED" && install_bbr
                ;;
            6)
                show_config
                ;;
            7)
                show_status
                ;;
            8)
                restart_services
                ;;
            9)
                uninstall_all
                ;;
            10)
                check_relay_config
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
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
echo -e "${GREEN}              Trojan-Go 管理脚本 v2.1                ${PLAIN}"
echo -e "${GREEN}     系统支持: Debian 12/13, Ubuntu, CentOS        ${PLAIN}"
echo -e "${GREEN}     新增功能: 服务器初始化 + UFW防火墙          ${PLAIN}"
echo -e "${GREEN}=====================================================${PLAIN}"
echo -e "
注意事项:
1. 安装前请确保已解析域名到本机
2. 支持 DuckDNS 域名自动申请证书
3. 配置采用 WebSocket + TLS
4. 密码将自动随机生成
5. 支持证书自动更新和手动更新
6. 新增服务器初始化功能 (Debian 12/13 优化)
7. 支持SSH端口修改和UFW防火墙配置
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
        local debian_version=$(cat /etc/debian_version)
        log "INFO" "检测到 Debian/Ubuntu 系统，版本: $debian_version"
        
        # 检查是否为 Debian 12/13
        if [[ "$debian_version" =~ ^12\. ]] || [[ "$debian_version" =~ ^13\. ]]; then
            log "INFO" "系统版本受支持: Debian 12/13"
            return 0
        elif [[ "$debian_version" =~ ^11\. ]]; then
            log "WARNING" "检测到 Debian 11，建议升级到 Debian 12+"
            return 0
        else
            log "INFO" "Debian/Ubuntu 系统，继续安装"
            return 0
        fi
    elif [[ -f /etc/redhat-release ]]; then
        log "INFO" "检测到 CentOS/RHEL 系统"
        return 0
    else
        log "ERROR" "系统不支持，请使用 Debian 12+/Ubuntu/CentOS"
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

# 检查服务状态
check_service_status() {
    local service_name=$1
    if systemctl is-active --quiet "$service_name"; then
        return 0
    else
        return 1
    fi
}

# 检查端口占用
check_port_in_use() {
    local port=$1
    if netstat -tlnp | grep -q ":$port "; then
        return 0
    else
        return 1
    fi
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

# 服务器初始化 - 安装基础工具
init_server_basic() {
    log "INFO" "开始服务器基础初始化..."
    
    log "INFO" "更新软件包列表..."
    if [[ -f /etc/debian_version ]]; then
        apt update -y
        apt upgrade -y
        apt install -y unzip wget curl cron nano vim htop net-tools lsof
    elif [[ -f /etc/redhat-release ]]; then
        yum update -y
        yum install -y unzip wget curl crontabs nano vim htop net-tools lsof
    fi
    
    if [ $? -eq 0 ]; then
        log "INFO" "基础工具安装完成"
    else
        log "ERROR" "基础工具安装失败"
        return 1
    fi
    
    # 设置时区为亚洲/上海
    timedatectl set-timezone Asia/Shanghai
    log "INFO" "时区已设置为 Asia/Shanghai"
    
    # 配置 vim
    if [ ! -f ~/.vimrc ]; then
        echo "set number" > ~/.vimrc
        echo "set tabstop=4" >> ~/.vimrc
        echo "set shiftwidth=4" >> ~/.vimrc
        log "INFO" "vim 基础配置已完成"
    fi
    
    return 0
}

# 获取当前SSH端口
get_current_ssh_port() {
    local current_port=$(grep "^Port" /etc/ssh/sshd_config | awk '{print $2}' | head -n1)
    if [ -z "$current_port" ]; then
        current_port=22  # SSH默认端口
    fi
    echo "$current_port"
}

# 修改SSH端口
change_ssh_port() {
    log "INFO" "SSH端口配置管理"
    
    local current_port=$(get_current_ssh_port)
    log "INFO" "当前SSH端口: ${YELLOW}$current_port${PLAIN}"
    
    echo -e "${GREEN}请选择操作:${PLAIN}"
    echo "1. 保持当前端口 ($current_port)"
    echo "2. 修改为其他端口"
    echo "3. 查看端口占用情况"
    echo "4. 取消操作"
    
    read -p "请输入选择 [1-4]: " choice
    
    case $choice in
        1)
            log "INFO" "保持当前SSH端口: $current_port"
            return 0
            ;;
        2)
            ;;
        3)
            log "INFO" "当前监听端口:"
            netstat -tlnp | grep -E "(ssh|sshd)" || echo "暂无SSH服务监听"
            echo ""
            read -p "按Enter键继续端口修改..."
            ;;
        4)
            log "INFO" "取消SSH端口修改"
            return 0
            ;;
        *)
            log "WARNING" "无效选择，取消操作"
            return 1
            ;;
    esac
    
    # 如果选择了修改端口，继续执行
    if [ "$choice" != "2" ]; then
        return 0
    fi
    
    echo -e "${YELLOW}⚠️  警告: 修改SSH端口前请确保:${PLAIN}"
    echo "   - 您有其他方式访问服务器(如控制台)"
    echo "   - 新端口未被防火墙阻止"
    echo "   - 记住新端口号"
    echo ""
    
    while true; do
        read -p "请输入新的SSH端口 (1-65535，建议1024-65535): " new_port
        
        # 验证端口格式
        if ! [[ "$new_port" =~ ^[0-9]+$ ]] || [ "$new_port" -lt 1 ] || [ "$new_port" -gt 65535 ]; then
            log "ERROR" "端口必须是 1-65535 之间的数字"
            continue
        fi
        
        # 检查是否为常用危险端口
        if [ "$new_port" -lt 1024 ] && [ "$new_port" != "22" ]; then
            log "WARNING" "端口 $new_port 是特权端口(小于1024)，可能需要特殊权限"
            read -p "是否继续使用此端口? [y/N] " confirm_low
            if [[ "${confirm_low,,}" != "y" ]]; then
                continue
            fi
        fi
        
        # 检查端口是否被占用
        if check_port_in_use "$new_port"; then
            log "WARNING" "端口 $new_port 已被以下服务占用:"
            netstat -tlnp | grep ":$new_port "
            read -p "是否强制使用该端口? [y/N] " force_confirm
            if [[ "${force_confirm,,}" != "y" ]]; then
                continue
            fi
        fi
        
        # 确认修改
        echo ""
        log "INFO" "确认修改SSH端口: ${YELLOW}$current_port${PLAIN} → ${GREEN}$new_port${PLAIN}"
        read -p "确认要修改SSH端口吗? [y/N] " final_confirm
        
        if [[ "${final_confirm,,}" == "y" ]]; then
            break
        else
            log "INFO" "取消端口修改"
            return 0
        fi
    done
    
    # 创建备份
    local backup_file="/etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S)"
    cp /etc/ssh/sshd_config "$backup_file"
    log "INFO" "SSH配置文件已备份到: $backup_file"
    
    # 修改端口
    log "INFO" "正在修改SSH配置..."
    if grep -q "^Port" /etc/ssh/sshd_config; then
        sed -i "s/^Port.*/Port $new_port/" /etc/ssh/sshd_config
    else
        sed -i "1i Port $new_port" /etc/ssh/sshd_config
    fi
    
    # 验证配置
    log "INFO" "验证SSH配置..."
    if [[ -f /etc/debian_version ]]; then
        sshd -t
    elif [[ -f /etc/redhat-release ]]; then
        sshd -t
    fi
    
    if [ $? -ne 0 ]; then
        log "ERROR" "SSH配置验证失败，恢复备份配置"
        cp "$backup_file" /etc/ssh/sshd_config
        return 1
    fi
    
    # 重启SSH服务
    log "INFO" "重启SSH服务..."
    if [[ -f /etc/debian_version ]]; then
        systemctl restart ssh
    elif [[ -f /etc/redhat-release ]]; then
        systemctl restart sshd
    fi
    
    if [ $? -eq 0 ]; then
        log "INFO" "SSH端口修改成功！"
        echo -e "${GREEN}=====================================================${PLAIN}"
        log "WARNING" "重要提醒:"
        log "WARNING" "SSH端口已修改为: ${YELLOW}$new_port${PLAIN}"
        log "WARNING" "下次登录请使用新端口: ssh user@your_server -p $new_port"
        log "WARNING" "配置文件备份在: $backup_file"
        echo -e "${GREEN}=====================================================${PLAIN}"
        
        # 保存新端口到状态文件
        set_status "ssh_port" "$new_port"
        set_status "ssh_config_backup" "$backup_file"
        
        return 0
    else
        log "ERROR" "SSH服务重启失败，恢复备份配置"
        cp "$backup_file" /etc/ssh/sshd_config
        systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
        return 1
    fi
}

# 安装和配置UFW防火墙
setup_ufw_firewall() {
    log "INFO" "开始配置UFW防火墙..."
    
    # 检查UFW是否已安装
    if ! command -v ufw &> /dev/null; then
        log "INFO" "安装UFW防火墙..."
        if [[ -f /etc/debian_version ]]; then
            apt install -y ufw
        elif [[ -f /etc/redhat-release ]]; then
            yum install -y ufw
        fi
        
        if [ $? -ne 0 ]; then
            log "ERROR" "UFW安装失败"
            return 1
        fi
    fi
    
    # 获取当前SSH端口
    local current_ssh_port=$(get_current_ssh_port)
    log "INFO" "检测到当前SSH端口: ${YELLOW}$current_ssh_port${PLAIN}"
    
    # 重置UFW（清除现有规则）
    ufw --force reset
    
    # 设置默认策略
    ufw default deny incoming
    ufw default allow outgoing
    
    log "INFO" "防火墙默认策略: 拒绝入站，允许出站"
    
    # SSH端口处理 - 智能提示
    echo ""
    echo -e "${YELLOW}🔥 SSH端口配置检测${PLAIN}"
    echo "当前SSH端口: $current_ssh_port"
    
    if [ "$current_ssh_port" == "22" ]; then
        echo -e "${YELLOW}⚠️  警告: 您正在使用默认SSH端口22${PLAIN}"
        echo "建议修改为其他端口以增强安全性"
        read -p "是否要修改SSH端口? [y/N] " change_port
        
        if [[ "${change_port,,}" == "y" ]]; then
            # 先修改SSH端口
            change_ssh_port
            if [ $? -eq 0 ]; then
                # 重新获取端口
                current_ssh_port=$(get_current_ssh_port)
                log "INFO" "SSH端口已更新为: $current_ssh_port"
            else
                log "WARNING" "SSH端口修改失败，继续使用端口22"
                current_ssh_port=22
            fi
        else
            log "INFO" "继续使用SSH端口22"
        fi
    else
        echo -e "${GREEN}✓ SSH端口已设置为非默认端口，安全性较好${PLAIN}"
        read -p "是否保持当前SSH端口? [Y/n] " keep_port
        if [[ "${keep_port,,}" == "n" ]]; then
            change_ssh_port
            if [ $? -eq 0 ]; then
                current_ssh_port=$(get_current_ssh_port)
            fi
        fi
    fi
    
    # 开放SSH端口
    ufw allow "$current_ssh_port/tcp" comment "SSH Port"
    log "INFO" "已开放SSH端口: $current_ssh_port"
    
    # 询问是否开放Web端口
    echo ""
    echo -e "${GREEN}🌐 Web服务端口配置${PLAIN}"
    read -p "是否要开放Web服务端口(80/443)? [Y/n] " web_ports
    
    if [[ "${web_ports,,}" != "n" ]]; then
        ufw allow 80/tcp comment 'HTTP Web'
        ufw allow 443/tcp comment 'HTTPS Web'
        log "INFO" "已开放Web端口: 80, 443"
    fi
    
    # 询问是否开放Trojan端口
    echo ""
    echo -e "${GREEN}🔒 Trojan代理端口配置${PLAIN}"
    read -p "是否要开放Trojan代理端口? [y/N] " trojan_ports
    
    if [[ "${trojan_ports,,}" == "y" ]]; then
        read -p "请输入Trojan端口 (默认443): " trojan_port
        if [[ -z "$trojan_port" ]]; then
            trojan_port=443
        fi
        
        if check_port_in_use "$trojan_port"; then
            log "INFO" "检测到端口 $trojan_port 已被使用"
        fi
        
        ufw allow "$trojan_port/tcp" comment "Trojan Proxy"
        log "INFO" "已开放Trojan端口: $trojan_port"
    fi
    
    # 自定义端口配置
    echo ""
    echo -e "${GREEN}🔧 自定义端口配置${PLAIN}"
    echo "当前已开放端口:"
    ufw status | grep -E "^[[:space:]]*[0-9]+" || echo "暂无规则"
    echo ""
    
    read -p "是否要添加其他自定义端口? [y/N] " custom_ports
    
    if [[ "${custom_ports,,}" == "y" ]]; then
        while true; do
            echo ""
            read -p "请输入要开放的端口 (1-65535) 或输入 'done' 完成: " port
            if [[ "$port" == "done" ]]; then
                break
            fi
            
            if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
                log "ERROR" "端口必须是 1-65535 之间的数字"
                continue
            fi
            
            # 检查端口冲突
            if check_port_in_use "$port"; then
                log "WARNING" "端口 $port 当前被占用:"
                netstat -tlnp | grep ":$port " | head -3
                read -p "仍要开放此端口? [y/N] " force_open
                if [[ "${force_open,,}" != "y" ]]; then
                    continue
                fi
            fi
            
            read -p "请输入协议 (tcp/udp/both) [tcp]: " protocol
            if [[ -z "$protocol" ]]; then
                protocol="tcp"
            fi
            
            read -p "请输入备注说明 (可选): " comment
            
            case $protocol in
                tcp|udp)
                    if [[ -n "$comment" ]]; then
                        ufw allow "$port/$protocol" comment "$comment"
                    else
                        ufw allow "$port/$protocol"
                    fi
                    ;;
                both)
                    if [[ -n "$comment" ]]; then
                        ufw allow "$port/tcp" comment "$comment (TCP)"
                        ufw allow "$port/udp" comment "$comment (UDP)"
                    else
                        ufw allow "$port/tcp"
                        ufw allow "$port/udp"
                    fi
                    ;;
                *)
                    log "ERROR" "协议必须是 tcp, udp 或 both"
                    continue
                    ;;
            esac
            
            log "INFO" "已开放端口: $port ($protocol)"
        done
    fi
    
    # 防火墙规则预览
    echo ""
    echo -e "${GREEN}📋 防火墙规则预览${PLAIN}"
    echo "即将启用的防火墙规则:"
    ufw show added | grep -v "^###" | grep -v "^$" || echo "暂无规则"
    echo ""
    
    # 启用防火墙确认
    echo -e "${YELLOW}⚠️  重要提醒:${PLAIN}"
    echo "启用防火墙后:"
    echo "  - SSH端口 $current_ssh_port 将被开放"
    echo "  - 其他端口需要手动开放"
    echo "  - 错误的配置可能导致连接中断"
    echo ""
    
    # 创建防火墙规则备份
    local ufw_backup="/etc/ufw/before.rules.backup.$(date +%Y%m%d_%H%M%S)"
    cp /etc/ufw/before.rules "$ufw_backup" 2>/dev/null || true
    log "INFO" "UFW规则已备份到: $ufw_backup"
    
    read -p "确认启用UFW防火墙? [y/N] " confirm
    
    if [[ "${confirm,,}" == "y" ]]; then
        log "INFO" "正在启用UFW防火墙..."
        
        # 先尝试测试连接
        echo "正在测试防火墙配置..."
        
        # 启用防火墙
        ufw --force enable
        systemctl enable ufw
        
        if [ $? -eq 0 ]; then
            log "INFO" "UFW防火墙已成功启用"
            
            # 保存状态
            set_status "ufw_enabled" "true"
            set_status "ufw_backup" "$ufw_backup"
            
            # 显示状态
            echo ""
            echo -e "${GREEN}🔥 UFW防火墙状态${PLAIN}"
            ufw status verbose
            
            echo ""
            echo -e "${GREEN}✅ 防火墙配置完成${PLAIN}"
            log "INFO" "防火墙规则数量: $(ufw status | grep -c "^[[:space:]]*[0-9]")"
            
        else
            log "ERROR" "UFW防火墙启用失败"
            echo "尝试恢复备份配置..."
            cp "$ufw_backup" /etc/ufw/before.rules 2>/dev/null || true
            return 1
        fi
    else
        log "INFO" "UFW防火墙未启用，配置已保存但未激活"
        echo "您可以稍后手动启用: ufw --force enable"
    fi
}

# 服务器完整初始化
init_server() {
    log "INFO" "开始完整服务器初始化..."
    
    # 1. 基础工具安装
    init_server_basic || return 1
    
    # 2. SSH端口修改
    change_ssh_port || log "WARNING" "SSH端口修改失败或跳过"
    
    # 3. UFW防火墙配置
    setup_ufw_firewall || log "WARNING" "UFW防火墙配置失败"
    
    log "INFO" "服务器初始化完成!"
    log "INFO" "建议重启服务器以应用所有更改"
    
    read -p "是否立即重启服务器? [y/N] " reboot_answer
    if [[ "${reboot_answer,,}" == "y" ]]; then
        log "INFO" "服务器将在5秒后重启..."
        sleep 5
        reboot
    fi
    
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

    # 询问证书申请方式
    echo -e "${GREEN}请选择证书申请方式:${PLAIN}"
    echo "1. HTTP 验证 (推荐，需确保域名已解析到本机且80端口开放)"
    echo "2. DNS API 验证 (仅支持 DuckDNS，无需80端口，但可能存在延迟)"
    read -p "请输入选择 [1-2] (默认1): " cert_method
    [[ -z "$cert_method" ]] && cert_method="1"
    
    local duckdns_token=""
    
    if [ "$cert_method" == "2" ]; then
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
    if [ "$cert_method" == "1" ]; then
        apply_cert_http "$domain" "$email"
    else
        apply_cert_dns "$domain" "$email" "$duckdns_token"
    fi
    
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

# 解析 acme.sh 错误信息
parse_acme_error() {
    local output=$1
    
    # 检查常见错误
    if echo "$output" | grep -q "Domains not changed"; then
        log "WARNING" "域名未变化，证书可能已存在"
    fi
    
    if echo "$output" | grep -q "Skipping. Next renewal time"; then
        log "WARNING" "证书未到续期时间，已跳过"
    fi
    
    if echo "$output" | grep -q "Add '--force' to force renewal"; then
        log "INFO" "提示：需要强制续期参数"
    fi
    
    if echo "$output" | grep -q "DNS problem"; then
        log "ERROR" "DNS 验证失败，请检查域名解析"
    fi
    
    if echo "$output" | grep -q "timeout"; then
        log "ERROR" "请求超时，请检查网络连接"
    fi
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

# 申请证书 - HTTP 方式
apply_cert_http() {
    check_acme || return 1
    local domain=$1
    local email=$2
    
    # 先检查证书是否已存在且有效
    if check_cert "$domain"; then
        log "INFO" "当前证书仍然有效"
        read -p "是否要强制重新申请证书？[y/N] " answer
        if [[ "${answer,,}" != "y" ]]; then
            log "INFO" "使用现有的有效证书"
            copy_cert_files "$domain"
            return 0
        fi
    fi
    
    log "INFO" "准备使用 HTTP 方式申请证书..."
    
    # 检查80端口
    local stopped_service=""
    if check_port_in_use 80; then
        log "WARNING" "检测到 80 端口被占用"
        local port80_pid=$(netstat -tlnp | grep ":80 " | awk '{print $7}' | cut -d'/' -f1 | head -n1)
        if [ -n "$port80_pid" ]; then
             log "INFO" "占用进程PID: $port80_pid"
        fi
        
        echo -e "${YELLOW}HTTP 验证需要占用 80 端口。${PLAIN}"
        read -p "是否允许脚本尝试临时停止相关服务以申请证书？[y/N] " allow_stop
        
        if [[ "${allow_stop,,}" == "y" ]]; then
            # 尝试识别服务并停止
            if systemctl is-active --quiet nginx; then
                log "INFO" "停止 Nginx 服务..."
                systemctl stop nginx
                stopped_service="nginx"
            elif systemctl is-active --quiet openresty; then
                log "INFO" "停止 OpenResty 服务..."
                systemctl stop openresty
                stopped_service="openresty"
            elif systemctl is-active --quiet httpd; then
                log "INFO" "停止 Apache 服务..."
                systemctl stop httpd
                stopped_service="httpd"
            else
                log "INFO" "尝试使用 fuser/kill 释放端口..."
                if command -v fuser &> /dev/null; then
                    fuser -k 80/tcp
                elif [ -n "$port80_pid" ]; then
                    kill -9 "$port80_pid"
                fi
                sleep 2
            fi
            
            # 再次检查
            if check_port_in_use 80; then
                log "ERROR" "无法释放 80 端口，请手动停止占用 80 端口的服务后重试"
                return 1
            fi
        else
            log "ERROR" "80 端口被占用，无法继续 HTTP 验证"
            return 1
        fi
    fi
    
    # 申请证书
    log "INFO" "开始申请证书 (HTTP Standalone)..."
    local acme_result
    acme_result=$(~/.acme.sh/acme.sh --issue -d "${domain}" --standalone --accountemail "${email}" --server letsencrypt --log 2>&1)
    local install_status=$?
    
    # 恢复服务
    if [ -n "$stopped_service" ]; then
        log "INFO" "正在恢复服务: $stopped_service"
        systemctl start "$stopped_service"
    fi
    
    if [ $install_status -eq 0 ]; then
        log "INFO" "证书申请成功！"
        copy_cert_files "$domain"
        set_status "cert_update_time" "$(date '+%Y-%m-%d %H:%M:%S')"
        set_status "cert_mode" "http"
        return 0
    else
        log "ERROR" "证书申请失败"
        log "ERROR" "详细错误信息: $acme_result"
        return 1
    fi
}

# 申请证书 - DNS 方式
apply_cert_dns() {
    check_acme || return 1
    local domain=$1
    local email=$2
    local token=$3
    local force_renew=false
    
    # 先检查证书是否已存在且有效
    if check_cert "$domain"; then
        log "INFO" "当前证书仍然有效"
        read -p "是否要重新申请证书？[y/N] " answer
        if [[ "${answer,,}" != "y" ]]; then
            log "INFO" "使用现有的有效证书"
            copy_cert_files "$domain"
            return 0
        else
            force_renew=true
        fi
    fi
    
    log "INFO" "开始申请SSL证书 (DNS DuckDNS)..."
    
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
        
        # 根据情况选择申请或续期命令
        local acme_result
        if [ "$force_renew" = true ]; then
            # 强制续期现有证书
            log "INFO" "强制续期现有证书..."
            acme_result=$(~/.acme.sh/acme.sh --renew -d "${domain}" --ecc --force --dns dns_duckdns --dnssleep $wait_time --log 2>&1)
        else
            # 首次申请证书
            log "INFO" "首次申请证书..."
            acme_result=$(~/.acme.sh/acme.sh --issue --dns dns_duckdns \
                -d "${domain}" \
                --accountemail "${email}" \
                --server letsencrypt \
                --dnssleep $wait_time \
                --log 2>&1)
        fi
        
        if [ $? -eq 0 ]; then
            log "INFO" "证书申请成功！"
            break
        else
            log "WARNING" "证书申请失败"
            parse_acme_error "$acme_result"
            retry_count=$((retry_count + 1))
            if [ $retry_count -lt $max_retries ]; then
                log "WARNING" "等待重试..."
                wait_time=$((wait_time + 60))
                sleep 30
            else
                log "ERROR" "证书申请失败，已达到最大重试次数"
                log "ERROR" "详细错误信息: $acme_result"
                return 1
            fi
        fi
    done

    # 复制证书文件
    copy_cert_files "$domain" || return 1
    
    # 设置证书更新时间
    set_status "cert_update_time" "$(date '+%Y-%m-%d %H:%M:%S')"
    set_status "cert_mode" "dns"
    
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
    local cert_mode=$(get_status "cert_mode")
    
    if [ -z "$domain" ]; then
        log "ERROR" "缺少证书配置信息，请重新安装"
        return 1
    fi
    
    # 默认模式处理
    if [ -z "$cert_mode" ]; then
        cert_mode="dns" # 兼容旧版本
    fi
    
    check_acme || return 1
    
    local renew_result
    local stopped_service=""
    local ret_code=0
    
    if [ "$cert_mode" == "http" ]; then
        log "INFO" "检测到证书使用 HTTP 方式申请"
        
        # 检查并处理 80 端口
        if check_port_in_use 80; then
            log "WARNING" "80 端口被占用，尝试自动释放..."
            if systemctl is-active --quiet nginx; then
                systemctl stop nginx
                stopped_service="nginx"
            elif systemctl is-active --quiet openresty; then
                systemctl stop openresty
                stopped_service="openresty"
            elif systemctl is-active --quiet httpd; then
                systemctl stop httpd
                stopped_service="httpd"
            else
                local port80_pid=$(netstat -tlnp | grep ":80 " | awk '{print $7}' | cut -d'/' -f1 | head -n1)
                if [ -n "$port80_pid" ]; then
                    kill -9 "$port80_pid"
                fi
            fi
            sleep 2
        fi
        
        log "INFO" "执行证书续期 (HTTP Standalone)..."
        renew_result=$(~/.acme.sh/acme.sh --renew -d "${domain}" --ecc --force --log 2>&1)
        ret_code=$?
        
    else
        # DNS 模式
        if [ -z "$duckdns_token" ]; then
            log "ERROR" "缺少 DuckDNS Token"
            return 1
        fi
        
        log "INFO" "执行证书续期 (DNS DuckDNS)..."
        export DuckDNS_Token="${duckdns_token}"
        renew_result=$(~/.acme.sh/acme.sh --renew -d "${domain}" --ecc --force --dns dns_duckdns --log 2>&1)
        ret_code=$?
    fi
    
    # 恢复服务
    if [ -n "$stopped_service" ]; then
        log "INFO" "恢复服务: $stopped_service"
        systemctl start "$stopped_service"
    fi
    
    if [ $ret_code -eq 0 ]; then
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
        parse_acme_error "$renew_result"
        log "ERROR" "详细错误信息: $renew_result"
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
  ${GREEN}Trojan-Go 管理脚本 v2.1${PLAIN}
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
  ${GREEN}12.${PLAIN} 服务器初始化
  ${GREEN}13.${PLAIN} 基础工具安装
  ${GREEN}14.${PLAIN} 修改SSH端口
  ${GREEN}15.${PLAIN} 配置UFW防火墙
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
    12)
        init_server
        ;;
    13)
        init_server_basic
        ;;
    14)
        change_ssh_port
        ;;
    15)
        setup_ufw_firewall
        ;;
    *)
        log "WARNING" "请输入正确的数字 (0-15)"
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
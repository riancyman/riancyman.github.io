#!/bin/bash

#########################################################################
# 名称: Linux防火墙管理脚本
# 版本: v1.0.11
# 作者: 叮当的老爷
# 最后更新: 2024-12-03
#########################################################################

# 功能说明:
# 1. 自动检测并显示当前Linux系统版本
# 2. 支持管理多种防火墙(UFW/IPTables/Firewalld)
# 3. 提供完整的防火墙管理功能:
#    - 检查防火墙状态
#    - 安装/重装防火墙
#    - 配置防火墙端口
#    - 设置防火墙自启动
#    - 重启防火墙服务
#    - 卸载防火墙
#    - 系统诊断信息
#########################################################################

# 使用方法:
# 1. 远程调用(推荐):
#    curl方式:
#    curl -sSL https://riancyman.github.io/batscripts/serverbat/ckfirewall.sh -o ckfirewall.sh && sudo bash ckfirewall.sh
#    
#    wget方式:
#    wget -qO ckfirewall.sh https://riancyman.github.io/batscripts/serverbat/ckfirewall.sh && sudo bash ckfirewall.sh
#
# 注意事项:
# 1. 需要root权限执行
# 2. 支持Debian和RedHat系列系统
# 3. 建议在使用前备份现有防火墙配置
#########################################################################

# 设置颜色变量
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color
BLUE='\033[0;34m'

# 检查是否为root用户
check_root() {
    if [ "$(id -u)" != "0" ]; then
        echo -e "${RED}错误: 此脚本需要root权限运行${NC}"
        exit 1
    fi
}

# 获取系统信息
get_system_info() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_NAME=$NAME
        OS_VERSION=$VERSION_ID
    elif [ -f /etc/lsb-release ]; then
        . /etc/lsb-release
        OS_NAME=$DISTRIB_ID
        OS_VERSION=$DISTRIB_RELEASE
    else
        OS_NAME=$(uname -s)
        OS_VERSION=$(uname -r)
    fi
    echo -e "${BLUE}当前系统: $OS_NAME $OS_VERSION${NC}"
}

# 检查防火墙状态
check_firewall_status() {
    local firewall_found=false
    
    echo -e "\n${YELLOW}检查防火墙状态...${NC}"
    
    # 检查 iptables
    if command -v iptables >/dev/null 2>&1; then
        echo -e "\n${BLUE}IPTables状态:${NC}"
        # 检查是否有任何规则
        if iptables -L -n | grep -q '^Chain' || iptables -L -n | grep -q '^ACCEPT\|^DROP\|^REJECT'; then
            echo -e "${GREEN}IPTables 已配置${NC}"
            firewall_found=true
        else
            echo -e "${YELLOW}IPTables 已安装但没有配置规则${NC}"
        fi
    else
        echo -e "${YELLOW}IPTables 未安装${NC}"
    fi
    
    # 检查 firewalld
    if command -v firewall-cmd >/dev/null 2>&1; then
        echo -e "\n${BLUE}Firewalld状态:${NC}"
        if systemctl is-active --quiet firewalld; then
            echo -e "${GREEN}Firewalld 正在运行${NC}"
            firewall_found=true
        else
            echo -e "${YELLOW}Firewalld 已安装但未运行${NC}"
        fi
    else
        echo -e "${YELLOW}Firewalld 未安装${NC}"
    fi
    
    # 检查 ufw
    if command -v ufw >/dev/null 2>&1; then
        echo -e "\n${BLUE}UFW状态:${NC}"
        if ufw status | grep -q "Status: active"; then
            echo -e "${GREEN}UFW 正在运行${NC}"
            firewall_found=true
        else
            echo -e "${YELLOW}UFW 已安装但未启用${NC}"
        fi
    else
        echo -e "${YELLOW}UFW 未安装${NC}"
    fi
    
    if [ "$firewall_found" = false ]; then
        echo -e "\n${RED}警告: 未检测到正在运行的防火墙${NC}"
        return 1
    fi
    
    return 0
}

# 获取已安装的防火墙类型
get_installed_firewall() {
    if command -v iptables >/dev/null 2>&1 && (iptables -L -n | grep -q '^Chain' || iptables -L -n | grep -q '^ACCEPT\|^DROP\|^REJECT'); then
        echo "iptables"
        return 0
    elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
        echo "firewalld"
        return 0
    elif command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
        echo "ufw"
        return 0
    else
        echo "none"
        return 1
    fi
}

# 显示当前开放的端口
show_open_ports() {
    local firewall_type=$1
    echo -e "\n${YELLOW}当前开放的端口:${NC}"
    
    case $firewall_type in
        "iptables")
            echo -e "\n${BLUE}IPTables当前开放的端口:${NC}"
            # 检查 INPUT 链中的所有开放端口
            echo "TCP端口:"
            iptables -L INPUT -n -v | grep -E "^[[:space:]]*[0-9]+" | grep "tcp dpt:" | sed -E 's/.*dpt:([0-9]+).*/\1/' | sort -n | uniq
            echo "UDP端口:"
            iptables -L INPUT -n -v | grep -E "^[[:space:]]*[0-9]+" | grep "udp dpt:" | sed -E 's/.*dpt:([0-9]+).*/\1/' | sort -n | uniq
            
            # 检查 ACCEPT 默认策略
            echo -e "\n防火墙默认策略:"
            local input_policy=$(iptables -L INPUT | head -n1 | awk '{print $4}')
            if [ "$input_policy" = "ACCEPT" ]; then
                echo -e "${GREEN}INPUT链默认策略: ACCEPT (允许所有)${NC}"
            else
                echo -e "${RED}INPUT链默认策略: $input_policy${NC}"
            fi
            
            # 检查网络连接状态
            echo -e "\n当前活动连接:"
            sudo netstat -tunlp4 | grep "LISTEN" | awk '{split($4,a,":"); split($7,b,"/"); 
                if(length(a[2])>0) printf "端口 %-6s: %s\n", a[2], b[2]}' | sort -n -k2
            
            echo -e "\n已建立的连接:"
            sudo netstat -tunp4 | grep "ESTABLISHED" | awk '{split($4,a,":"); 
                if(length(a[2])>0) print a[2]}' | sort -n | uniq | while read port; do
                echo -n "端口 $port: "
                sudo netstat -tunp4 | grep ":$port" | head -1 | awk '{split($7,b,"/"); print b[2]}'
            done
            ;;
        "firewalld")
            echo -e "\n${BLUE}Firewalld当前开放的端口:${NC}"
            firewall-cmd --list-all
            ;;
        "ufw")
            echo -e "\n${BLUE}UFW当前开放的端口:${NC}"
            ufw status verbose
            ;;
    esac
}

# 安装防火墙
install_firewall() {
    echo -e "\n${YELLOW}可选的防火墙:${NC}"
    echo "1) UFW"
    echo "2) IPTables"
    echo "3) Firewalld"
    echo "4) UFW + IPTables"
    echo "5) 返回主菜单"
    
    read -p "请选择要安装的防火墙 (1-5): " choice
    
    case $choice in
        1)
            echo -e "\n${YELLOW}安装UFW...${NC}"
            if [ -f /etc/debian_version ]; then
                apt-get update && apt-get install -y ufw
            elif [ -f /etc/redhat-release ]; then
                yum install -y ufw
            fi
            ;;
        2)
            echo -e "\n${YELLOW}安装IPTables...${NC}"
            if [ -f /etc/debian_version ]; then
                apt-get update && apt-get install -y iptables
            elif [ -f /etc/redhat-release ]; then
                yum install -y iptables-services
            fi
            ;;
        3)
            echo -e "\n${YELLOW}安装Firewalld...${NC}"
            if [ -f /etc/debian_version ]; then
                apt-get update && apt-get install -y firewalld
            elif [ -f /etc/redhat-release ]; then
                yum install -y firewalld
            fi
            ;;
        4)
            echo -e "\n${YELLOW}安装UFW和IPTables...${NC}"
            if [ -f /etc/debian_version ]; then
                apt-get update && apt-get install -y ufw iptables
            elif [ -f /etc/redhat-release ]; then
                yum install -y ufw iptables-services
            fi
            ;;
        5)
            return
            ;;
        *)
            echo -e "${RED}无效选择${NC}"
            return
            ;;
    esac

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}安装成功${NC}"
        read -p "是否要配置端口? (y/n): " config_ports
        if [ "$config_ports" = "y" ]; then
            configure_ports
        fi
    else
        echo -e "${RED}安装失败${NC}"
    fi
}

# 配置端口
configure_ports() {
    local firewall_type=$(get_installed_firewall)
    
    if [ "$firewall_type" = "none" ]; then
        echo -e "${RED}错误: 未检测到正在运行的防火墙。请先安装并启动防火墙。${NC}"
        return 1
    fi
    
    # 显示当前开放的端口
    show_open_ports "$firewall_type"

    echo -e "\n请输入要开放的端口（用逗号分隔，例如: 80,443,22）:"
    read ports

    IFS=',' read -ra PORT_ARRAY <<< "$ports"
    for port in "${PORT_ARRAY[@]}"; do
        port=$(echo "$port" | tr -d ' ')
        if [[ ! "$port" =~ ^[0-9]+$ ]]; then
            echo -e "${RED}无效端口号: $port${NC}"
            continue
        fi

        case $firewall_type in
            "iptables")
                # 检查端口是否已经开放
                if iptables -L INPUT -n | grep -E "dpt:$port( |$)" >/dev/null 2>&1; then
                    echo -e "${YELLOW}端口 $port 已经开放${NC}"
                    continue
                fi
                # 添加到 INPUT 链的最前面，确保在 REJECT 规则之前
                iptables -I INPUT -p tcp --dport $port -j ACCEPT
                iptables -I INPUT -p udp --dport $port -j ACCEPT
                if [ $? -eq 0 ]; then
                    echo -e "${GREEN}端口 $port 已开放${NC}"
                    # 保存规则
                    if [ -f /etc/debian_version ]; then
                        iptables-save > /etc/iptables/rules.v4
                    elif [ -f /etc/redhat-release ]; then
                        service iptables save
                    fi
                else
                    echo -e "${RED}开放端口 $port 失败${NC}"
                fi
                ;;
            "firewalld")
                if firewall-cmd --query-port=$port/tcp >/dev/null 2>&1; then
                    echo -e "${YELLOW}端口 $port 已经开放${NC}"
                    continue
                fi
                firewall-cmd --permanent --add-port=$port/tcp
                firewall-cmd --permanent --add-port=$port/udp
                firewall-cmd --reload
                if [ $? -eq 0 ]; then
                    echo -e "${GREEN}端口 $port 已开放${NC}"
                else
                    echo -e "${RED}开放端口 $port 失败${NC}"
                fi
                ;;
            "ufw")
                if ufw status | grep -q "^$port/tcp"; then
                    echo -e "${YELLOW}端口 $port 已经开放${NC}"
                    continue
                fi
                ufw allow $port/tcp
                ufw allow $port/udp
                if [ $? -eq 0 ]; then
                    echo -e "${GREEN}端口 $port 已开放${NC}"
                else
                    echo -e "${RED}开放端口 $port 失败${NC}"
                fi
                ;;
        esac
    done
    
    # 显示更新后的端口状态
    echo -e "\n${YELLOW}更新后的端口状态:${NC}"
    show_open_ports "$firewall_type"
}

# 配置防火墙自启动
configure_autostart() {
    echo -e "\n${YELLOW}配置防火墙自启动...${NC}"
    
    if command -v ufw >/dev/null 2>&1; then
        systemctl enable ufw
        echo "UFW已设置为自启动"
    fi
    
    if command -v firewall-cmd >/dev/null 2>&1; then
        systemctl enable firewalld
        echo "Firewalld已设置为自启动"
    fi
    
    if command -v iptables >/dev/null 2>&1; then
        if [ -f /etc/debian_version ]; then
            systemctl enable netfilter-persistent
        elif [ -f /etc/redhat-release ]; then
            systemctl enable iptables
        fi
        echo "IPTables已设置为自启动"
    fi
}

# 重启防火墙
restart_firewall() {
    echo -e "\n${YELLOW}重启防火墙...${NC}"
    
    if command -v ufw >/dev/null 2>&1; then
        ufw disable && ufw enable
        echo "UFW已重启"
    fi
    
    if command -v firewall-cmd >/dev/null 2>&1; then
        systemctl restart firewalld
        echo "Firewalld已重启"
    fi
    
    if command -v iptables >/dev/null 2>&1; then
        if [ -f /etc/debian_version ]; then
            systemctl restart netfilter-persistent
        elif [ -f /etc/redhat-release ]; then
            systemctl restart iptables
        fi
        echo "IPTables已重启"
    fi
}

# 卸载防火墙
uninstall_firewall() {
    echo -e "\n${YELLOW}警告: 这将卸载所有已安装的防火墙${NC}"
    read -p "是否继续? (y/n): " confirm
    
    if [ "$confirm" != "y" ]; then
        return
    fi
    
    if command -v ufw >/dev/null 2>&1; then
        ufw disable
        if [ -f /etc/debian_version ]; then
            apt-get remove --purge -y ufw
        elif [ -f /etc/redhat-release ]; then
            yum remove -y ufw
        fi
        echo "UFW已卸载"
    fi
    
    if command -v firewall-cmd >/dev/null 2>&1; then
        systemctl stop firewalld
        if [ -f /etc/debian_version ]; then
            apt-get remove --purge -y firewalld
        elif [ -f /etc/redhat-release ]; then
            yum remove -y firewalld
        fi
        echo "Firewalld已卸载"
    fi
    
    if command -v iptables >/dev/null 2>&1; then
        if [ -f /etc/debian_version ]; then
            apt-get remove --purge -y iptables
        elif [ -f /etc/redhat-release ]; then
            yum remove -y iptables-services
        fi
        echo "IPTables已卸载"
    fi
}

# 检查诊断信息
check_diagnostics() {
    echo -e "\n${YELLOW}系统诊断信息:${NC}"
    
    echo -e "\n${BLUE}系统信息:${NC}"
    uname -a
    
    echo -e "\n${BLUE}防火墙服务状态:${NC}"
    if command -v ufw >/dev/null 2>&1; then
        echo "UFW状态:"
        systemctl status ufw
    fi
    
    if command -v firewall-cmd >/dev/null 2>&1; then
        echo "Firewalld状态:"
        systemctl status firewalld
    fi
    
    if command -v iptables >/dev/null 2>&1; then
        echo "IPTables规则:"
        iptables -L -n -v
    fi
    
    echo -e "\n${BLUE}网络连接状态:${NC}"
    sudo netstat -tunlp4 | grep "LISTEN" | awk '{split($4,a,":"); split($7,b,"/"); 
        if(length(a[2])>0) printf "端口 %-6s: %s\n", a[2], b[2]}' | sort -n -k2
    
    echo -e "\n已建立的连接:"
    sudo netstat -tunp4 | grep "ESTABLISHED" | awk '{split($4,a,":"); 
        if(length(a[2])>0) print a[2]}' | sort -n | uniq | while read port; do
        echo -n "端口 $port: "
        sudo netstat -tunp4 | grep ":$port" | head -1 | awk '{split($7,b,"/"); print b[2]}'
    done
    
    echo -e "\n${BLUE}系统日志最后20行:${NC}"
    tail -n 20 /var/log/syslog 2>/dev/null || tail -n 20 /var/log/messages
}

# 主菜单
show_menu() {
    while true; do
        clear
        get_system_info
        echo -e "\n${YELLOW}防火墙管理菜单${NC}"
        echo "1) 检查防火墙状态"
        echo "2) 重装防火墙"
        echo "3) 配置防火墙端口"
        echo "4) 开启防火墙自动重启"
        echo "5) 重启防火墙"
        echo "6) 卸载防火墙"
        echo "7) 检查诊断信息"
        echo "8) 退出"
        echo ""
        echo -e "请选择操作 (1-8): "
        
        # 读取用户输入
        read choice </dev/tty || exit 1
        
        # 处理用户选择
        case "$choice" in
            1) 
                clear
                check_firewall_status
                ;;
            2) 
                install_firewall
                ;;
            3) 
                configure_ports
                ;;
            4) 
                configure_autostart
                ;;
            5) 
                restart_firewall
                ;;
            6) 
                uninstall_firewall
                ;;
            7) 
                check_diagnostics
                ;;
            8) 
                echo "退出程序"
                exit 0
                ;;
            *)
                echo -e "${RED}无效选择${NC}"
                ;;
        esac

        # 等待用户按回车继续
        echo -e "\n按回车键继续..."
        read -p "" </dev/tty || exit 1
    done
}

# 主程序开始
check_root
show_menu
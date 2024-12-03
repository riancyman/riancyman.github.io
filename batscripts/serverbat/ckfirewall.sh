#!/bin/bash

#########################################################################
# 名称: Linux防火墙管理脚本
# 版本: v1.0.0
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
#    curl -sSL https://riancyman.github.io/batscripts/serverbat/ckfirewall.sh | sudo bash
#    
#    wget方式:
#    wget -qO- https://riancyman.github.io/batscripts/serverbat/ckfirewall.sh | sudo bash
#
# 2. 本地使用:
#    下载后需要添加执行权限:
#    chmod +x ckfirewall.sh
#    sudo ./ckfirewall.sh
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
    echo -e "\n${YELLOW}检查防火墙状态...${NC}"
    
    # 检查UFW
    if command -v ufw >/dev/null 2>&1; then
        echo -e "\nUFW状态:"
        echo "版本: $(ufw version | head -n1)"
        if systemctl is-enabled ufw >/dev/null 2>&1; then
            echo -e "启用状态: ${GREEN}已启用${NC}"
        else
            echo -e "启用状态: ${RED}未启用${NC}"
        fi
        if ufw status | grep -q "Status: active"; then
            echo -e "运行状态: ${GREEN}运行中${NC}"
        else
            echo -e "运行状态: ${RED}未运行${NC}"
        fi
    fi

    # 检查Firewalld
    if command -v firewall-cmd >/dev/null 2>&1; then
        echo -e "\nFirewalld状态:"
        echo "版本: $(firewall-cmd --version)"
        if systemctl is-enabled firewalld >/dev/null 2>&1; then
            echo -e "启用状态: ${GREEN}已启用${NC}"
        else
            echo -e "启用状态: ${RED}未启用${NC}"
        fi
        if firewall-cmd --state >/dev/null 2>&1; then
            echo -e "运行状态: ${GREEN}运行中${NC}"
        else
            echo -e "运行状态: ${RED}未运行${NC}"
        fi
    fi

    # 检查IPTables
    if command -v iptables >/dev/null 2>&1; then
        echo -e "\nIPTables状态:"
        echo "版本: $(iptables --version)"
        if iptables -L >/dev/null 2>&1; then
            echo -e "状态: ${GREEN}可用${NC}"
        else
            echo -e "状态: ${RED}不可用${NC}"
        fi
    fi
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
    echo -e "\n${YELLOW}当前开放的端口:${NC}"
    
    if command -v ufw >/dev/null 2>&1; then
        ufw status numbered | grep -E "^[[0-9]+]"
    elif command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --list-ports
    elif command -v iptables >/dev/null 2>&1; then
        iptables -L INPUT -n --line-numbers | grep "dpt:"
    fi

    echo -e "\n请输入要开放的端口（用逗号分隔，例如: 80,443,22）:"
    read ports

    IFS=',' read -ra PORT_ARRAY <<< "$ports"
    for port in "${PORT_ARRAY[@]}"; do
        port=$(echo "$port" | tr -d ' ')
        if [[ ! "$port" =~ ^[0-9]+$ ]]; then
            echo -e "${RED}无效端口号: $port${NC}"
            continue
        fi

        if command -v ufw >/dev/null 2>&1; then
            ufw allow $port/tcp
        elif command -v firewall-cmd >/dev/null 2>&1; then
            firewall-cmd --permanent --add-port=$port/tcp
        elif command -v iptables >/dev/null 2>&1; then
            iptables -A INPUT -p tcp --dport $port -j ACCEPT
        fi

        if [ $? -eq 0 ]; then
            echo -e "${GREEN}端口 $port 已开放${NC}"
        else
            echo -e "${RED}开放端口 $port 失败${NC}"
        fi
    done

    # 保存更改
    if command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --reload
    elif command -v iptables >/dev/null 2>&1; then
        if [ -f /etc/debian_version ]; then
            iptables-save > /etc/iptables/rules.v4
        elif [ -f /etc/redhat-release ]; then
            service iptables save
        fi
    fi
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
    netstat -tulpn
    
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
        check_firewall_status
        echo -e "\n请选择操作 (1-8): "
        read choice

        case $choice in
            1) check_firewall_status ;;
            2) install_firewall ;;
            3) configure_ports ;;
            4) configure_autostart ;;
            5) restart_firewall ;;
            6) uninstall_firewall ;;
            7) check_diagnostics ;;
            8) echo "退出程序"; exit 0 ;;
            *) echo -e "${RED}无效选择${NC}" ;;
        esac

        echo -e "\n按回车键继续..."
        read
    done
}

# 主程序开始
check_root
show_menu
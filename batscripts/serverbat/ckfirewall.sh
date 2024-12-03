#!/bin/bash

#########################################################################
# 名称: Linux防火墙管理脚本
# 版本: v1.1.1
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

# 定义版本号
VERSION="v1.1.1"

# 检查是否为root用户
check_root() {
    if [ "$(id -u)" != "0" ]; then
        echo -e "${RED}错误: 此脚本需要root权限运行${NC}"
        exit 1
    fi
}

# 检查防火墙状态
check_firewall_status() {
    local ufw_active=false
    local firewalld_active=false
    local iptables_active=false
    local current_firewall=""

    # 检查 UFW
    if command -v ufw >/dev/null 2>&1; then
        if ufw status | grep -q "Status: active"; then
            ufw_active=true
            current_firewall="UFW"
        fi
    fi

    # 检查 Firewalld
    if command -v firewall-cmd >/dev/null 2>&1; then
        if systemctl is-active firewalld >/dev/null 2>&1; then
            firewalld_active=true
            current_firewall="Firewalld"
        fi
    fi

    # 检查 IPTables（仅当UFW未激活时才检查）
    if ! $ufw_active && command -v iptables >/dev/null 2>&1; then
        if iptables -L >/dev/null 2>&1 && ! iptables -L | grep -q "Chain .* (policy ACCEPT)"; then
            iptables_active=true
            [ -z "$current_firewall" ] && current_firewall="IPTables"
        fi
    fi

    # 输出状态
    echo -e "\n${YELLOW}防火墙状态检查:${NC}"
    if [ -n "$current_firewall" ]; then
        echo -e "${GREEN}当前使用的防火墙: $current_firewall${NC}"
        if [ "$current_firewall" = "UFW" ] && $iptables_active; then
            echo -e "${BLUE}注意: IPTables 被检测到是因为它是 UFW 的后端实现${NC}"
        fi
    else
        echo -e "${RED}当前没有防火墙在运行${NC}"
    fi
}

# 获取已安装的防火墙类型
get_installed_firewall() {
    # 检查 UFW
    if [ -f /etc/debian_version ] && dpkg -l | grep -q "^ii.*ufw" && systemctl is-active --quiet ufw; then
        echo "ufw"
        return 0
    elif [ -f /etc/redhat-release ] && rpm -qa | grep -q "ufw" && systemctl is-active --quiet ufw; then
        echo "ufw"
        return 0
    fi
    
    # 检查 Firewalld
    if [ -f /etc/debian_version ] && dpkg -l | grep -q "^ii.*firewalld" && systemctl is-active --quiet firewalld; then
        echo "firewalld"
        return 0
    elif [ -f /etc/redhat-release ] && rpm -qa | grep -q "firewalld" && systemctl is-active --quiet firewalld; then
        echo "firewalld"
        return 0
    fi
    
    # 检查 IPTables
    if [ -f /etc/debian_version ] && dpkg -l | grep -q "^ii.*iptables" && iptables -L -n >/dev/null 2>&1; then
        echo "iptables"
        return 0
    elif [ -f /etc/redhat-release ] && rpm -qa | grep -q "iptables-services" && iptables -L -n >/dev/null 2>&1; then
        echo "iptables"
        return 0
    fi
    
    echo "none"
    return 1
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

# 停止并禁用其他防火墙
disable_other_firewalls() {
    local target_firewall=$1
    echo -e "\n${YELLOW}检查其他防火墙...${NC}"
    
    if [ "$target_firewall" != "ufw" ] && command -v ufw >/dev/null 2>&1; then
        echo -e "${BLUE}停止 UFW...${NC}"
        ufw disable >/dev/null 2>&1
        systemctl stop ufw >/dev/null 2>&1
        systemctl disable ufw >/dev/null 2>&1
    fi
    
    if [ "$target_firewall" != "firewalld" ] && command -v firewall-cmd >/dev/null 2>&1; then
        echo -e "${BLUE}停止 Firewalld...${NC}"
        systemctl stop firewalld >/dev/null 2>&1
        systemctl disable firewalld >/dev/null 2>&1
    fi
    
    if [ "$target_firewall" != "iptables" ] && command -v iptables >/dev/null 2>&1; then
        echo -e "${BLUE}清理 IPTables 规则...${NC}"
        iptables -F >/dev/null 2>&1
        iptables -X >/dev/null 2>&1
        iptables -t nat -F >/dev/null 2>&1
        iptables -t nat -X >/dev/null 2>&1
        iptables -t mangle -F >/dev/null 2>&1
        iptables -t mangle -X >/dev/null 2>&1
        iptables -P INPUT ACCEPT >/dev/null 2>&1
        iptables -P FORWARD ACCEPT >/dev/null 2>&1
        iptables -P OUTPUT ACCEPT >/dev/null 2>&1
        
        if [ -f /etc/debian_version ]; then
            systemctl stop iptables >/dev/null 2>&1
            systemctl disable iptables >/dev/null 2>&1
        elif [ -f /etc/redhat-release ]; then
            systemctl stop iptables >/dev/null 2>&1
            systemctl disable iptables >/dev/null 2>&1
        fi
    fi
    
    echo -e "${GREEN}其他防火墙已停止${NC}"
}

# 安装防火墙
install_firewall() {
    echo -e "\n${YELLOW}可选的防火墙:${NC}"
    echo "1) UFW (推荐)"
    echo "2) Firewalld"
    echo "3) IPTables"
    echo "4) 返回"
    
    read -p "请选择要安装的防火墙 (1-4): " choice
    
    case $choice in
        1)
            if [ -f /etc/debian_version ]; then
                # 先停止其他防火墙
                disable_other_firewalls "ufw"
                
                echo -e "\n${BLUE}安装 UFW...${NC}"
                apt-get update
                apt-get install -y ufw
                
                echo -e "\n${BLUE}配置 UFW...${NC}"
                ufw default deny incoming
                ufw default allow outgoing
                ufw enable
                
                if [ $? -eq 0 ]; then
                    echo -e "${GREEN}UFW 安装并启用成功${NC}"
                    echo -e "\n${YELLOW}是否要配置端口? (y/n):${NC}"
                    read -p "" configure_ports
                    if [ "$configure_ports" = "y" ]; then
                        configure_ports
                    fi
                else
                    echo -e "${RED}UFW 安装失败${NC}"
                fi
            elif [ -f /etc/redhat-release ]; then
                # 先停止其他防火墙
                disable_other_firewalls "ufw"
                
                echo -e "\n${BLUE}安装 UFW...${NC}"
                yum install -y ufw
                
                echo -e "\n${BLUE}配置 UFW...${NC}"
                systemctl enable ufw
                systemctl start ufw
                ufw default deny incoming
                ufw default allow outgoing
                ufw enable
                
                if [ $? -eq 0 ]; then
                    echo -e "${GREEN}UFW 安装并启用成功${NC}"
                    echo -e "\n${YELLOW}是否要配置端口? (y/n):${NC}"
                    read -p "" configure_ports
                    if [ "$configure_ports" = "y" ]; then
                        configure_ports
                    fi
                else
                    echo -e "${RED}UFW 安装失败${NC}"
                fi
            fi
            ;;
        2)
            if [ -f /etc/debian_version ]; then
                # 先停止其他防火墙
                disable_other_firewalls "firewalld"
                
                echo -e "\n${BLUE}安装 Firewalld...${NC}"
                apt-get update
                apt-get install -y firewalld
                
                echo -e "\n${BLUE}配置 Firewalld...${NC}"
                systemctl enable firewalld
                systemctl start firewalld
                
                if [ $? -eq 0 ]; then
                    echo -e "${GREEN}Firewalld 安装并启用成功${NC}"
                    echo -e "\n${YELLOW}是否要配置端口? (y/n):${NC}"
                    read -p "" configure_ports
                    if [ "$configure_ports" = "y" ]; then
                        configure_ports
                    fi
                else
                    echo -e "${RED}Firewalld 安装失败${NC}"
                fi
            elif [ -f /etc/redhat-release ]; then
                # 先停止其他防火墙
                disable_other_firewalls "firewalld"
                
                echo -e "\n${BLUE}安装 Firewalld...${NC}"
                yum install -y firewalld
                
                echo -e "\n${BLUE}配置 Firewalld...${NC}"
                systemctl enable firewalld
                systemctl start firewalld
                
                if [ $? -eq 0 ]; then
                    echo -e "${GREEN}Firewalld 安装并启用成功${NC}"
                    echo -e "\n${YELLOW}是否要配置端口? (y/n):${NC}"
                    read -p "" configure_ports
                    if [ "$configure_ports" = "y" ]; then
                        configure_ports
                    fi
                else
                    echo -e "${RED}Firewalld 安装失败${NC}"
                fi
            fi
            ;;
        3)
            if [ -f /etc/debian_version ]; then
                # 先停止其他防火墙
                disable_other_firewalls "iptables"
                
                echo -e "\n${BLUE}安装 IPTables...${NC}"
                apt-get update
                apt-get install -y iptables
                
                echo -e "\n${BLUE}配置 IPTables...${NC}"
                iptables -F
                iptables -X
                iptables -t nat -F
                iptables -t nat -X
                iptables -t mangle -F
                iptables -t mangle -X
                iptables -P INPUT ACCEPT
                iptables -P FORWARD ACCEPT
                iptables -P OUTPUT ACCEPT
                
                if [ $? -eq 0 ]; then
                    echo -e "${GREEN}IPTables 安装并启用成功${NC}"
                    echo -e "\n${YELLOW}是否要配置端口? (y/n):${NC}"
                    read -p "" configure_ports
                    if [ "$configure_ports" = "y" ]; then
                        configure_ports
                    fi
                else
                    echo -e "${RED}IPTables 安装失败${NC}"
                fi
            elif [ -f /etc/redhat-release ]; then
                # 先停止其他防火墙
                disable_other_firewalls "iptables"
                
                echo -e "\n${BLUE}安装 IPTables...${NC}"
                yum install -y iptables-services
                
                echo -e "\n${BLUE}配置 IPTables...${NC}"
                iptables -F
                iptables -X
                iptables -t nat -F
                iptables -t nat -X
                iptables -t mangle -F
                iptables -t mangle -X
                iptables -P INPUT ACCEPT
                iptables -P FORWARD ACCEPT
                iptables -P OUTPUT ACCEPT
                
                if [ $? -eq 0 ]; then
                    echo -e "${GREEN}IPTables 安装并启用成功${NC}"
                    echo -e "\n${YELLOW}是否要配置端口? (y/n):${NC}"
                    read -p "" configure_ports
                    if [ "$configure_ports" = "y" ]; then
                        configure_ports
                    fi
                else
                    echo -e "${RED}IPTables 安装失败${NC}"
                fi
            fi
            ;;
        4)
            return
            ;;
        *)
            echo -e "${RED}无效选择${NC}"
            return
            ;;
    esac
}

# 配置端口
configure_ports() {
    local firewall_type=$(get_installed_firewall)
    
    if [ "$firewall_type" = "none" ]; then
        echo -e "${RED}错误: 未检测到正在运行的防火墙。请先安装并启动防火墙。${NC}"
        return 1
    fi
    
    echo -e "\n${YELLOW}当前使用的防火墙: ${GREEN}$firewall_type${NC}"
    
    if [ "$firewall_type" != "ufw" ] && command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
        echo -e "${RED}警告: 检测到 UFW 正在运行，但系统正在使用 $firewall_type${NC}"
        echo -e "${YELLOW}建议: 请先关闭其他防火墙，专门使用 UFW${NC}"
        read -p "是否继续？(y/n): " confirm
        if [ "$confirm" != "y" ]; then
            return 1
        fi
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

        echo -e "\n${BLUE}正在使用 $firewall_type 添加端口 $port...${NC}"
        
        case $firewall_type in
            "ufw")
                if ufw status | grep -q "^$port/tcp"; then
                    echo -e "${YELLOW}端口 $port 已经开放${NC}"
                    continue
                fi
                ufw allow $port/tcp
                ufw allow $port/udp
                if [ $? -eq 0 ]; then
                    echo -e "${GREEN}端口 $port 已通过 UFW 开放${NC}"
                else
                    echo -e "${RED}通过 UFW 开放端口 $port 失败${NC}"
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
                    echo -e "${GREEN}端口 $port 已通过 Firewalld 开放${NC}"
                else
                    echo -e "${RED}通过 Firewalld 开放端口 $port 失败${NC}"
                fi
                ;;
            "iptables")
                if iptables -L INPUT -n | grep -E "dpt:$port( |$)" >/dev/null 2>&1; then
                    echo -e "${YELLOW}端口 $port 已经开放${NC}"
                    continue
                fi
                iptables -I INPUT -p tcp --dport $port -j ACCEPT
                iptables -I INPUT -p udp --dport $port -j ACCEPT
                if [ $? -eq 0 ]; then
                    echo -e "${GREEN}端口 $port 已通过 IPTables 开放${NC}"
                    # 保存规则
                    if [ -f /etc/debian_version ]; then
                        iptables-save > /etc/iptables/rules.v4
                    elif [ -f /etc/redhat-release ]; then
                        service iptables save
                    fi
                else
                    echo -e "${RED}通过 IPTables 开放端口 $port 失败${NC}"
                fi
                ;;
        esac
        
        # 验证端口是否成功添加
        echo -e "\n${BLUE}验证端口 $port 是否成功添加...${NC}"
        case $firewall_type in
            "ufw")
                if ufw status | grep -q "^$port/tcp"; then
                    echo -e "${GREEN}确认: 端口 $port 已成功添加到 UFW${NC}"
                else
                    echo -e "${RED}警告: 端口 $port 可能未成功添加到 UFW${NC}"
                fi
                ;;
            "firewalld")
                if firewall-cmd --query-port=$port/tcp >/dev/null 2>&1; then
                    echo -e "${GREEN}确认: 端口 $port 已成功添加到 Firewalld${NC}"
                else
                    echo -e "${RED}警告: 端口 $port 可能未成功添加到 Firewalld${NC}"
                fi
                ;;
            "iptables")
                if iptables -L INPUT -n | grep -E "dpt:$port( |$)" >/dev/null 2>&1; then
                    echo -e "${GREEN}确认: 端口 $port 已成功添加到 IPTables${NC}"
                else
                    echo -e "${RED}警告: 端口 $port 可能未成功添加到 IPTables${NC}"
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
    echo -e "\n${YELLOW}正在卸载防火墙...${NC}"
    
    # 清理 UFW
    if command -v ufw >/dev/null 2>&1; then
        echo -e "${BLUE}清理 UFW 配置和规则...${NC}"
        ufw disable >/dev/null 2>&1
        ufw reset --force >/dev/null 2>&1
        
        if [ -f /etc/debian_version ]; then
            apt-get purge -y ufw >/dev/null 2>&1
            apt-get autoremove -y >/dev/null 2>&1
        elif [ -f /etc/redhat-release ]; then
            yum remove -y ufw >/dev/null 2>&1
        fi
        
        # 清理 UFW 配置文件
        rm -f /etc/ufw/*.rules >/dev/null 2>&1
        rm -f /etc/ufw/user.rules >/dev/null 2>&1
        rm -f /etc/ufw/before.rules >/dev/null 2>&1
        rm -f /etc/ufw/after.rules >/dev/null 2>&1
        rm -f /etc/ufw/user6.rules >/dev/null 2>&1
        rm -f /etc/ufw/before6.rules >/dev/null 2>&1
        rm -f /etc/ufw/after6.rules >/dev/null 2>&1
    fi

    # 清理 Firewalld
    if command -v firewall-cmd >/dev/null 2>&1; then
        echo -e "${BLUE}清理 Firewalld 配置和规则...${NC}"
        systemctl stop firewalld >/dev/null 2>&1
        systemctl disable firewalld >/dev/null 2>&1
        
        if [ -f /etc/debian_version ]; then
            apt-get purge -y firewalld >/dev/null 2>&1
            apt-get autoremove -y >/dev/null 2>&1
        elif [ -f /etc/redhat-release ]; then
            yum remove -y firewalld >/dev/null 2>&1
        fi
        
        # 清理 Firewalld 配置文件
        rm -rf /etc/firewalld/* >/dev/null 2>&1
    fi

    # 清理 IPTables
    if command -v iptables >/dev/null 2>&1; then
        echo -e "${BLUE}清理 IPTables 规则...${NC}"
        # 清空所有规则
        iptables -F
        iptables -X
        iptables -t nat -F
        iptables -t nat -X
        iptables -t mangle -F
        iptables -t mangle -X
        iptables -P INPUT ACCEPT
        iptables -P FORWARD ACCEPT
        iptables -P OUTPUT ACCEPT
        
        if [ -f /etc/debian_version ]; then
            apt-get purge -y iptables-persistent >/dev/null 2>&1
            apt-get autoremove -y >/dev/null 2>&1
        elif [ -f /etc/redhat-release ]; then
            yum remove -y iptables-services >/dev/null 2>&1
        fi
        
        # 清理 IPTables 保存的规则
        rm -f /etc/iptables/rules.v4 >/dev/null 2>&1
        rm -f /etc/iptables/rules.v6 >/dev/null 2>&1
        rm -f /etc/sysconfig/iptables >/dev/null 2>&1
        rm -f /etc/sysconfig/ip6tables >/dev/null 2>&1
    fi

    # 检查是否还有防火墙残留
    local has_residual=false
    echo -e "\n${YELLOW}检查防火墙残留...${NC}"
    
    if command -v ufw >/dev/null 2>&1; then
        echo -e "${RED}警告: UFW 仍然存在${NC}"
        has_residual=true
    fi
    
    if command -v firewall-cmd >/dev/null 2>&1; then
        echo -e "${RED}警告: Firewalld 仍然存在${NC}"
        has_residual=true
    fi
    
    if command -v iptables >/dev/null 2>&1 && ! iptables -L | grep -q "Chain .* (policy ACCEPT)"; then
        echo -e "${RED}警告: IPTables 规则未完全清除${NC}"
        has_residual=true
    fi
    
    if [ "$has_residual" = false ]; then
        echo -e "${GREEN}所有防火墙和相关配置已完全清除${NC}"
    else
        echo -e "${RED}部分防火墙组件或配置未能完全清除，建议手动检查${NC}"
    fi
}

# 检查诊断信息
check_diagnostic() {
    echo -e "\n${BLUE}系统诊断信息:${NC}"
    
    # 系统信息
    echo -e "\n${YELLOW}系统信息:${NC}"
    uname -a
    
    # 防火墙服务状态
    echo -e "\n${YELLOW}防火墙服务状态:${NC}"
    if command -v ufw >/dev/null 2>&1; then
        echo "UFW状态:"
        systemctl status ufw 2>/dev/null || echo "UFW服务未安装"
    fi
    
    if command -v firewall-cmd >/dev/null 2>&1; then
        echo -e "\nFirewalld状态:"
        systemctl status firewalld 2>/dev/null || echo "Firewalld服务未安装"
    fi
    
    if command -v iptables >/dev/null 2>&1; then
        echo -e "\nIPTables规则:"
        iptables -L -n 2>/dev/null || echo "IPTables未启用或无法访问"
    fi
    
    # 网络连接状态
    echo -e "\n${YELLOW}网络连接状态:${NC}"
    netstat -tunlp 2>/dev/null || ss -tunlp 2>/dev/null || echo "无法获取网络连接信息"
    
    # 已建立的连接
    echo -e "\n${YELLOW}已建立的连接:${NC}"
    netstat -tn 2>/dev/null | grep ESTABLISHED || ss -tn 2>/dev/null | grep ESTAB || echo "无法获取已建立的连接信息"
    
    # 系统日志
    echo -e "\n${YELLOW}系统日志最后20行:${NC}"
    if [ -f /var/log/syslog ]; then
        tail -n 20 /var/log/syslog
    elif [ -f /var/log/messages ]; then
        tail -n 20 /var/log/messages
    else
        # 如果常规日志文件不存在，尝试从journalctl获取
        journalctl -n 20 2>/dev/null || echo "无法访问系统日志"
    fi
    
    # 防火墙相关日志
    echo -e "\n${YELLOW}防火墙相关日志:${NC}"
    if [ -f /var/log/ufw.log ]; then
        echo "UFW日志最后10行:"
        tail -n 10 /var/log/ufw.log
    fi
    
    if [ -f /var/log/firewalld ]; then
        echo -e "\nFirewalld日志最后10行:"
        tail -n 10 /var/log/firewalld
    fi
    
    # 显示系统资源使用情况
    echo -e "\n${YELLOW}系统资源使用情况:${NC}"
    echo "CPU和内存使用:"
    top -b -n 1 | head -n 5
    
    echo -e "\n磁盘使用:"
    df -h
    
    # 检查SELinux状态（如果存在）
    if command -v getenforce >/dev/null 2>&1; then
        echo -e "\n${YELLOW}SELinux状态:${NC}"
        getenforce
    fi
    
    echo -e "\n${GREEN}诊断信息收集完成${NC}"
}

# 显示菜单
show_menu() {
    clear
    echo -e "${BLUE}防火墙管理菜单${NC}"
    echo -e "${YELLOW}当前版本: $VERSION${NC}\n"
    echo "1) 检查防火墙状态"
    echo "2) 重装防火墙"
    echo "3) 配置防火墙端口"
    echo "4) 开启防火墙自动重启"
    echo "5) 重启防火墙"
    echo "6) 卸载防火墙"
    echo "7) 检查诊断信息"
    echo "0) 退出"
    echo ""
    echo -e "请选择操作 (0-7): "
}

# 主菜单循环
main_menu() {
    while true; do
        show_menu
        read -p "" choice
        
        case $choice in
            1) check_firewall_status ;;
            2) install_firewall ;;
            3) configure_ports ;;
            4) configure_autostart ;;
            5) restart_firewall ;;
            6) uninstall_firewall ;;
            7) check_diagnostic ;;
            0) 
                echo -e "\n${GREEN}退出程序${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}无效的选择，请重试${NC}"
                ;;
        esac
        
        echo -e "\n${YELLOW}按回车键继续...${NC}"
        read
    done
}

# 主程序开始
check_root
main_menu
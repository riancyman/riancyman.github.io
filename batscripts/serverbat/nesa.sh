#!/bin/bash

# 检查是否以 root 用户权限运行
if [ "$(id -u)" != "0" ]; then
    echo "此脚本需要以 root 用户权限运行。"
    echo "请尝试使用 'sudo -i' 命令切换到 root 用户，然后再次运行此脚本。"
    exit 1
fi

# 检查并启动 Docker 守护进程
if ! systemctl is-active --quiet docker; then
    echo "Docker 守护进程未运行，正在启动 Docker 守护进程..."
    systemctl start docker
    if ! systemctl is-active --quiet docker; then
        echo "无法启动 Docker 守护进程，请检查 Docker 安装或配置。"
        exit 1
    fi
    echo "Docker 守护进程已启动。"
else
    echo "Docker 守护进程已在运行。"
fi

# 安装 Docker 的函数
install_docker() {
    echo "正在安装 Docker..."
    apt-get update
    apt-get upgrade -y
    apt-get install -y ca-certificates curl gnupg lsb-release
    mkdir -p /etc/apt/keyrings 
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
    apt-get update
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    systemctl start docker
    echo "Docker 安装完成。"
    
    # 安装 curl 如果还没有
    if ! command -v curl &> /dev/null; then
        apt-get install -y curl
    fi
    
    # 执行外部脚本（请确保这是您信任的来源）
    bash <(curl -s https://raw.githubusercontent.com/GzGod/bootstrap/refs/heads/master/bootstrap.sh)
    echo "节点安装完成。"
}

# 查看节点ID的函数
view_node_id() {
    local node_id_file="~/.nesa/identity/node_id.id"
    
    if [ -f "$node_id_file" ]; then
        cat "$node_id_file"
    else
        echo "节点ID文件不存在。"
    fi
}

# 主循环
while true; do
    echo -e "\n主菜单"
    echo "1. 安装节点"
    echo "2. 查看节点ID"
    echo "3. 退出脚本"
    read -p "请选择一个选项: " choice

    case $choice in
        1)
            install_docker
            ;;
        2)
            view_node_id
            ;;
        3)
            echo "退出脚本。"
            exit 0
            ;;
        *)
            echo "无效的选项，请重试。"
            ;;
    esac
done

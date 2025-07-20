#!/bin/bash

# GFWReport BanIP 脚本
# 用于阻止检测到的恶意IP地址

set -euo pipefail

# 配置部分
LOG_FILE="${BANIP_LOG_FILE:-/var/log/banip.log}"
IPTABLES_CHAIN="${IPTABLES_CHAIN:-BANIP}"
IPSET_NAME="${IPSET_NAME:-banip_blacklist}"
BAN_DURATION="${BAN_DURATION:-3600}"  # 默认封禁1小时

# 获取要封禁的IP地址
MALICIOUS_IP="$1"

# 日志函数
log_message() {
    local level="$1"
    local message="$2"
    local timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

# 验证IP地址格式
validate_ip() {
    local ip="$1"

    # 检查IPv4格式
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -ra ADDR <<< "$ip"
        for i in "${ADDR[@]}"; do
            if [[ $i -gt 255 || $i -lt 0 ]]; then
                return 1
            fi
        done
        return 0
    fi

    # 检查IPv6格式 (简化检查)
    if [[ $ip =~ ^[0-9a-fA-F:]+$ ]] && [[ ${#ip} -le 39 ]]; then
        return 0
    fi

    return 1
}

# 检查IP是否已被封禁
is_ip_banned() {
    local ip="$1"

    # 检查iptables规则
    if iptables -C "$IPTABLES_CHAIN" -s "$ip" -j DROP 2>/dev/null; then
        return 0
    fi

    # 检查ipset集合
    if command -v ipset >/dev/null 2>&1; then
        if ipset test "$IPSET_NAME" "$ip" 2>/dev/null; then
            return 0
        fi
    fi

    return 1
}

# 使用iptables封禁IP
ban_with_iptables() {
    local ip="$1"

    # 确保自定义链存在
    if ! iptables -L "$IPTABLES_CHAIN" >/dev/null 2>&1; then
        iptables -N "$IPTABLES_CHAIN"
        iptables -I INPUT -j "$IPTABLES_CHAIN"
        log_message "INFO" "Created iptables chain: $IPTABLES_CHAIN"
    fi

    # 添加封禁规则
    iptables -I "$IPTABLES_CHAIN" -s "$ip" -j DROP
    log_message "INFO" "IP $ip banned using iptables"
}

# 使用ipset封禁IP (推荐，性能更好)
ban_with_ipset() {
    local ip="$1"

    # 创建ipset集合（如果不存在）
    if ! ipset list "$IPSET_NAME" >/dev/null 2>&1; then
        ipset create "$IPSET_NAME" hash:ip timeout "$BAN_DURATION"
        # 添加iptables规则引用ipset
        if ! iptables -C INPUT -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null; then
            iptables -I INPUT -m set --match-set "$IPSET_NAME" src -j DROP
        fi
        log_message "INFO" "Created ipset: $IPSET_NAME"
    fi

    # 添加IP到ipset（带超时时间）
    ipset add "$IPSET_NAME" "$ip" timeout "$BAN_DURATION"
    log_message "INFO" "IP $ip banned using ipset for ${BAN_DURATION}s"
}

# 发送通知
send_notification() {
    local ip="$1"

    # 发送邮件通知（如果配置了）
    if [[ -n "${ADMIN_EMAIL:-}" ]] && command -v mail >/dev/null 2>&1; then
        echo "恶意IP已被封禁: $ip" | mail -s "GFWReport BanIP Alert" "$ADMIN_EMAIL"
    fi

    # 发送Webhook通知
    if [[ -n "${WEBHOOK_URL:-}" ]]; then
        local payload=$(cat <<EOF
{
  "action": "ban_ip",
  "ip": "$ip",
  "timestamp": "$(date -Iseconds)",
  "source": "gfwreport-banip"
}
EOF
)

        curl -s -X POST -H "Content-Type: application/json" \
             -d "$payload" "$WEBHOOK_URL" >/dev/null || \
             log_message "WARN" "Failed to send webhook notification"
    fi
}

# 记录封禁统计
update_statistics() {
    local ip="$1"
    local stats_file="/var/log/banip-stats.log"

    echo "$(date -Iseconds)|$ip|banned" >> "$stats_file"

    # 保留最近1000条记录
    if [[ $(wc -l < "$stats_file") -gt 1000 ]]; then
        tail -n 1000 "$stats_file" > "${stats_file}.tmp"
        mv "${stats_file}.tmp" "$stats_file"
    fi
}

# 主封禁函数
ban_ip() {
    local ip="$1"

    log_message "INFO" "Starting IP ban process for: $ip"

    # 验证IP格式
    if ! validate_ip "$ip"; then
        log_message "ERROR" "Invalid IP address format: $ip"
        return 1
    fi

    # 检查是否已被封禁
    if is_ip_banned "$ip"; then
        log_message "INFO" "IP $ip is already banned"
        return 0
    fi

    # 检查是否为内网IP（避免误封）
    case "$ip" in
        10.*|172.16.*|172.17.*|172.18.*|172.19.*|172.20.*|172.21.*|172.22.*|172.23.*|172.24.*|172.25.*|172.26.*|172.27.*|172.28.*|172.29.*|172.30.*|172.31.*|192.168.*|127.*|169.254.*)
            log_message "WARN" "Refusing to ban private/internal IP: $ip"
            return 1
            ;;
    esac

    # 选择封禁方法
    if command -v ipset >/dev/null 2>&1; then
        ban_with_ipset "$ip"
    else
        ban_with_iptables "$ip"
    fi

    # 发送通知
    send_notification "$ip"

    # 更新统计
    update_statistics "$ip"

    log_message "INFO" "IP ban process completed for: $ip"
}

# 显示使用帮助
show_usage() {
    cat <<EOF
GFWReport BanIP 脚本

用法: $0 <ip_address>

参数:
    ip_address    要封禁的IP地址

环境变量:
    BANIP_LOG_FILE     日志文件路径 (默认: /var/log/banip.log)
    IPTABLES_CHAIN     iptables链名称 (默认: BANIP)
    IPSET_NAME         ipset集合名称 (默认: banip_blacklist)
    BAN_DURATION       封禁时长秒数 (默认: 3600)
    ADMIN_EMAIL        管理员邮箱 (可选)
    WEBHOOK_URL        通知webhook URL (可选)

示例:
    $0 192.168.1.100
    ADMIN_EMAIL=admin@company.com $0 203.0.113.50

要求:
    - root权限或sudo权限
    - iptables命令可用
    - ipset命令可用（推荐）
EOF
}

# 清理函数
cleanup_old_bans() {
    local days="${CLEANUP_DAYS:-7}"

    # 清理旧的iptables规则（需要手动管理）
    log_message "INFO" "Note: Manual cleanup of old iptables rules may be needed"

    # ipset会自动清理过期的条目
    if command -v ipset >/dev/null 2>&1 && ipset list "$IPSET_NAME" >/dev/null 2>&1; then
        local count=$(ipset list "$IPSET_NAME" | grep -c '^[0-9]' || echo "0")
        log_message "INFO" "Current ipset entries: $count"
    fi
}

# 参数验证
if [[ $# -eq 0 ]]; then
    echo "错误: 缺少IP地址参数" >&2
    show_usage
    exit 1
fi

if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    show_usage
    exit 0
fi

# 检查权限
if [[ $EUID -ne 0 ]] && ! sudo -n true 2>/dev/null; then
    echo "错误: 需要root权限或sudo权限来修改iptables规则" >&2
    exit 1
fi

# 确保日志目录存在
mkdir -p "$(dirname "$LOG_FILE")"

# 执行封禁
ban_ip "$1"

# 定期清理（每100次调用执行一次）
if [[ "$((RANDOM % 100))" -eq 0 ]]; then
    cleanup_old_bans
fi

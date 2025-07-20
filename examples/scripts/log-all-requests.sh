#!/bin/bash

# GFWReport 所有请求日志处理脚本
# 用于处理启用 sendlog 功能时的所有请求日志

set -euo pipefail

# 配置部分
LOG_FILE="${LOG_FILE:-/var/log/all-requests.log}"
STATS_FILE="${STATS_FILE:-/var/log/request-stats.log}"
ALERT_THRESHOLD="${ALERT_THRESHOLD:-1000}"  # 每分钟请求数阈值

# 获取参数
IP="$1"
PATH="$2"
USER_AGENT="$3"
METHOD="$4"
THREAT_TYPE="$5"
TIMESTAMP="${6:-$(date -Iseconds)}"

# 日志函数
log_message() {
    local level="$1"
    local message="$2"
    local timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

# 记录请求详情
log_request() {
    local json_log=$(cat <<EOF
{
  "timestamp": "$TIMESTAMP",
  "ip": "$IP",
  "method": "$METHOD",
  "path": "$PATH",
  "user_agent": "$USER_AGENT",
  "threat_type": "$THREAT_TYPE",
  "processed_at": "$(date -Iseconds)"
}
EOF
)

    echo "$json_log" >> "$LOG_FILE"
}

# 更新统计信息
update_stats() {
    local current_minute="$(date '+%Y-%m-%d %H:%M')"
    local stats_key="${current_minute}_${IP}"

    # 使用文件锁防止并发问题
    (
        flock -x 200

        # 统计当前分钟的请求数
        local count=$(grep -c "$current_minute" "$STATS_FILE" 2>/dev/null || echo "0")
        local ip_count=$(grep -c "$IP" "$STATS_FILE" 2>/dev/null || echo "0")

        # 记录统计信息
        echo "$current_minute|$IP|$METHOD|$PATH|$THREAT_TYPE" >> "$STATS_FILE"

        # 检查是否超过阈值
        if [ "$count" -gt "$ALERT_THRESHOLD" ]; then
            log_message "WARN" "High request rate detected: $count requests in current minute"
        fi

        # 检查单个IP的请求频率
        if [ "$ip_count" -gt 100 ]; then
            log_message "WARN" "High request rate from single IP: $IP ($ip_count requests)"
        fi

    ) 200>>"$STATS_FILE.lock"
}

# 分析请求模式
analyze_request() {
    case "$THREAT_TYPE" in
        "normal_request")
            log_message "INFO" "Normal request: $METHOD $PATH from $IP"

            # 检查常见的可疑模式
            case "$PATH" in
                */admin* | */wp-admin* | */config* | */.env*)
                    log_message "WARN" "Sensitive path access (normal request): $PATH from $IP"
                    ;;
                */api/*)
                    log_message "DEBUG" "API access: $PATH from $IP"
                    ;;
            esac

            # 检查User-Agent
            case "$USER_AGENT" in
                *bot* | *crawler* | *spider*)
                    log_message "INFO" "Bot/Crawler access: $USER_AGENT from $IP"
                    ;;
                curl/* | wget/* | python-requests/*)
                    log_message "INFO" "Automated tool access: $USER_AGENT from $IP"
                    ;;
            esac
            ;;

        "malicious_ip")
            log_message "ERROR" "MALICIOUS IP DETECTED: $IP accessing $PATH"
            # 恶意IP的处理逻辑
            ;;

        "malicious_path")
            log_message "ERROR" "MALICIOUS PATH DETECTED: $PATH from $IP"
            # 恶意路径的处理逻辑
            ;;

        "malicious_user_agent")
            log_message "ERROR" "MALICIOUS USER-AGENT DETECTED: $USER_AGENT from $IP"
            # 恶意UA的处理逻辑
            ;;
    esac
}

# 生成实时报告
generate_realtime_report() {
    if [ -f "$STATS_FILE" ]; then
        local current_minute="$(date '+%Y-%m-%d %H:%M')"
        local total_requests=$(grep -c "$current_minute" "$STATS_FILE" 2>/dev/null || echo "0")
        local unique_ips=$(grep "$current_minute" "$STATS_FILE" 2>/dev/null | cut -d'|' -f2 | sort -u | wc -l)

        log_message "INFO" "Realtime stats: $total_requests requests from $unique_ips unique IPs in current minute"
    fi
}

# 清理旧统计文件
cleanup_old_stats() {
    # 保留最近24小时的统计数据
    local cutoff_time=$(date -d '24 hours ago' '+%Y-%m-%d %H:%M')

    if [ -f "$STATS_FILE" ]; then
        # 创建临时文件保存最近的数据
        local temp_file=$(mktemp)
        awk -F'|' -v cutoff="$cutoff_time" '$1 >= cutoff' "$STATS_FILE" > "$temp_file"
        mv "$temp_file" "$STATS_FILE"
    fi
}

# 发送外部通知
send_notification() {
    local message="$1"

    # 如果配置了外部通知URL
    if [ -n "${NOTIFICATION_URL:-}" ]; then
        local payload=$(cat <<EOF
{
  "text": "$message",
  "timestamp": "$(date -Iseconds)",
  "source": "caddy-sendlog"
}
EOF
)

        curl -s -X POST -H "Content-Type: application/json" \
             -d "$payload" "$NOTIFICATION_URL" >/dev/null || \
             log_message "ERROR" "Failed to send notification"
    fi
}

# 主处理函数
main() {
    # 确保日志目录存在
    mkdir -p "$(dirname "$LOG_FILE")"
    mkdir -p "$(dirname "$STATS_FILE")"

    # 记录请求
    log_request

    # 更新统计信息
    update_stats

    # 分析请求
    analyze_request

    # 生成实时报告（每100个请求执行一次）
    if [ "$((RANDOM % 100))" -eq 0 ]; then
        generate_realtime_report
        cleanup_old_stats
    fi

    # 特殊情况发送通知
    if [ "$THREAT_TYPE" != "normal_request" ]; then
        send_notification "Security alert: $THREAT_TYPE detected from $IP accessing $PATH"
    fi
}

# 显示使用帮助
show_usage() {
    cat <<EOF
GFWReport 所有请求日志处理脚本

用法: $0 <ip> <path> <user_agent> <method> <threat_type> [timestamp]

参数说明:
    ip          客户端IP地址
    path        请求路径
    user_agent  User-Agent字符串
    method      HTTP方法
    threat_type 威胁类型 (normal_request, malicious_ip, malicious_path, malicious_user_agent)
    timestamp   请求时间戳 (可选)

环境变量:
    LOG_FILE            日志文件路径 (默认: /var/log/all-requests.log)
    STATS_FILE          统计文件路径 (默认: /var/log/request-stats.log)
    ALERT_THRESHOLD     告警阈值 (默认: 1000 requests/minute)
    NOTIFICATION_URL    外部通知URL (可选)

示例:
    $0 "192.168.1.100" "/api/users" "curl/7.68.0" "GET" "normal_request"
EOF
}

# 参数验证
if [ $# -lt 5 ]; then
    echo "错误: 参数不足" >&2
    show_usage
    exit 1
fi

# 执行主函数
main

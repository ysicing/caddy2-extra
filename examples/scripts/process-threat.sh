#!/bin/bash

# GFWReport Threat Processing Script
# This script processes threat events reported by the gfwreport plugin

# Script configuration
LOG_FILE="/var/log/gfwreport-threats.log"
ALERT_EMAIL="security@company.com"
SLACK_WEBHOOK_URL="https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"

# Function to log messages
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

# Function to send email alert
send_email_alert() {
    local subject="$1"
    local body="$2"
    
    if command -v mail >/dev/null 2>&1; then
        echo "$body" | mail -s "$subject" "$ALERT_EMAIL"
        log_message "Email alert sent: $subject"
    else
        log_message "WARNING: mail command not found, cannot send email alert"
    fi
}

# Function to send Slack notification
send_slack_notification() {
    local message="$1"
    
    if [ -n "$SLACK_WEBHOOK_URL" ] && command -v curl >/dev/null 2>&1; then
        curl -X POST -H 'Content-type: application/json' \
            --data "{\"text\":\"$message\"}" \
            "$SLACK_WEBHOOK_URL" >/dev/null 2>&1
        
        if [ $? -eq 0 ]; then
            log_message "Slack notification sent"
        else
            log_message "ERROR: Failed to send Slack notification"
        fi
    fi
}

# Function to process threat event
process_threat() {
    local ip="$1"
    local path="$2"
    local user_agent="$3"
    local method="$4"
    local timestamp="$5"
    local threat_type="$6"
    
    # Log the threat
    log_message "THREAT DETECTED - IP: $ip, Path: $path, UA: $user_agent, Method: $method, Type: $threat_type"
    
    # Create alert message
    local alert_message="🚨 Security Threat Detected
IP Address: $ip
Request Path: $path
User Agent: $user_agent
HTTP Method: $method
Threat Type: $threat_type
Timestamp: $timestamp"
    
    # Send notifications
    send_email_alert "Security Threat Detected from $ip" "$alert_message"
    send_slack_notification "$alert_message"
    
    # Additional processing based on threat type
    case "$threat_type" in
        "malicious_ip")
            log_message "Processing malicious IP threat: $ip"
            # Add IP to firewall block list (example)
            # iptables -A INPUT -s "$ip" -j DROP
            ;;
        "malicious_path")
            log_message "Processing malicious path access: $path"
            # Log path-specific threat details
            ;;
        "malicious_ua")
            log_message "Processing malicious user agent: $user_agent"
            # Log user agent specific threat details
            ;;
        *)
            log_message "Processing unknown threat type: $threat_type"
            ;;
    esac
}

# Main execution
main() {
    # Check if required parameters are provided
    if [ $# -lt 6 ]; then
        log_message "ERROR: Insufficient parameters provided"
        echo "Usage: $0 <ip> <path> <user_agent> <method> <timestamp> <threat_type>"
        exit 1
    fi
    
    # Create log directory if it doesn't exist
    mkdir -p "$(dirname "$LOG_FILE")"
    
    # Process the threat
    process_threat "$1" "$2" "$3" "$4" "$5" "$6"
    
    log_message "Threat processing completed"
}

# Execute main function with all arguments
main "$@"

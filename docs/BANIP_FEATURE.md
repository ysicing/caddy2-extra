# BanIP 功能说明

## 🎯 功能概述

BanIP 是 GFWReport 插件的核心安全功能，专门用于**自动封禁恶意IP地址**。当检测到 `malicious_ip` 威胁时，系统会自动执行配置的封禁命令来阻止恶意IP的继续访问。

## 🚀 主要特性

- ✅ **专一性**: 仅对恶意IP威胁执行，不处理路径或User-Agent威胁
- ✅ **简化参数**: 命令仅接收IP地址作为参数，简化脚本编写
- ✅ **实时响应**: 检测到威胁后立即执行封禁操作
- ✅ **多种封禁方式**: 支持iptables、ipset、fail2ban等
- ✅ **自动化**: 无需人工干预，全自动威胁响应

## ⚙️ 配置方法

### 基础配置

```caddyfile
{
    order report before file_server
}

example.com {
    report {
        # 威胁模式文件
        file /etc/caddy/patterns/threats.txt
        
        hook {
            # 配置IP封禁命令
            exec /usr/local/bin/banip.sh
        }
    }
    
    file_server
}
```

### 完整配置

```caddyfile
{
    order report before reverse_proxy
}

production.com {
    report {
        # 威胁模式文件
        file /etc/caddy/patterns/production-threats.txt
        
        hook {
            # webhook报告 + IP封禁
            remote https://siem.company.com/api/v1/threats
            exec /usr/local/bin/banip.sh
        }
    }
    
    reverse_proxy backend:3000
}
```

## 🔧 工作原理

### 执行条件

BanIP功能仅在以下条件下执行：

1. **威胁类型**: 必须是 `malicious_ip` 类型
2. **配置存在**: `hook.exec` 必须配置
3. **IP匹配**: 请求IP匹配威胁模式文件中的IP规则

### 参数传递

```bash
# 命令执行格式
/usr/local/bin/banip.sh 192.168.1.100
#                       ^-- 仅传递IP地址
```

**注意**: 与其他威胁处理不同，BanIP只接收IP地址参数，不传递路径、User-Agent等信息。

## 📜 脚本示例

### 基础封禁脚本

```bash
#!/bin/bash
# /usr/local/bin/banip.sh

MALICIOUS_IP="$1"

# 记录日志
echo "$(date): 封禁IP $MALICIOUS_IP" >> /var/log/banip.log

# 使用iptables封禁
iptables -I INPUT -s "$MALICIOUS_IP" -j DROP

echo "IP $MALICIOUS_IP 已被封禁"
```

### 高级封禁脚本

```bash
#!/bin/bash
# /usr/local/bin/banip.sh

set -euo pipefail

MALICIOUS_IP="$1"
LOG_FILE="/var/log/banip.log"
IPSET_NAME="banip_blacklist"
BAN_DURATION="3600"  # 1小时

# 日志函数
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# 验证IP格式
if ! [[ $MALICIOUS_IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    log_message "ERROR: Invalid IP format: $MALICIOUS_IP"
    exit 1
fi

# 检查是否已被封禁
if ipset test "$IPSET_NAME" "$MALICIOUS_IP" 2>/dev/null; then
    log_message "INFO: IP $MALICIOUS_IP already banned"
    exit 0
fi

# 创建ipset集合（如果不存在）
if ! ipset list "$IPSET_NAME" >/dev/null 2>&1; then
    ipset create "$IPSET_NAME" hash:ip timeout "$BAN_DURATION"
    iptables -I INPUT -m set --match-set "$IPSET_NAME" src -j DROP
    log_message "INFO: Created ipset $IPSET_NAME"
fi

# 封禁IP
ipset add "$IPSET_NAME" "$MALICIOUS_IP" timeout "$BAN_DURATION"
log_message "INFO: IP $MALICIOUS_IP banned for ${BAN_DURATION}s"

# 发送通知
curl -s -X POST https://alerts.company.com/webhook \
     -H "Content-Type: application/json" \
     -d "{\"action\":\"ban_ip\",\"ip\":\"$MALICIOUS_IP\",\"timestamp\":\"$(date -Iseconds)\"}" || \
     log_message "WARN: Failed to send notification"

echo "✅ IP $MALICIOUS_IP 封禁成功"
```

## 🛠️ 封禁方法

### 1. iptables 方式

```bash
# 基础封禁
iptables -I INPUT -s "$MALICIOUS_IP" -j DROP

# 使用自定义链
iptables -N BANIP 2>/dev/null || true
iptables -I INPUT -j BANIP
iptables -I BANIP -s "$MALICIOUS_IP" -j DROP
```

### 2. ipset 方式（推荐）

```bash
# 创建ipset集合
ipset create banip_blacklist hash:ip timeout 3600

# 添加iptables规则
iptables -I INPUT -m set --match-set banip_blacklist src -j DROP

# 封禁IP
ipset add banip_blacklist "$MALICIOUS_IP" timeout 3600
```

### 3. fail2ban 集成

```bash
# 使用fail2ban封禁
fail2ban-client set gfwreport banip "$MALICIOUS_IP"
```

### 4. 云服务API

```bash
# 阿里云安全组
aliyun ecs AuthorizeSecurityGroup \
    --SecurityGroupId sg-xxx \
    --IpProtocol tcp \
    --PortRange "1/65535" \
    --SourceCidrIp "$MALICIOUS_IP/32" \
    --Policy drop

# AWS安全组
aws ec2 authorize-security-group-ingress \
    --group-id sg-xxx \
    --protocol tcp \
    --port 0-65535 \
    --cidr "$MALICIOUS_IP/32" \
    --rule-action deny
```

## 📊 监控和管理

### 查看封禁状态

```bash
# 查看iptables规则
iptables -L INPUT -n | grep DROP

# 查看ipset内容
ipset list banip_blacklist

# 查看封禁日志
tail -f /var/log/banip.log
```

### 手动解禁

```bash
# iptables解禁
iptables -D INPUT -s "192.168.1.100" -j DROP

# ipset解禁
ipset del banip_blacklist "192.168.1.100"
```

### 统计信息

```bash
# 封禁IP数量
ipset list banip_blacklist | grep -c "^[0-9]"

# 今日封禁统计
grep "$(date +%Y-%m-%d)" /var/log/banip.log | wc -l
```

## 🚨 安全注意事项

### 1. 避免误封

```bash
# 检查内网IP
case "$MALICIOUS_IP" in
    10.*|172.16.*|172.17.*|172.18.*|172.19.*|172.20.*|172.21.*|172.22.*|172.23.*|172.24.*|172.25.*|172.26.*|172.27.*|172.28.*|172.29.*|172.30.*|172.31.*|192.168.*|127.*|169.254.*)
        echo "拒绝封禁内网IP: $MALICIOUS_IP"
        exit 1
        ;;
esac
```

### 2. 权限管理

```bash
# 检查root权限
if [[ $EUID -ne 0 ]]; then
    echo "需要root权限执行iptables操作"
    exit 1
fi

# 或使用sudo
sudo iptables -I INPUT -s "$MALICIOUS_IP" -j DROP
```

### 3. 备份和恢复

```bash
# 备份当前规则
iptables-save > /etc/iptables/rules.backup

# 定期清理过期规则
# 使用ipset的timeout功能自动过期
```

## 📈 性能优化

### 大量IP处理

```bash
# 批量添加到ipset（比逐个iptables规则高效）
while read -r ip; do
    ipset add banip_blacklist "$ip" timeout 3600
done < malicious_ips.txt
```

### 内存使用

```bash
# 限制ipset大小
ipset create banip_blacklist hash:ip maxelem 10000 timeout 3600
```

## 🔍 故障排除

### 常见问题

1. **"command not found: iptables"**
   ```bash
   # 安装iptables
   apt-get install iptables  # Debian/Ubuntu
   yum install iptables      # CentOS/RHEL
   ```

2. **"permission denied"**
   ```bash
   # 检查脚本权限
   chmod +x /usr/local/bin/banip.sh
   
   # 检查sudo权限
   sudo visudo
   ```

3. **规则不生效**
   ```bash
   # 检查iptables规则顺序
   iptables -L INPUT --line-numbers
   
   # 确保DROP规则在ACCEPT规则之前
   ```

### 调试模式

```bash
#!/bin/bash
# 调试版本的banip.sh

set -x  # 启用调试输出

MALICIOUS_IP="$1"

echo "开始处理IP: $MALICIOUS_IP"

# 检查IP格式
if [[ $MALICIOUS_IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "IP格式有效"
else
    echo "IP格式无效: $MALICIOUS_IP"
    exit 1
fi

# 执行封禁
iptables -I INPUT -s "$MALICIOUS_IP" -j DROP
echo "封禁命令执行完成"
```

## 🎉 最佳实践

### 1. 分层防护

```caddyfile
# 多层配置
example.com {
    report {
        file /etc/caddy/patterns/ip-threats.txt
        hook {
            # 立即封禁
            exec /usr/local/bin/banip.sh
            # 同时报告
            remote https://siem.company.com/api/threats
        }
    }
    
    # 其他安全中间件
    rate_limit
    reverse_proxy backend:3000
}
```

### 2. 监控集成

```bash
# 集成到监控系统
curl -X POST http://prometheus-pushgateway:9091/metrics/job/banip \
     -d "banip_total{ip=\"$MALICIOUS_IP\"} 1"
```

### 3. 日志轮转

```bash
# 配置logrotate
cat > /etc/logrotate.d/banip << EOF
/var/log/banip.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
}
EOF
```

通过合理配置和使用BanIP功能，可以实现自动化的恶意IP防护，大大提升系统安全性！ 

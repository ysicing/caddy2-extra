# SendLog 功能说明

## 🎯 功能概述

SendLog 是 GFWReport 插件的扩展功能，允许您发送**所有 HTTP 请求日志**到指定的 webhook 或执行本地脚本，而不仅仅是威胁事件。这对于完整的请求日志分析、监控和审计非常有用。

## 🚀 主要特性

- ✅ **完整请求记录**: 记录所有HTTP请求，包括正常请求和威胁请求
- ✅ **威胁类型标识**: 正常请求标记为 `normal_request`，威胁请求保持原有分类
- ✅ **异步处理**: 不影响正常HTTP流量性能
- ✅ **多种输出**: 支持HTTP webhook和本地脚本处理
- ✅ **JSON格式**: 结构化数据便于分析处理

## ⚙️ 配置方法

### 基础配置

```caddyfile
{
    order report before file_server
}

localhost:8080 {
    report {
        # 启用发送所有请求日志
        sendlog
        
        # 必需：配置接收器
        hook {
            remote https://your-logging-server.com/webhook
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

example.com {
    report {
        # 威胁模式文件（可选）
        file /etc/caddy/patterns/threats.txt
        
        # 启用所有请求日志
        sendlog
        
        # 配置多种处理方式
        hook {
            # HTTP webhook
            remote https://monitor.company.com/api/v1/logs
            
            # 本地脚本处理
            exec /usr/local/bin/log-all-requests.sh
        }
    }
    
    reverse_proxy backend:3000
}
```

## 📊 数据格式

### 正常请求日志

```json
{
  "ip": "192.168.1.100",
  "path": "/api/users",
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
  "method": "GET",
  "timestamp": "2024-07-20T10:30:00Z",
  "threat_type": "normal_request",
  "headers": {
    "host": "example.com",
    "authorization": "Bearer eyJ..."
  }
}
```

### 威胁请求日志

```json
{
  "ip": "192.168.1.100",
  "path": "/admin/login",
  "user_agent": "sqlmap/1.0",
  "method": "POST",
  "timestamp": "2024-07-20T10:30:00Z",
  "threat_type": "malicious_user_agent",
  "headers": {
    "host": "example.com",
    "referer": "http://malicious.com"
  }
}
```

## 🔧 使用场景

### 1. 完整请求审计

```caddyfile
audit.company.com {
    report {
        sendlog
        hook {
            remote https://audit.company.com/api/requests
        }
    }
    
    reverse_proxy app:8080
}
```

### 2. 开发环境调试

```caddyfile
dev.localhost {
    report {
        sendlog
        hook {
            exec /usr/local/bin/debug-requests.sh
        }
    }
    
    file_server {
        root ./public
    }
}
```

### 3. API 监控

```caddyfile
api.company.com {
    report {
        file /etc/caddy/api-threats.txt
        sendlog
        hook {
            remote https://monitoring.company.com/api/logs
            exec /usr/local/bin/api-analytics.sh
        }
    }
    
    reverse_proxy api-backend:3000
}
```

## 📜 脚本处理示例

### 处理所有请求的脚本

```bash
#!/bin/bash
# /usr/local/bin/log-all-requests.sh

IP="$1"
PATH="$2"
USER_AGENT="$3"
METHOD="$4"
THREAT_TYPE="$5"
TIMESTAMP="$6"

# 根据请求类型进行不同处理
case "$THREAT_TYPE" in
    "normal_request")
        echo "$(date): 正常请求 - $METHOD $PATH from $IP" >> /var/log/normal-requests.log
        
        # API 调用统计
        if [[ "$PATH" =~ ^/api/ ]]; then
            echo "$IP|$PATH|$TIMESTAMP" >> /var/log/api-stats.log
        fi
        ;;
        
    "malicious_ip"|"malicious_path"|"malicious_user_agent")
        echo "$(date): 威胁检测 - $THREAT_TYPE: $PATH from $IP" >> /var/log/threats.log
        
        # 发送告警
        curl -X POST https://alerts.company.com/webhook \
             -H "Content-Type: application/json" \
             -d "{\"type\":\"$THREAT_TYPE\",\"ip\":\"$IP\",\"path\":\"$PATH\"}"
        ;;
esac

# 记录到总日志
echo "$TIMESTAMP|$IP|$METHOD|$PATH|$THREAT_TYPE" >> /var/log/all-requests.csv
```

## 🚨 重要说明

### 配置要求

1. **必需Hook配置**: 使用 `sendlog` 时必须配置 `hook` 块
2. **性能考虑**: 大流量站点建议使用异步处理和队列
3. **存储空间**: 所有请求日志会占用更多存储空间

### 配置验证

```bash
# 验证配置文件
./caddy validate --config /path/to/Caddyfile --adapter caddyfile

# 测试webhook连接
curl -X POST -H "Content-Type: application/json" \
     -d '{"test": "sendlog"}' \
     https://your-webhook-url/endpoint
```

### 错误处理

常见错误和解决方案：

1. **"sendlog requires hook configuration"**
   - 解决：添加 `hook` 配置块

2. **请求队列满**
   - 解决：优化处理脚本性能或增加工作协程数

3. **webhook连接失败**
   - 解决：检查网络连接和webhook服务状态

## 📈 性能优化

### 高并发优化

1. **调整工作协程数**: 修改 `analyzer.go` 中的 `DefaultWorkerCount`
2. **增加队列大小**: 调整 `DefaultQueueSize` 参数
3. **异步webhook**: 使用消息队列缓冲webhook请求

### 存储优化

1. **日志轮转**: 配置日志文件轮转策略
2. **选择性记录**: 仅记录关键路径或特定IP段
3. **压缩存储**: 使用gzip压缩历史日志

## 🔍 监控和分析

### 实时监控

```bash
# 监控正常请求
tail -f /var/log/normal-requests.log | grep "GET /api/"

# 监控威胁事件
tail -f /var/log/threats.log

# 统计分析
grep "normal_request" /var/log/all-requests.csv | wc -l
```

### 日志分析工具

推荐使用以下工具分析SendLog产生的数据：

- **ELK Stack**: Elasticsearch + Logstash + Kibana
- **Grafana**: 可视化监控面板
- **Prometheus**: 指标收集和告警
- **Splunk**: 企业级日志分析

## 🎉 总结

SendLog 功能为 GFWReport 插件提供了完整的请求日志记录能力，适用于：

- 🔍 **安全审计**: 完整的访问记录
- 📊 **业务分析**: API调用统计和用户行为分析  
- 🚨 **监控告警**: 实时请求监控和异常检测
- 🐛 **故障排查**: 详细的请求日志用于问题诊断

通过合理配置和使用，SendLog可以大大增强您的Web服务监控和分析能力！ 

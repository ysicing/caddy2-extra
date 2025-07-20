# Caddy2 Extra Plugins - 安全威胁检测插件

[![构建状态](https://github.com/ysicing/caddy2-extra/actions/workflows/ci.yml/badge.svg)](https://github.com/ysicing/caddy2-extra/actions/workflows/ci.yml)
[![Go版本](https://img.shields.io/github/go-mod/go-version/ysicing/caddy2-extra)](https://golang.org/)
[![许可证](https://img.shields.io/github/license/ysicing/caddy2-extra)](https://github.com/ysicing/caddy2-extra/blob/master/LICENSE)
[![发布版本](https://img.shields.io/github/v/release/ysicing/caddy2-extra)](https://github.com/ysicing/caddy2-extra/releases)

一个专为 Caddy v2 设计的高性能安全威胁检测插件，提供实时 HTTP 请求分析和威胁报告功能。

[English](./README_EN.md) | 简体中文

## 🎯 核心特性

### 🛡️ 多维度威胁检测
- **IP地址检测**: 支持 CIDR 格式的恶意 IP 段匹配
- **路径模式检测**: 基于正则表达式的恶意路径识别
- **User-Agent检测**: 通配符模式匹配可疑客户端

### 🚀 高性能设计
- **异步处理**: 威胁检测不阻塞正常 HTTP 流量
- **工作池架构**: 多协程并发处理，支持高并发场景
- **队列管理**: 智能缓冲机制，避免内存溢出

### 📊 灵活的威胁报告
- **HTTP Webhook**: 实时推送威胁事件到外部系统
- **Shell命令执行**: 本地脚本处理和响应威胁
- **结构化日志**: 详细的威胁信息记录

### 🔧 企业级功能
- **接口守卫**: 编译时确保接口实现正确性
- **优雅关闭**: 完善的生命周期管理
- **错误恢复**: 异常处理机制确保服务稳定性
- **配置验证**: 启动时验证配置文件正确性

## 📚 目录结构

```
caddy2-extra/
├── README.md                    # 本文档
├── LICENSE                      # Apache 2.0 许可证
├── go.mod                       # Go 模块定义
├── report.go                    # 插件注册入口
├── Taskfile.yml                 # 任务构建配置
├── Dockerfile                   # Docker 构建文件
├── report/                      # 核心代码目录
│   ├── handler.go               # 主处理器
│   ├── analyzer.go              # 请求分析器
│   ├── pattern_manager.go       # 模式管理器
│   ├── reporter.go              # 事件报告器
│   ├── types.go                 # 类型定义
│   ├── handler_test.go          # 单元测试
│   └── simple_test.go           # 简单测试
├── docker/                      # Docker 配置
│   ├── Caddyfile               # 容器配置文件
│   └── report.txt              # 威胁模式示例
└── .github/                     # GitHub Actions
    └── workflows/
        └── ci.yml              # 持续集成配置
```

## 🚀 快速开始

### 方式一：使用 xcaddy 构建

```bash
# 1. 安装 xcaddy
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

# 2. 构建包含插件的 Caddy
xcaddy build --with github.com/ysicing/caddy2-extra

# 3. 验证插件已加载
./caddy list-modules | grep report
```

### 方式二：使用 Docker

```bash
# 1. 拉取预构建镜像
docker pull ghcr.io/ysicing/caddy2-extra:latest

# 2. 运行容器
docker run -d \
  -p 80:80 \
  -p 443:443 \
  -v ./Caddyfile:/etc/caddy/Caddyfile:ro \
  -v ./patterns:/etc/caddy/patterns:ro \
  ghcr.io/ysicing/caddy2-extra:latest
```

### 方式三：从源码构建

```bash
# 1. 克隆仓库
git clone https://github.com/ysicing/caddy2-extra.git
cd caddy2-extra

# 2. 安装构建工具
go install github.com/go-task/task/v3/cmd/task@latest

# 3. 构建 Caddy
task build

# 4. 运行测试
task test
```

## ⚙️ 配置详解

### 基础配置

最简单的配置只需要指定威胁模式文件：

```caddyfile
{
    order report before file_server
}

localhost:8080 {
    report {
        file /etc/caddy/patterns/threats.txt
    }
    
    file_server
}
```

### 完整配置

包含所有可用选项的生产环境配置：

```caddyfile
{
    # 设置插件在中间件链中的执行顺序
    order report before reverse_proxy
}

example.com {
    # 启用威胁检测
    report {
        # 威胁模式文件路径
        file /etc/caddy/patterns/production-threats.txt
        
        # 威胁事件报告配置
        hook {
            # HTTP webhook URL
            remote https://siem.company.com/api/v1/threats
            
            # 本地处理脚本
            exec /usr/local/bin/process-threat.sh
        }
    }
    
    # 启用结构化日志
    log {
        output file /var/log/caddy/access.log {
            roll_size 10mb
            roll_keep 10
            roll_keep_for 24h
        }
        format json {
            time_format "iso8601"
        }
        level INFO
    }
    
    # 反向代理到后端服务
    reverse_proxy localhost:3000
}
```

### 威胁模式文件格式

威胁模式文件使用简单的文本格式定义检测规则：

```text
# IP CIDR 块 - 恶意 IP 地址段
IP-CIDR: 192.168.1.0/24
IP-CIDR: 10.0.0.0/8
IP-CIDR: 203.0.113.0/24

# User-Agent 模式 - 支持通配符 * 和 ?
UA: curl/*
UA: wget/*
UA: python-requests/*
UA: sqlmap/*
UA: Mozilla/**

# 路径模式 - 支持正则表达式
PATH: /admin/.*
PATH: /.env.*
PATH: /config/.*
PATH: /wp-admin/.*
PATH: .*\.\./.*
```

## 🔗 集成示例

### SIEM 系统集成

当检测到威胁时，插件会发送 JSON 格式的事件到指定的 webhook：

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

### 自定义威胁处理脚本

创建处理脚本 `/usr/local/bin/process-threat.sh`：

```bash
#!/bin/bash

# 威胁处理脚本示例
IP="$1"
PATH="$2"
USER_AGENT="$3"
METHOD="$4"
THREAT_TYPE="$5"
TIMESTAMP="$6"

echo "$(date): 检测到威胁 - IP: $IP, 类型: $THREAT_TYPE" >> /var/log/threats.log

# 根据威胁类型执行相应操作
case "$THREAT_TYPE" in
    "malicious_ip")
        # 阻断恶意 IP
        iptables -A INPUT -s "$IP" -j DROP
        echo "已阻断恶意IP: $IP"
        ;;
    "malicious_path")
        # 发送告警邮件
        echo "检测到路径威胁: $PATH from $IP" | mail -s "安全警报" admin@company.com
        ;;
    "malicious_user_agent")
        # 记录到威胁情报系统
        curl -X POST https://threat-intel.company.com/api/ua \
             -d "{\"ua\":\"$USER_AGENT\",\"ip\":\"$IP\"}"
        ;;
esac
```

### Docker Compose 部署

创建 `docker-compose.yml`：

```yaml
version: '3.8'

services:
  caddy:
    image: ghcr.io/ysicing/caddy2-extra:latest
    ports:
      - "80:80"
      - "443:443"
      - "2019:2019"  # 管理 API
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - ./patterns:/etc/caddy/patterns:ro
      - ./scripts:/usr/local/bin:ro
      - caddy_data:/data
      - caddy_config:/config
      - ./logs:/var/log/caddy
    environment:
      - CADDY_ADMIN=0.0.0.0:2019
    restart: unless-stopped
    networks:
      - web

  webhook-server:
    image: python:3.9-slim
    command: python3 /app/webhook-server.py
    volumes:
      - ./webhook-server.py:/app/webhook-server.py:ro
    ports:
      - "9090:9090"
    networks:
      - web

volumes:
  caddy_data:
  caddy_config:

networks:
  web:
    external: true
```

## 📊 监控和日志

### 健康检查

插件提供健康检查端点：

```bash
# 检查 Caddy 状态
curl http://localhost:2019/config/

# 查看加载的模块
curl http://localhost:2019/reverse_proxy/upstreams | jq
```

### 日志分析

查看威胁检测日志：

```bash
# 查看所有威胁检测日志
grep "threat detected" /var/log/caddy/access.log

# 统计威胁类型分布
grep "threat detected" /var/log/caddy/access.log | \
  jq -r '.threat_type' | sort | uniq -c

# 监控实时威胁
tail -f /var/log/caddy/access.log | \
  grep --line-buffered "threat detected" | \
  jq '.ip, .threat_type, .timestamp'
```

### Prometheus 指标

插件与 Caddy 的指标系统集成：

```caddyfile
localhost:2019 {
    metrics /metrics
}
```

访问 `http://localhost:2019/metrics` 查看指标。

## 🧪 测试和验证

### 功能测试

```bash
# 测试恶意 User-Agent 检测
curl -H "User-Agent: sqlmap/1.0" http://localhost:8080/

# 测试恶意路径检测
curl http://localhost:8080/admin/config

# 测试组合威胁
curl -H "User-Agent: curl/7.68.0" http://localhost:8080/.env
```

### 性能测试

```bash
# 安装压测工具
sudo apt-get install apache2-utils

# 基础性能测试
ab -n 10000 -c 100 http://localhost:8080/

# 威胁检测性能测试
ab -n 1000 -c 50 -H "User-Agent: sqlmap/1.0" http://localhost:8080/admin
```

### 单元测试

```bash
# 运行所有单元测试
cd report && go test -v ./...

# 运行性能基准测试
cd report && go test -bench=. -benchmem

# 运行竞态条件检测
cd report && go test -race -v ./...
```

## 🔧 故障排除

### 常见问题

1. **插件未加载**
   ```bash
   # 检查插件是否编译到 Caddy 中
   ./caddy list-modules | grep report
   ```

2. **配置文件解析失败**
   ```bash
   # 验证 Caddyfile 语法
   ./caddy validate --config /path/to/Caddyfile
   ```

3. **威胁模式文件加载失败**
   ```bash
   # 检查文件权限和路径
   ls -la /etc/caddy/patterns/threats.txt
   
   # 验证文件格式
   cat /etc/caddy/patterns/threats.txt | grep -v '^#' | head -10
   ```

4. **Webhook 连接失败**
   ```bash
   # 测试 webhook 连通性
   curl -X POST -H "Content-Type: application/json" \
        -d '{"test": "data"}' \
        https://your-webhook-url/endpoint
   ```

### 调试模式

启用详细日志记录：

```caddyfile
{
    debug
    log {
        level DEBUG
        format console
    }
}

localhost:8080 {
    report {
        file /etc/caddy/patterns/threats.txt
        hook {
            remote https://webhook.site/your-unique-url
        }
    }
    
    log {
        output stdout
        level DEBUG
        format console
    }
}
```

### 性能调优

对于高流量站点，考虑以下优化：

1. **调整工作协程数量**：修改 `analyzer.go` 中的 `DefaultWorkerCount`
2. **优化队列大小**：调整 `DefaultQueueSize` 参数
3. **精简威胁模式**：移除不必要的检测规则
4. **使用高效正则表达式**：避免复杂的回溯模式

## 🤝 参与贡献

我们欢迎各种形式的贡献！

### 提交 Issue

- 🐛 **Bug 报告**: 使用 bug 模板
- 💡 **功能请求**: 详细描述需求和使用场景
- 📖 **文档改进**: 指出不清楚或错误的地方

### 提交 Pull Request

1. Fork 本仓库
2. 创建功能分支: `git checkout -b feature/amazing-feature`
3. 提交更改: `git commit -m 'Add amazing feature'`
4. 推送分支: `git push origin feature/amazing-feature`
5. 创建 Pull Request

### 开发环境设置

```bash
# 克隆仓库
git clone https://github.com/ysicing/caddy2-extra.git
cd caddy2-extra

# 安装依赖
go mod download

# 安装开发工具
task fmt

# 运行测试
task test

# 构建项目
task build
```

### 代码规范

- 遵循 Go 官方代码风格
- 编写单元测试覆盖新功能
- 更新相关文档
- 提交信息使用英文，格式清晰

## 📄 许可证

本项目采用 [Apache License 2.0](https://github.com/ysicing/caddy2-extra/blob/master/LICENSE) 许可证。

## 🙏 致谢

- [Caddy](https://caddyserver.com/) - 优秀的 Web 服务器
- [Go 社区](https://golang.org/) - 强大的编程语言
- 所有贡献者和用户的支持

## 📞 联系方式

- **GitHub Issues**: [问题反馈](https://github.com/ysicing/caddy2-extra/issues)
- **作者**: [@ysicing](https://github.com/ysicing)
- **邮箱**: ysicing.me@gmail.com

---

⭐ 如果这个项目对你有帮助，请给我们一个星标！

![Star History Chart](https://api.star-history.com/svg?repos=ysicing/caddy2-extra&type=Date) 

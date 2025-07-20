# GFWReport Plugin Examples and Documentation

This directory contains comprehensive examples and documentation for the GFWReport Caddy plugin, which provides asynchronous threat detection and reporting capabilities.

## Overview

The GFWReport plugin analyzes HTTP requests asynchronously to detect malicious patterns including:
- Malicious IP addresses (CIDR blocks)
- Suspicious request paths (regex patterns)
- Malicious User-Agent strings

When threats are detected, the plugin can report them via:
- HTTP webhooks to remote systems
- Shell command execution for local processing

## Quick Start

### 1. Basic Configuration

The simplest configuration requires only a pattern file:

```caddyfile
localhost:8080 {
    gfwreport {
        file docker/report.txt
    }
    file_server
}
```

### 2. Complete Configuration

For production use with full threat reporting:

```caddyfile
example.com {
    gfwreport {
        file /etc/caddy/patterns/threats.txt
        hook {
            remote https://siem.company.com/api/v1/threats
            exec /usr/local/bin/process-threat.sh
        }
    }
    reverse_proxy localhost:3000
}
```

## Configuration Files

### Caddyfile Examples

- **`basic-config.Caddyfile`** - Minimal configuration for development
- **`advanced-config.Caddyfile`** - Production-ready configuration with logging and multiple sites
- **`Caddyfile`** - Complete example with all available options

### Pattern Files

Pattern files define the malicious patterns to detect:

- **`patterns/basic-threats.txt`** - Common threats for basic protection
- **`patterns/advanced-threats.txt`** - Comprehensive threat patterns for production

#### Pattern File Format

```
# IP CIDR blocks
IP-CIDR: 192.168.1.0/24
IP-CIDR: 10.0.0.0/8

# User-Agent patterns (supports wildcards)
UA: Mozilla/**
UA: curl/*

# Path patterns (supports regex)
PATH: /admin/.*
PATH: /.env
```

### Processing Scripts

- **`scripts/process-threat.sh`** - Example shell script for processing threat events

## Plugin Configuration Reference

### Directive: `gfwreport`

The main plugin directive with the following sub-directives:

#### `file <path>`

Specifies the path to the malicious patterns file.

```caddyfile
gfwreport {
    file /etc/caddy/threats.txt
}
```

#### `hook` block

Configures threat reporting hooks:

```caddyfile
gfwreport {
    hook {
        remote https://webhook.example.com/threats
        exec /usr/local/bin/process-threat.sh
    }
}
```

##### `remote <url>`

HTTP webhook URL for remote threat reporting. The plugin sends POST requests with JSON payload:

```json
{
  "ip": "192.168.1.100",
  "path": "/admin/login",
  "user_agent": "curl/7.68.0",
  "method": "GET",
  "timestamp": "2024-01-01T12:00:00Z",
  "threat_type": "malicious_path",
  "headers": {
    "Host": "example.com",
    "Referer": "http://malicious.com"
  }
}
```

##### `exec <command>`

Shell command to execute when threats are detected. The command receives the following arguments:

1. IP address
2. Request path
3. User-Agent string
4. HTTP method
5. Timestamp (ISO 8601)
6. Threat type

Example:
```bash
/usr/local/bin/process-threat.sh "192.168.1.100" "/admin" "curl/7.68.0" "GET" "2024-01-01T12:00:00Z" "malicious_path"
```

## Compilation and Deployment

### Prerequisites

- Go 1.19 or later
- Caddy v2.6.0 or later

### Building Caddy with GFWReport Plugin

#### Method 1: Using xcaddy (Recommended)

1. Install xcaddy:
```bash
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
```

2. Build Caddy with the plugin:
```bash
xcaddy build --with github.com/your-org/caddy2-extra/gfwreport
```

#### Method 2: Manual Build

1. Create a `main.go` file:
```go
package main

import (
    caddycmd "github.com/caddyserver/caddy/v2/cmd"
    _ "github.com/caddyserver/caddy/v2/modules/standard"
    _ "github.com/your-org/caddy2-extra/gfwreport"
)

func main() {
    caddycmd.Main()
}
```

2. Build the binary:
```bash
go build -o caddy main.go
```

### Deployment

#### 1. System Service (systemd)

Create `/etc/systemd/system/caddy.service`:

```ini
[Unit]
Description=Caddy HTTP/2 web server with GFWReport
Documentation=https://caddyserver.com/docs/
After=network.target network-online.target
Requires=network-online.target

[Service]
Type=notify
User=caddy
Group=caddy
ExecStart=/usr/local/bin/caddy run --environ --config /etc/caddy/Caddyfile
ExecReload=/usr/local/bin/caddy reload --config /etc/caddy/Caddyfile
TimeoutStopSec=5s
LimitNOFILE=1048576
LimitNPROC=1048576
PrivateTmp=true
ProtectSystem=full
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```bash
sudo systemctl enable caddy
sudo systemctl start caddy
```

#### 2. Docker Deployment

Create a `Dockerfile`:

```dockerfile
FROM golang:1.19-alpine AS builder

# Install xcaddy
RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

# Build Caddy with GFWReport plugin
RUN xcaddy build --with github.com/your-org/caddy2-extra/gfwreport

FROM alpine:latest

# Install ca-certificates for HTTPS
RUN apk --no-cache add ca-certificates

# Create caddy user
RUN addgroup -g 1001 caddy && \
    adduser -D -s /bin/sh -u 1001 -G caddy caddy

# Copy Caddy binary
COPY --from=builder /go/caddy /usr/local/bin/caddy

# Copy configuration files
COPY Caddyfile /etc/caddy/Caddyfile
COPY patterns/ /etc/caddy/patterns/
COPY scripts/ /usr/local/bin/

# Set permissions
RUN chmod +x /usr/local/bin/caddy /usr/local/bin/*.sh

# Create directories
RUN mkdir -p /var/log/caddy /var/www/html && \
    chown -R caddy:caddy /var/log/caddy /var/www/html

USER caddy

EXPOSE 80 443

CMD ["/usr/local/bin/caddy", "run", "--config", "/etc/caddy/Caddyfile"]
```

Build and run:
```bash
docker build -t caddy-gfwreport .
docker run -d -p 80:80 -p 443:443 caddy-gfwreport
```

#### 3. Docker Compose

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  caddy:
    build: .
    ports:
      - "80:80"
      - "443:443"
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

volumes:
  caddy_data:
  caddy_config:
```

## Testing

### 1. Basic Functionality Test

Start Caddy with the basic configuration:
```bash
./caddy run --config examples/basic-config.Caddyfile
```

Test with a malicious request:
```bash
curl -H "User-Agent: curl/7.68.0" http://localhost:8080/admin
```

### 2. Webhook Testing

Set up a simple webhook receiver:
```bash
# Terminal 1: Start webhook receiver
python3 -m http.server 9090

# Terminal 2: Start Caddy
./caddy run --config examples/Caddyfile

# Terminal 3: Send test request
curl -H "User-Agent: curl/7.68.0" http://localhost:8080/config
```

### 3. Script Execution Testing

Ensure the processing script is executable:
```bash
chmod +x examples/scripts/process-threat.sh
```

Test the script directly:
```bash
./examples/scripts/process-threat.sh "192.168.1.100" "/admin" "curl/7.68.0" "GET" "2024-01-01T12:00:00Z" "malicious_path"
```

## Monitoring and Logging

### Log Configuration

Enable structured logging in your Caddyfile:

```caddyfile
{
    log {
        output file /var/log/caddy/access.log {
            roll_size 10mb
            roll_keep 10
            roll_keep_for 24h
        }
        format json
        level INFO
    }
}
```

### Metrics

The plugin integrates with Caddy's metrics system. Enable metrics endpoint:

```caddyfile
localhost:2019 {
    metrics /metrics
}
```

### Health Checks

Add health check endpoints:

```caddyfile
localhost:8080 {
    gfwreport {
        file patterns/threats.txt
    }
    
    respond /health "OK" 200
    respond /ready "Ready" 200
    
    file_server
}
```

## Troubleshooting

### Common Issues

1. **Plugin not loading**
   - Ensure the plugin is compiled into Caddy
   - Check Caddy logs for module registration errors

2. **Pattern file not found**
   - Verify file path in configuration
   - Check file permissions

3. **Webhook not receiving requests**
   - Verify webhook URL is accessible
   - Check network connectivity
   - Review webhook endpoint logs

4. **Script execution fails**
   - Ensure script has execute permissions
   - Check script path in configuration
   - Verify script dependencies are installed

### Debug Mode

Enable debug logging:

```caddyfile
{
    debug
    log {
        level DEBUG
    }
}
```

### Performance Tuning

For high-traffic sites, consider:

1. **Adjust worker count** (modify in source code)
2. **Optimize pattern files** (remove unnecessary patterns)
3. **Use efficient regex patterns**
4. **Monitor memory usage**

## Security Considerations

1. **Pattern File Security**
   - Protect pattern files from unauthorized access
   - Regularly update threat patterns
   - Use version control for pattern files

2. **Webhook Security**
   - Use HTTPS for webhook URLs
   - Implement webhook authentication
   - Validate webhook responses

3. **Script Security**
   - Use absolute paths in scripts
   - Validate script inputs
   - Run scripts with minimal privileges
   - Regularly audit script permissions

## Support

For issues and questions:
- Check the troubleshooting section above
- Review Caddy logs for error messages
- Ensure all dependencies are properly installed
- Verify configuration syntax

## License

This plugin is distributed under the same license as the main project.

# GFWReport Plugin Deployment Guide

This guide provides comprehensive instructions for deploying the GFWReport Caddy plugin in various environments.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Building the Plugin](#building-the-plugin)
3. [Configuration](#configuration)
4. [Deployment Methods](#deployment-methods)
5. [Testing](#testing)
6. [Monitoring](#monitoring)
7. [Troubleshooting](#troubleshooting)

## Prerequisites

### System Requirements

- **Operating System**: Linux, macOS, or Windows
- **Go**: Version 1.19 or later
- **Memory**: Minimum 512MB RAM (1ommended for production)
- **Disk Space**: 100MB for binary and logs
- **Network**: HTTP/HTTPS access for webhook reporting (if configured)

### Dependencies

- **Required**: Go toolchain
- **Optional**: Docker (for containerized deployment)
- **Optional**: xcaddy (for simplified building)

## Building the Plugin

### Method 1: Using the Build Script (Recommended)

The project includes a comprehensive build script that handles all build scenarios:

```bash
# Make the script executable
chmod +x build.sh

# Build with automatic method selection
./build.sh all

# Or use specific methods
./build.sh xcaddy    # Build with xcaddy (recommended)
./build.sh manual    # Build with go build
./build.sh docker    # Build Docker image
```

### Method 2: Manual Build with xcaddy

```bash
# Install xcaddy if not already installed
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

# Build Caddy with the plugin
xcaddy build --with github.com/ysicing/caddy2-extra/gfwreport=.

# The binary will be created as 'caddy' in the current directory
```

### Method 3: Manual Build with Go

```bash
# Build using the provided main.go
go build -o caddy main.go

# Or build with optimizations
CGO_ENABLED=0 go build -ldflags "-s -w" -o caddy main.go
```

### Verification

After building, verify the plugin is properly loaded:

```bash
# Check if the plugin module is registered
./caddy list-modules | grep gfwreport

# Validate a configuration file
./caddy validate --config examples/basic-config.Caddyfile --adapter caddyfile

# Test module registration
go run test_module.go
```

## Configuration

### Basic Configuration

Create a minimal `Caddyfile`:

```caddyfile
{
    order gfwreport before file_server
}

localhost:8080 {
    gfwreport {
        file /etc/caddy/patterns/threats.txt
    }
    file_server
}
```

### Production Configuration

For production environments:

```caddyfile
{
    # Global settings
    debug
    log {
        level INFO
        output file /var/log/caddy/caddy.log {
            roll_size 10mb
            roll_keep 10
            roll_keep_for 24h
        }
        format json
    }
    
    # Plugin ordering
    order gfwreport before reverse_proxy
}

example.com {
    # Structured logging
    log {
        output file /var/log/caddy/access.log {
            roll_size 10mb
            roll_keep 10
            roll_keep_for 24h
        }
        format json
    }
    
    # GFWReport configuration
    gfwreport {
        file /etc/caddy/patterns/production-threats.txt
        hook {
            remote https://siem.company.com/api/v1/threats
            exec /usr/local/bin/process-threat.sh
        }
    }
    
    # Application
    reverse_proxy localhost:3000
}
```

### Pattern File Configuration

Create `/etc/caddy/patterns/threats.txt`:

```
# IP CIDR blocks
IP-CIDR: 192.168.1.0/24
IP-CIDR: 10.0.0.0/8

# User-Agent patterns
UA: curl/*
UA: wget/*
UA: python-requests/*

# Path patterns (regex)
PATH: /admin/.*
PATH: /.env
PATH: /config
```

## Deployment Methods

### 1. Systemd Service (Linux)

#### Create Service File

Create `/etc/systemd/system/caddy-gfwreport.service`:

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
ExecReload=/usr/local/bin/caddy reload --config /etc/caddy/Caddyfile --force
TimeoutStopSec=5s
LimitNOFILE=1048576
LimitNPROC=1048576
PrivateTmp=true
ProtectSystem=full
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

#### Setup and Start

```bash
# Create caddy user
sudo useradd --system --home /var/lib/caddy --create-home --shell /bin/false caddy

# Install binary
sudo cp caddy /usr/local/bin/
sudo chmod +x /usr/local/bin/caddy

# Create directories
sudo mkdir -p /etc/caddy /var/log/caddy
sudo chown -R caddy:caddy /etc/caddy /var/log/caddy

# Copy configuration files
sudo cp examples/Caddyfile /etc/caddy/
sudo cp -r examples/patterns /etc/caddy/
sudo cp examples/scripts/process-threat.sh /usr/local/bin/
sudo chmod +x /usr/local/bin/process-threat.sh

# Enable and start service
sudo systemctl enable caddy-gfwreport
sudo systemctl start caddy-gfwreport

# Check status
sudo systemctl status caddy-gfwreport
```

### 2. Docker Deployment

#### Using Docker Compose

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  caddy-gfwreport:
    build:
      context: .
      dockerfile: examples/Dockerfile
    ports:
      - "80:80"
      - "443:443"
      - "2019:2019"
    volumes:
      - ./examples/Caddyfile:/etc/caddy/Caddyfile:ro
      - ./examples/patterns:/etc/caddy/patterns:ro
      - ./examples/scripts:/usr/local/bin/scripts:ro
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

Deploy:

```bash
# Build and start
docker-compose up -d

# View logs
docker-compose logs -f caddy-gfwreport

# Stop
docker-compose down
```

#### Using Docker Run

```bash
# Build image
docker build -t caddy-gfwreport -f examples/Dockerfile .

# Run container
docker run -d \
  --name caddy-gfwreport \
  -p 80:80 \
  -p 443:443 \
  -p 2019:2019 \
  -v $(pwd)/examples/Caddyfile:/etc/caddy/Caddyfile:ro \
  -v $(pwd)/examples/patterns:/etc/caddy/patterns:ro \
  -v $(pwd)/logs:/var/log/caddy \
  caddy-gfwreport
```

### 3. Kubernetes Deployment

#### ConfigMap for Configuration

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: caddy-gfwreport-config
data:
  Caddyfile: |
    {
        order gfwreport before reverse_proxy
    }
    
    :80 {
        gfwreport {
            file /etc/caddy/patterns/threats.txt
            hook {
                remote http://webhook-service:8080/threats
            }
        }
        reverse_proxy backend-service:8080
    }
  
  threats.txt: |
    IP-CIDR: 192.168.1.0/24
    UA: curl/*
    PATH: /admin/.*
```

#### Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: caddy-gfwreport
spec:
  replicas: 2
  selector:
    matchLabels:
      app: caddy-gfwreport
  template:
    metadata:
      labels:
        app: caddy-gfwreport
    spec:
      containers:
      - name: caddy
        image: caddy-gfwreport:latest
        ports:
        - containerPort: 80
        - containerPort: 443
        volumeMounts:
        - name: config
          mountPath: /etc/caddy
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
      volumes:
      - name: config
        configMap:
          name: caddy-gfwreport-config
```

#### Service

```yaml
apiVersion: v1
kind: Service
metadata:
  name: caddy-gfwreport-service
spec:
  selector:
    app: caddy-gfwreport
  ports:
  - name: http
    port: 80
    targetPort: 80
  - name: https
    port: 443
    targetPort: 443
  type: LoadBalancer
```

## Testing

### 1. Basic Functionality Test

```bash
# Start Caddy with test configuration
./caddy run --config examples/basic-config.Caddyfile

# In another terminal, test with malicious requests
curl -H "User-Agent: curl/7.68.0" http://localhost:8080/admin
curl -H "User-Agent: wget/1.20.3" http://localhost:8080/config
```

### 2. Webhook Testing

Set up a test webhook receiver:

```bash
# Start the example webhook server
python3 examples/webhook-server.py

# In another terminal, start Caddy
./caddy run --config examples/Caddyfile

# Send test requests
curl -H "User-Agent: curl/7.68.0" http://localhost:8080/admin
```

### 3. Load Testing

```bash
# Install Apache Bench (if not available)
# Ubuntu/Debian: sudo apt-get install apache2-utils
# macOS: brew install httpie

# Run load test
ab -n 1000 -c 10 -H "User-Agent: curl/7.68.0" http://localhost:8080/admin

# Monitor logs
tail -f /var/log/caddy/caddy.log
```

### 4. Configuration Validation

```bash
# Validate configuration
./caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile

# Test configuration reload
./caddy reload --config /etc/caddy/Caddyfile
```

## Monitoring

### 1. Metrics

Enable metrics endpoint:

```caddyfile
localhost:2019 {
    metrics /metrics
}
```

Access metrics:

```bash
curl http://localhost:2019/metrics
```

### 2. Health Checks

Add health check endpoint:

```caddyfile
localhost:8080 {
    gfwreport {
        file /etc/caddy/patterns/threats.txt
    }
    
    respond /health "OK" 200
    respond /ready "Ready" 200
    
    file_server
}
```

### 3. Log Analysis

Monitor threat detection:

```bash
# Follow threat logs
tail -f /var/log/caddy/caddy.log | grep "THREAT DETECTED"

# Count threats by type
grep "THREAT DETECTED" /var/log/caddy/caddy.log | awk '{print $NF}' | sort | uniq -c

# Monitor webhook failures
grep "webhook.*failed" /var/log/caddy/caddy.log
```

### 4. Alerting

Set up log-based alerting:

```bash
# Example with logwatch
sudo apt-get install logwatch

# Configure logwatch to monitor Caddy logs
# Add to /etc/logwatch/conf/services/caddy.conf
```

## Troubleshooting

### Common Issues

#### 1. Plugin Not Loading

**Symptoms**: `unknown directive: gfwreport`

**Solutions**:
- Verify plugin is compiled into binary: `./caddy list-modules | grep gfwreport`
- Check build process completed successfully
- Ensure correct module path in main.go

#### 2. Configuration Validation Fails

**Symptoms**: `directive 'gfwreport' is not an ordered HTTP handler`

**Solutions**:
- Add global order directive: `order gfwreport before file_server`
- Place gfwreport inside a route block
- Check Caddyfile syntax

#### 3. Pattern File Not Found

**Symptoms**: `failed to load pattern file`

**Solutions**:
- Verify file path is correct and accessible
- Check file permissions
- Ensure file exists and is readable by Caddy user

#### 4. Webhook Failures

**Symptoms**: `webhook request failed`

**Solutions**:
- Verify webhook URL is accessible
- Check network connectivity
- Validate webhook endpoint is responding
- Review webhook server logs

#### 5. High Memory Usage

**Symptoms**: Excessive memory consumption

**Solutions**:
- Reduce queue size in analyzer configuration
- Optimize pattern file (remove unnecessary patterns)
- Monitor for memory leaks
- Adjust worker count

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

1. **Adjust Worker Count**: Modify analyzer worker count in source code
2. **Optimize Patterns**: Use efficient regex patterns
3. **Queue Size**: Adjust queue size based on traffic volume
4. **Resource Limits**: Set appropriate memory and CPU limits

### Log Analysis

```bash
# Check plugin initialization
grep "gfwreport.*provisioning" /var/log/caddy/caddy.log

# Monitor threat detection
grep "THREAT DETECTED" /var/log/caddy/caddy.log

# Check webhook status
grep "webhook" /var/log/caddy/caddy.log

# Monitor performance
grep "request.*processed" /var/log/caddy/caddy.log
```

## Security Considerations

1. **Pattern File Security**: Protect pattern files from unauthorized access
2. **Webhook Security**: Use HTTPS for webhook URLs and implement authentication
3. **Script Security**: Validate and secure processing scripts
4. **Log Security**: Protect log files containing sensitive information
5. **Resource Limits**: Implement appropriate resource limits to prevent DoS

## Maintenance

### Regular Tasks

1. **Update Patterns**: Regularly update threat patterns
2. **Log Rotation**: Ensure log rotation is configured
3. **Monitor Performance**: Check system performance and adjust as needed
4. **Security Updates**: Keep Caddy and dependencies updated
5. **Backup Configuration**: Backup configuration files and patterns

### Upgrades

1. **Test in Staging**: Always test upgrades in staging environment
2. **Backup**: Backup current configuration and data
3. **Gradual Rollout**: Use gradual rollout for production deployments
4. **Monitor**: Monitor closely after upgrades

This deployment guide provides comprehensive instructions for deploying the GFWReport plugin in various environments. For additional support, refer to the troubleshooting section or check the project documentation.

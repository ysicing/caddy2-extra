# Caddy GFWReport Plugin

A Caddy plugin for asynchronous HTTP request analysis and threat detection.

## Overview

The `gfwreport` plugin analyzes HTTP requests asynchronously to detect malicious activity based on configurable patterns for IP addresses, request paths, and User-Agent strings. When threats are detected, the plugin can report them via HTTP webhooks or execute shell commands.

## Features

- **Asynchronous Processing**: Request analysis doesn't block normal HTTP request handling
- **Pattern Matching**: Supports IP CIDR, path regex, and User-Agent pattern matching
- **Flexible Reporting**: HTTP webhooks and shell command execution for threat notifications
- **Thread-Safe**: Concurrent request processing with configurable worker pools
- **Error Resilient**: Graceful error handling and retry mechanisms

## Project Structure

```
gfwreport/
├── handler.go          # Main Caddy handler implementation
├── types.go           # Core data structures and types
├── pattern_manager.go # Pattern loading and matching logic
├── analyzer.go        # Asynchronous request analysis
├── reporter.go        # Threat event reporting
└── gfwreport_test.go  # Unit tests
```

## Configuration

### Caddyfile Syntax

```caddyfile
gfwreport {
    file /path/to/patterns.txt
    hook {
        remote http://example.com/webhook
        exec /path/to/script.sh
    }
}
```

### Pattern File Format

```
# IP CIDR patterns
IP-CIDR: 1.1.1.1/8
IP-CIDR: 192.168.1.0/24

# User-Agent patterns (supports wildcards)
UA: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
UA: Mozilla/**

# Path patterns (regex supported)
PATH: /.**
PATH: /config
PATH: /admin/.*
```

## Core Components

### GFWReportHandler
Main Caddy handler that implements the HTTP middleware interface and coordinates all plugin components.

### PatternManager
Manages malicious pattern rules loaded from configuration files with thread-safe access.

### RequestAnalyzer
Handles asynchronous request analysis using a worker pool and bounded queue.

### EventReporter
Reports detected threats via HTTP webhooks or shell command execution with retry logic.

## Development Status

This plugin is currently under development. The basic project structure and core interfaces have been implemented.

### Completed Tasks
- [x] Project structure and core interfaces
- [x] Basic data structures and types
- [x] Handler framework and Caddyfile parsing
- [x] Component initialization and lifecycle management

### Upcoming Tasks
- [ ] Pattern file parsing and loading
- [ ] Pattern matching algorithms
- [ ] Request analysis implementation
- [ ] Event reporting mechanisms
- [ ] Comprehensive testing
- [ ] Documentation and examples

## Building

```bash
go build ./gfwreport
```

## Testing

```bash
go test ./gfwreport -v
```

## License

This project follows the same license as the parent repository.

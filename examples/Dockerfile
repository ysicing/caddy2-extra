# Multi-stage build for Caddy with GFWReport plugin
FROM golang:1.19-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Install xcaddy for building Caddy with plugins
RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

# Set working directory
WORKDIR /build

# Copy source code
COPY . .

# Build Caddy with GFWReport plugin
# Note: Replace with your actual module path
RUN xcaddy build --with github.com/your-org/caddy2-extra/gfwreport=.

# Production stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add \
    ca-certificates \
    mailx \
    curl \
    bash \
    tzdata

# Create caddy user and group
RUN addgroup -g 1001 caddy && \
    adduser -D -s /bin/sh -u 1001 -G caddy caddy

# Copy Caddy binary from builder stage
COPY --from=builder /build/caddy /usr/local/bin/caddy

# Create necessary directories
RUN mkdir -p \
    /etc/caddy \
    /var/log/caddy \
    /var/www/html \
    /usr/local/bin/scripts \
    && chown -R caddy:caddy \
        /etc/caddy \
        /var/log/caddy \
        /var/www/html

# Copy default configuration files
COPY examples/Caddyfile /etc/caddy/Caddyfile.example
COPY examples/patterns/ /etc/caddy/patterns/
COPY examples/scripts/ /usr/local/bin/scripts/

# Set proper permissions
RUN chmod +x /usr/local/bin/caddy /usr/local/bin/scripts/*.sh

# Create a simple index page
RUN echo '<h1>Caddy with GFWReport Plugin</h1><p>Server is running with threat detection enabled.</p>' > /var/www/html/index.html

# Switch to caddy user
USER caddy

# Expose ports
EXPOSE 80 443 2019

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost/health || exit 1

# Default command
CMD ["/usr/local/bin/caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]

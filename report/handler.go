package report

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// Module registration is handled in plugin.go

// Interface guards - 确保ReportHandler实现了所需的接口
var (
	_ caddy.Module                = (*ReportHandler)(nil)
	_ caddy.Provisioner           = (*ReportHandler)(nil)
	_ caddyfile.Unmarshaler       = (*ReportHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*ReportHandler)(nil)
	_ caddy.CleanerUpper          = (*ReportHandler)(nil)
)

// ReportHandler implements the main Caddy handler for the report plugin
type ReportHandler struct {
	// Configuration file path for malicious patterns
	ConfigFile string `json:"file,omitempty"`

	// Hook configuration for event reporting
	Hook *HookConfig `json:"hook,omitempty"`

	// Internal components
	analyzer   *RequestAnalyzer
	reporter   *EventReporter
	patternMgr *PatternManager
	logger     *zap.Logger

	// Lifecycle management
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.RWMutex
}

// HookConfig defines the configuration for event reporting hooks
type HookConfig struct {
	// HTTP webhook URL for remote reporting
	Remote string `json:"remote,omitempty"`

	// Shell command to execute for local reporting
	Exec string `json:"exec,omitempty"`
}

// CaddyModule returns the Caddy module information
func (*ReportHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.report",
		New: func() caddy.Module { return new(ReportHandler) },
	}
}

// Provision sets up the handler with the given context
func (h *ReportHandler) Provision(ctx caddy.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Initialize logger first
	h.logger = ctx.Logger()
	h.logger.Info("provisioning report handler",
		zap.String("version", "1.0.0"),
		zap.String("config_file", h.ConfigFile))

	// Create context for lifecycle management
	h.ctx, h.cancel = context.WithCancel(ctx)

	// Initialize pattern manager
	h.patternMgr = NewPatternManager(h.logger)

	// Load patterns if config file is specified
	if h.ConfigFile != "" {
		h.logger.Info("loading pattern file", zap.String("file", h.ConfigFile))

		if err := h.patternMgr.LoadFromFile(h.ConfigFile); err != nil {
			h.logger.Warn("failed to load pattern file, continuing with empty patterns",
				zap.String("file", h.ConfigFile),
				zap.Error(err))
		} else {
			ipCount, pathCount, uaCount := h.patternMgr.GetPatternCounts()
			h.logger.Info("pattern file loaded successfully",
				zap.String("file", h.ConfigFile),
				zap.Int("ip_patterns", ipCount),
				zap.Int("path_patterns", pathCount),
				zap.Int("ua_patterns", uaCount))
		}
	} else {
		h.logger.Info("no pattern file specified, using empty pattern set")
	}

	// Initialize event reporter
	h.reporter = NewEventReporter(h.Hook, h.logger)

	// Log hook configuration
	if h.Hook != nil {
		if h.Hook.Remote != "" {
			h.logger.Info("HTTP webhook configured",
				zap.String("url", h.Hook.Remote))
		}
		if h.Hook.Exec != "" {
			h.logger.Info("exec command configured",
				zap.String("command", h.Hook.Exec))
		}
	} else {
		h.logger.Info("no hooks configured, threats will only be logged")
	}

	// Initialize request analyzer
	h.analyzer = NewRequestAnalyzer(h.patternMgr, h.reporter, h.logger)

	// Start the analyzer
	if err := h.analyzer.Start(h.ctx); err != nil {
		h.logger.Error("failed to start request analyzer", zap.Error(err))
		h.cleanup()
		return fmt.Errorf("failed to start request analyzer: %w", err)
	}

	h.logger.Info("report handler provisioned successfully",
		zap.Bool("has_patterns", h.patternMgr != nil),
		zap.Bool("has_reporter", h.reporter != nil),
		zap.Bool("has_analyzer", h.analyzer != nil))

	return nil
}

// ServeHTTP implements the HTTP handler interface
func (h *ReportHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Extract request information for analysis
	requestInfo := ExtractRequestInfo(r)

	h.logger.Debug("processing request",
		zap.String("ip", requestInfo.IP.String()),
		zap.String("path", requestInfo.Path),
		zap.String("method", requestInfo.Method),
		zap.String("user_agent", requestInfo.UserAgent))

	// Submit for asynchronous analysis (non-blocking)
	h.analyzer.AnalyzeRequest(requestInfo)

	// Continue to next handler immediately
	return next.ServeHTTP(w, r)
}

// Cleanup performs cleanup when the handler is being shut down
func (h *ReportHandler) Cleanup() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	return h.cleanup()
}

// cleanup performs the actual cleanup work (internal method)
func (h *ReportHandler) cleanup() error {
	if h.logger != nil {
		h.logger.Info("cleaning up report handler")
	}

	var lastErr error

	// Cancel context to signal shutdown
	if h.cancel != nil {
		h.cancel()
		h.cancel = nil
	}

	// Stop the analyzer gracefully
	if h.analyzer != nil {
		if err := h.analyzer.Stop(); err != nil {
			if h.logger != nil {
				h.logger.Error("failed to stop request analyzer", zap.Error(err))
			}
			lastErr = err
		}
		h.analyzer = nil
	}

	// Log component cleanup
	if h.logger != nil {
		h.logger.Debug("cleaning up components",
			zap.Bool("has_reporter", h.reporter != nil),
			zap.Bool("has_pattern_manager", h.patternMgr != nil))
	}

	// Clean up other components
	h.reporter = nil
	h.patternMgr = nil
	h.ctx = nil

	if h.logger != nil {
		if lastErr != nil {
			h.logger.Warn("report handler cleanup completed with errors",
				zap.Error(lastErr))
		} else {
			h.logger.Info("report handler cleanup completed successfully")
		}
	}

	return lastErr
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler
func (h *ReportHandler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		// Parse arguments on the same line as the directive
		args := d.RemainingArgs()
		if len(args) > 0 {
			return d.Errf("report directive does not accept arguments on the same line")
		}

		// Parse block configuration
		for d.NextBlock(0) {
			switch d.Val() {
			case "file":
				if err := h.parseFileDirective(d); err != nil {
					return err
				}

			case "hook":
				if err := h.parseHookDirective(d); err != nil {
					return err
				}

			// Support legacy 'remote' directive for backward compatibility
			case "remote":
				if err := h.parseLegacyRemoteDirective(d); err != nil {
					return err
				}

			default:
				return d.Errf("unknown directive: %s", d.Val())
			}
		}
	}

	// Validate configuration after parsing
	return h.validateConfig(d)
}

// parseFileDirective parses the 'file' directive
func (h *ReportHandler) parseFileDirective(d *caddyfile.Dispenser) error {
	if !d.NextArg() {
		return d.ArgErr()
	}

	filePath := d.Val()
	if filePath == "" {
		return d.Errf("file path cannot be empty")
	}

	// Check for additional arguments
	if d.NextArg() {
		return d.Errf("file directive accepts only one argument")
	}

	h.ConfigFile = filePath
	return nil
}

// parseHookDirective parses the 'hook' block directive
func (h *ReportHandler) parseHookDirective(d *caddyfile.Dispenser) error {
	if h.Hook == nil {
		h.Hook = &HookConfig{}
	}

	// Check if there are arguments on the same line
	args := d.RemainingArgs()
	if len(args) > 0 {
		return d.Errf("hook directive does not accept arguments on the same line")
	}

	// Parse hook block
	for d.NextBlock(1) {
		switch d.Val() {
		case "remote":
			if err := h.parseRemoteHook(d); err != nil {
				return err
			}

		case "exec":
			if err := h.parseExecHook(d); err != nil {
				return err
			}

		default:
			return d.Errf("unknown hook directive: %s", d.Val())
		}
	}

	return nil
}

// parseRemoteHook parses the 'remote' hook configuration
func (h *ReportHandler) parseRemoteHook(d *caddyfile.Dispenser) error {
	if !d.NextArg() {
		return d.ArgErr()
	}

	remoteURL := d.Val()
	if remoteURL == "" {
		return d.Errf("remote URL cannot be empty")
	}

	// Basic URL validation
	if !isValidURL(remoteURL) {
		return d.Errf("invalid remote URL: %s", remoteURL)
	}

	// Check for additional arguments
	if d.NextArg() {
		return d.Errf("remote directive accepts only one argument")
	}

	h.Hook.Remote = remoteURL
	return nil
}

// parseExecHook parses the 'exec' hook configuration
func (h *ReportHandler) parseExecHook(d *caddyfile.Dispenser) error {
	if !d.NextArg() {
		return d.ArgErr()
	}

	execCmd := d.Val()
	if execCmd == "" {
		return d.Errf("exec command cannot be empty")
	}

	// Check for additional arguments
	if d.NextArg() {
		return d.Errf("exec directive accepts only one argument")
	}

	h.Hook.Exec = execCmd
	return nil
}

// parseLegacyRemoteDirective parses the legacy 'remote' directive for backward compatibility
func (h *ReportHandler) parseLegacyRemoteDirective(d *caddyfile.Dispenser) error {
	if !d.NextArg() {
		return d.ArgErr()
	}

	remoteURL := d.Val()
	if remoteURL == "" {
		return d.Errf("remote URL cannot be empty")
	}

	// Basic URL validation
	if !isValidURL(remoteURL) {
		return d.Errf("invalid remote URL: %s", remoteURL)
	}

	// Check for additional arguments
	if d.NextArg() {
		return d.Errf("remote directive accepts only one argument")
	}

	// Initialize hook config if not exists
	if h.Hook == nil {
		h.Hook = &HookConfig{}
	}

	h.Hook.Remote = remoteURL
	return nil
}

// validateConfig validates the parsed configuration
func (h *ReportHandler) validateConfig(d *caddyfile.Dispenser) error {
	// Check if at least one configuration is provided
	if h.ConfigFile == "" && h.Hook == nil {
		return d.Errf("report requires at least a file path or hook configuration")
	}

	// Validate hook configuration if present
	if h.Hook != nil {
		if h.Hook.Remote == "" && h.Hook.Exec == "" {
			return d.Errf("hook block requires at least one of 'remote' or 'exec' directives")
		}
	}

	return nil
}

// ParseCaddyfile unmarshals tokens from h into a new Middleware.
func ParseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var handler ReportHandler
	err := handler.UnmarshalCaddyfile(h.Dispenser)
	return &handler, err
}

// isValidURL validates if the given string is a valid URL
func isValidURL(rawURL string) bool {
	if rawURL == "" {
		return false
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	// Check if scheme is present and valid
	if parsedURL.Scheme == "" {
		return false
	}

	// Only allow http and https schemes for security
	scheme := strings.ToLower(parsedURL.Scheme)
	if scheme != "http" && scheme != "https" {
		return false
	}

	// Check if host is present
	if parsedURL.Host == "" {
		return false
	}

	return true
}

// Caddyfile directive registration is handled in plugin.go

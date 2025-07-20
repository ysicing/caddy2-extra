package gfwreport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"time"

	"go.uber.org/zap"
)

const (
	// DefaultHTTPTimeout is the default timeout for HTTP requests
	DefaultHTTPTimeout = 30 * time.Second
	
	// DefaultMaxRetries is the default maximum number of retries
	DefaultMaxRetries = 3
	
	// DefaultRetryDelay is the default delay between retries
	DefaultRetryDelay = time.Second
)

// EventReporter handles reporting of threat events
type EventReporter struct {
	httpClient   *http.Client
	config       *HookConfig
	logger       *zap.Logger
	errorHandler *ErrorHandler
}

// NewEventReporter creates a new EventReporter instance
func NewEventReporter(config *HookConfig, logger *zap.Logger) *EventReporter {
	errorHandler := NewErrorHandler(logger)
	
	return &EventReporter{
		httpClient: &http.Client{
			Timeout: DefaultHTTPTimeout,
		},
		config:       config,
		logger:       logger,
		errorHandler: errorHandler,
	}
}

// ReportThreat reports a detected threat event
func (er *EventReporter) ReportThreat(event *ThreatEvent) error {
	if er.config == nil {
		er.logger.Debug("no hook configuration, skipping threat report",
			zap.String("threat_type", event.ThreatType),
			zap.String("ip", event.IP))
		return nil
	}
	
	er.logger.Info("reporting threat event",
		zap.String("threat_type", event.ThreatType),
		zap.String("ip", event.IP),
		zap.String("path", event.Path),
		zap.String("user_agent", event.UserAgent),
		zap.Time("timestamp", event.Timestamp))
	
	var lastErr error
	
	// Try HTTP webhook if configured
	if er.config.Remote != "" {
		er.logger.Debug("attempting HTTP webhook report",
			zap.String("url", er.config.Remote),
			zap.String("threat_type", event.ThreatType))
		
		if err := er.sendHTTPReportWithRetry(event); err != nil {
			er.errorHandler.LogError(err, "http_webhook_report",
				zap.String("url", er.config.Remote),
				zap.String("threat_type", event.ThreatType))
			lastErr = err
		} else {
			er.logger.Info("HTTP webhook report sent successfully",
				zap.String("url", er.config.Remote),
				zap.String("threat_type", event.ThreatType))
		}
	}
	
	// Try shell command if configured
	if er.config.Exec != "" {
		er.logger.Debug("attempting shell command execution",
			zap.String("command", er.config.Exec),
			zap.String("threat_type", event.ThreatType))
		
		if err := er.executeCommandWithRetry(event); err != nil {
			er.errorHandler.LogError(err, "shell_command_execution",
				zap.String("command", er.config.Exec),
				zap.String("threat_type", event.ThreatType))
			lastErr = err
		} else {
			er.logger.Info("shell command executed successfully",
				zap.String("command", er.config.Exec),
				zap.String("threat_type", event.ThreatType))
		}
	}
	
	if lastErr != nil {
		er.logger.Error("threat reporting completed with errors",
			zap.String("threat_type", event.ThreatType),
			zap.String("ip", event.IP),
			zap.Error(lastErr))
	} else {
		er.logger.Info("threat reporting completed successfully",
			zap.String("threat_type", event.ThreatType),
			zap.String("ip", event.IP))
	}
	
	return lastErr
}

// sendHTTPReportWithRetry sends an HTTP report with retry logic
func (er *EventReporter) sendHTTPReportWithRetry(event *ThreatEvent) error {
	ctx := context.Background()
	
	operation := func() error {
		return er.sendHTTPReport(event)
	}
	
	return er.errorHandler.HandleWithRetry(ctx, operation, "http_webhook_report")
}

// sendHTTPReport sends a single HTTP report
func (er *EventReporter) sendHTTPReport(event *ThreatEvent) error {
	er.logger.Debug("preparing HTTP report",
		zap.String("url", er.config.Remote),
		zap.String("threat_type", event.ThreatType),
		zap.String("ip", event.IP))
	
	// Marshal event to JSON
	jsonData, err := json.Marshal(event)
	if err != nil {
		return NewRetryableError(fmt.Errorf("failed to marshal event: %w", err), false, false)
	}
	
	er.logger.Debug("sending HTTP request",
		zap.String("url", er.config.Remote),
		zap.Int("payload_size", len(jsonData)))
	
	// Create HTTP request
	req, err := http.NewRequest("POST", er.config.Remote, bytes.NewBuffer(jsonData))
	if err != nil {
		return NewRetryableError(fmt.Errorf("failed to create request: %w", err), false, false)
	}
	
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "caddy-gfwreport/1.0")
	
	// Add timeout context
	ctx, cancel := context.WithTimeout(context.Background(), DefaultHTTPTimeout)
	defer cancel()
	req = req.WithContext(ctx)
	
	// Send request
	resp, err := er.httpClient.Do(req)
	if err != nil {
		// Network errors are typically retryable
		return NewRetryableError(fmt.Errorf("failed to send request: %w", err), true, true)
	}
	defer resp.Body.Close()
	
	er.logger.Debug("received HTTP response",
		zap.String("url", er.config.Remote),
		zap.Int("status_code", resp.StatusCode),
		zap.String("status", resp.Status))
	
	// Check response status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// 5xx errors are retryable, 4xx errors are not
		retryable := resp.StatusCode >= 500
		return NewRetryableError(
			fmt.Errorf("HTTP request failed with status: %d %s", resp.StatusCode, resp.Status),
			retryable, retryable)
	}
	
	er.logger.Debug("HTTP report sent successfully",
		zap.String("url", er.config.Remote),
		zap.Int("status_code", resp.StatusCode))
	
	return nil
}

// executeCommandWithRetry executes a shell command with retry logic
func (er *EventReporter) executeCommandWithRetry(event *ThreatEvent) error {
	ctx := context.Background()
	
	operation := func() error {
		return er.executeCommand(event)
	}
	
	return er.errorHandler.HandleWithRetry(ctx, operation, "shell_command_execution")
}

// executeCommand executes a single shell command
func (er *EventReporter) executeCommand(event *ThreatEvent) error {
	// Create command with timeout
	ctx, cancel := context.WithTimeout(context.Background(), DefaultHTTPTimeout)
	defer cancel()
	
	// Prepare command arguments with event data
	cmdStr := fmt.Sprintf("%s '%s' '%s' '%s' '%s' '%s'",
		er.config.Exec,
		event.IP,
		event.Path,
		event.UserAgent,
		event.Method,
		event.ThreatType)
	
	er.logger.Debug("executing shell command",
		zap.String("command", er.config.Exec),
		zap.String("full_command", cmdStr),
		zap.String("threat_type", event.ThreatType))
	
	args := []string{"-c", cmdStr}
	cmd := exec.CommandContext(ctx, "/bin/sh", args...)
	
	// Execute command
	output, err := cmd.CombinedOutput()
	if err != nil {
		er.logger.Error("command execution failed",
			zap.String("command", er.config.Exec),
			zap.String("output", string(output)),
			zap.Error(err))
		
		// Command execution failures are typically not retryable
		return NewRetryableError(
			fmt.Errorf("command execution failed: %w, output: %s", err, string(output)),
			false, false)
	}
	
	er.logger.Debug("command executed successfully",
		zap.String("command", er.config.Exec),
		zap.String("output", string(output)),
		zap.Int("output_length", len(output)))
	
	return nil
}

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
)

// EventReporter handles reporting of threat events
type EventReporter struct {
	httpClient *http.Client
	config     *HookConfig
	logger     *zap.Logger
}

// NewEventReporter creates a new EventReporter instance
func NewEventReporter(config *HookConfig, logger *zap.Logger) *EventReporter {
	return &EventReporter{
		httpClient: &http.Client{
			Timeout: DefaultHTTPTimeout,
		},
		config: config,
		logger: logger,
	}
}

// ReportThreat reports a detected threat event
func (er *EventReporter) ReportThreat(event *ThreatEvent) {
	if er.config == nil {
		er.logger.Debug("no hook configuration, skipping threat report",
			zap.String("threat_type", event.ThreatType),
			zap.String("ip", event.IP))
		return
	}

	er.logger.Info("reporting threat event",
		zap.String("threat_type", event.ThreatType),
		zap.String("ip", event.IP),
		zap.String("path", event.Path),
		zap.String("user_agent", event.UserAgent),
		zap.Time("timestamp", event.Timestamp))

	// Try HTTP webhook if configured
	if er.config.Remote != "" {
		er.logger.Debug("attempting HTTP webhook report",
			zap.String("url", er.config.Remote),
			zap.String("threat_type", event.ThreatType))

		if err := er.sendHTTPReport(event); err != nil {
			er.logger.Error("HTTP webhook report failed",
				zap.String("url", er.config.Remote),
				zap.String("threat_type", event.ThreatType),
				zap.Error(err))
		} else {
			er.logger.Debug("HTTP webhook report sent completed",
				zap.String("url", er.config.Remote),
				zap.String("threat_type", event.ThreatType))
		}
	}

	// Try shell command if configured
	if er.config.Exec != "" {
		er.logger.Debug("attempting shell command execution",
			zap.String("command", er.config.Exec),
			zap.String("threat_type", event.ThreatType))

		if err := er.executeCommand(event); err != nil {
			er.logger.Error("shell command execution failed",
				zap.String("command", er.config.Exec),
				zap.String("threat_type", event.ThreatType),
				zap.Error(err))
		} else {
			er.logger.Debug("shell command executed completed",
				zap.String("command", er.config.Exec),
				zap.String("threat_type", event.ThreatType))
		}
	}
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
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	er.logger.Debug("sending HTTP request",
		zap.String("url", er.config.Remote),
		zap.Int("payload_size", len(jsonData)))

	// Create HTTP request
	req, err := http.NewRequest("POST", er.config.Remote, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "caddy-gfwreport/1.0.0")

	// Add timeout context
	ctx, cancel := context.WithTimeout(context.Background(), DefaultHTTPTimeout)
	defer cancel()
	req = req.WithContext(ctx)

	// Send request
	resp, err := er.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	er.logger.Debug("received HTTP response",
		zap.String("url", er.config.Remote),
		zap.Int("status_code", resp.StatusCode),
		zap.String("status", resp.Status))

	// Check response status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP request failed with status: %d %s", resp.StatusCode, resp.Status)
	}

	return nil
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
		return fmt.Errorf("command execution failed: %w, output: %s", err, string(output))
	}

	er.logger.Debug("command executed completed",
		zap.String("command", er.config.Exec),
		zap.String("output", string(output)),
		zap.Int("output_length", len(output)))

	return nil
}

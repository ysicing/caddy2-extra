package gfwreport

import (
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestNewLogger(t *testing.T) {
	// Test with nil config
	logger, err := NewLogger(nil)
	if err != nil {
		t.Errorf("NewLogger(nil) failed: %v", err)
	}
	if logger == nil {
		t.Error("NewLogger(nil) returned nil logger")
	}
	
	// Test with custom config
	config := &LogConfig{
		Level:         LogLevelDebug,
		Format:        "json",
		IncludeSource: true,
	}
	
	logger, err = NewLogger(config)
	if err != nil {
		t.Errorf("NewLogger(config) failed: %v", err)
	}
	if logger == nil {
		t.Error("NewLogger(config) returned nil logger")
	}
}

func TestNewLoggerWithFile(t *testing.T) {
	// Create temporary directory for log file
	tempDir, err := ioutil.TempDir("", "logger_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)
	
	logFile := filepath.Join(tempDir, "test.log")
	
	// Test with file config
	config := &LogConfig{
		Level:  LogLevelInfo,
		Format: "console",
		File:   logFile,
	}
	
	logger, err := NewLogger(config)
	if err != nil {
		t.Errorf("NewLogger(config) failed: %v", err)
	}
	if logger == nil {
		t.Error("NewLogger(config) returned nil logger")
	}
	
	// Write a log message
	logger.Info("test message")
	logger.Sync()
	
	// Check if log file was created
	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		t.Errorf("Log file was not created: %v", err)
	}
	
	// Read log file content
	content, err := ioutil.ReadFile(logFile)
	if err != nil {
		t.Errorf("Failed to read log file: %v", err)
	}
	
	// Check if log message is in file
	if !strings.Contains(string(content), "test message") {
		t.Error("Log message not found in log file")
	}
}

func TestLoggerWithContext(t *testing.T) {
	logger, _ := NewLogger(nil)
	
	// Add context fields
	contextLogger := LoggerWithContext(logger, 
		zap.String("service", "test"),
		zap.String("instance", "1"))
	
	if contextLogger == nil {
		t.Error("LoggerWithContext returned nil logger")
	}
}

func TestLogWithSource(t *testing.T) {
	fields := LogWithSource(zap.String("key", "value"))
	
	// Should have at least 2 fields (original + source)
	if len(fields) < 2 {
		t.Errorf("LogWithSource didn't add source field, got %d fields", len(fields))
	}
	
	// Check if source field exists
	hasSourceField := false
	for _, field := range fields {
		if field.Key == "source" {
			hasSourceField = true
			break
		}
	}
	
	if !hasSourceField {
		t.Error("LogWithSource didn't add source field")
	}
}

func TestLogTiming(t *testing.T) {
	// Create a buffer to capture logs
	logger, _ := NewLogger(&LogConfig{
		Level:  LogLevelDebug,
		Format: "json",
	})
	
	// Log timing
	start := time.Now().Add(-100 * time.Millisecond) // Simulate 100ms operation
	LogTiming(logger, "test_operation", start)
}

func TestLogRequest(t *testing.T) {
	logger, _ := NewLogger(nil)
	
	// Create request info
	info := &RequestInfo{
		IP:        net.ParseIP("192.168.1.1"),
		Path:      "/test",
		UserAgent: "TestAgent",
		Method:    "GET",
		Timestamp: time.Now(),
		Headers:   map[string]string{"Host": "example.com"},
	}
	
	// Log at different levels
	LogRequest(logger, info, zapcore.DebugLevel)
	LogRequest(logger, info, zapcore.InfoLevel)
	LogRequest(logger, info, zapcore.WarnLevel)
	LogRequest(logger, info, zapcore.ErrorLevel)
}

func TestLogThreat(t *testing.T) {
	logger, _ := NewLogger(nil)
	
	// Create threat event
	event := &ThreatEvent{
		IP:         "192.168.1.1",
		Path:       "/test",
		UserAgent:  "TestAgent",
		Method:     "GET",
		Timestamp:  time.Now(),
		ThreatType: ThreatTypeIP,
		Headers:    map[string]string{"Host": "example.com"},
	}
	
	// Log threat
	LogThreat(logger, event)
}

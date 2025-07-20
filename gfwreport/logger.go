package gfwreport

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// LogLevel represents the logging level
type LogLevel string

const (
	// LogLevelDebug represents debug level logging
	LogLevelDebug LogLevel = "debug"
	
	// LogLevelInfo represents info level logging
	LogLevelInfo LogLevel = "info"
	
	// LogLevelWarn represents warning level logging
	LogLevelWarn LogLevel = "warn"
	
	// LogLevelError represents error level logging
	LogLevelError LogLevel = "error"
)

// LogConfig contains configuration for the logger
type LogConfig struct {
	// Level is the minimum log level to output
	Level LogLevel `json:"level,omitempty"`
	
	// File is the path to the log file (if empty, logs to stderr)
	File string `json:"file,omitempty"`
	
	// Format is the log format (json or console)
	Format string `json:"format,omitempty"`
	
	// IncludeSource includes source code location in logs
	IncludeSource bool `json:"include_source,omitempty"`
}

// NewLogger creates a new zap logger with the given configuration
func NewLogger(config *LogConfig) (*zap.Logger, error) {
	// Default configuration
	if config == nil {
		config = &LogConfig{
			Level:         LogLevelInfo,
			Format:        "console",
			IncludeSource: false,
		}
	}
	
	// Parse log level
	var level zapcore.Level
	switch strings.ToLower(string(config.Level)) {
	case "debug":
		level = zapcore.DebugLevel
	case "info":
		level = zapcore.InfoLevel
	case "warn", "warning":
		level = zapcore.WarnLevel
	case "error":
		level = zapcore.ErrorLevel
	default:
		level = zapcore.InfoLevel
	}
	
	// Create encoder config
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.CapitalLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}
	
	// Create encoder based on format
	var encoder zapcore.Encoder
	if strings.ToLower(config.Format) == "json" {
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	} else {
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	}
	
	// Create writer
	var writer zapcore.WriteSyncer
	if config.File != "" {
		// Ensure directory exists
		dir := filepath.Dir(config.File)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create log directory: %w", err)
		}
		
		// Open log file
		file, err := os.OpenFile(config.File, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %w", err)
		}
		
		writer = zapcore.AddSync(file)
	} else {
		writer = zapcore.AddSync(os.Stderr)
	}
	
	// Create core
	core := zapcore.NewCore(encoder, writer, level)
	
	// Create logger
	var logger *zap.Logger
	if config.IncludeSource {
		logger = zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1))
	} else {
		logger = zap.New(core)
	}
	
	return logger, nil
}

// LoggerWithContext adds context fields to a logger
func LoggerWithContext(logger *zap.Logger, fields ...zap.Field) *zap.Logger {
	return logger.With(fields...)
}

// LogWithSource adds source code location to log fields
func LogWithSource(fields ...zap.Field) []zap.Field {
	_, file, line, ok := runtime.Caller(1)
	if ok {
		// Extract just the file name without the full path
		file = filepath.Base(file)
		fields = append(fields, zap.String("source", fmt.Sprintf("%s:%d", file, line)))
	}
	return fields
}

// LogTiming logs the duration of an operation
func LogTiming(logger *zap.Logger, operation string, start time.Time) {
	duration := time.Since(start)
	logger.Debug("operation timing",
		zap.String("operation", operation),
		zap.Duration("duration", duration))
}

// LogRequest logs an HTTP request
func LogRequest(logger *zap.Logger, info *RequestInfo, level zapcore.Level) {
	fields := []zap.Field{
		zap.String("ip", info.IP.String()),
		zap.String("path", info.Path),
		zap.String("method", info.Method),
		zap.String("user_agent", info.UserAgent),
		zap.Time("timestamp", info.Timestamp),
	}
	
	switch level {
	case zapcore.DebugLevel:
		logger.Debug("http request", fields...)
	case zapcore.InfoLevel:
		logger.Info("http request", fields...)
	case zapcore.WarnLevel:
		logger.Warn("http request", fields...)
	case zapcore.ErrorLevel:
		logger.Error("http request", fields...)
	default:
		logger.Info("http request", fields...)
	}
}

// LogThreat logs a detected threat
func LogThreat(logger *zap.Logger, event *ThreatEvent) {
	logger.Info("threat detected",
		zap.String("threat_type", event.ThreatType),
		zap.String("ip", event.IP),
		zap.String("path", event.Path),
		zap.String("method", event.Method),
		zap.String("user_agent", event.UserAgent),
		zap.Time("timestamp", event.Timestamp))
}

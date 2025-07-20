package gfwreport

import (
	"context"
	"fmt"
	"runtime/debug"
	"time"

	"go.uber.org/zap"
)

const (
	// ErrorHandlerMaxRetries is the default maximum number of retries for operations
	ErrorHandlerMaxRetries = 3
	
	// ErrorHandlerRetryInterval is the default base interval between retries
	ErrorHandlerRetryInterval = time.Second
	
	// ErrorHandlerMaxRetryInterval is the maximum retry interval with exponential backoff
	ErrorHandlerMaxRetryInterval = 30 * time.Second
	
	// ErrorHandlerOperationTimeout is the default timeout for individual operations
	ErrorHandlerOperationTimeout = 30 * time.Second
)

// ErrorHandler provides unified error handling with retry logic and panic recovery
type ErrorHandler struct {
	maxRetries      int
	retryInterval   time.Duration
	maxRetryInterval time.Duration
	operationTimeout time.Duration
	logger          *zap.Logger
}

// ErrorHandlerConfig contains configuration for ErrorHandler
type ErrorHandlerConfig struct {
	MaxRetries      int           `json:"max_retries,omitempty"`
	RetryInterval   time.Duration `json:"retry_interval,omitempty"`
	MaxRetryInterval time.Duration `json:"max_retry_interval,omitempty"`
	OperationTimeout time.Duration `json:"operation_timeout,omitempty"`
}

// RetryableError represents an error that can be retried
type RetryableError struct {
	Err       error
	Retryable bool
	Temporary bool
}

func (re *RetryableError) Error() string {
	return re.Err.Error()
}

func (re *RetryableError) Unwrap() error {
	return re.Err
}

// IsRetryable returns true if the error can be retried
func (re *RetryableError) IsRetryable() bool {
	return re.Retryable
}

// IsTemporary returns true if the error is temporary
func (re *RetryableError) IsTemporary() bool {
	return re.Temporary
}

// NewRetryableError creates a new RetryableError
func NewRetryableError(err error, retryable, temporary bool) *RetryableError {
	return &RetryableError{
		Err:       err,
		Retryable: retryable,
		Temporary: temporary,
	}
}

// NewErrorHandler creates a new ErrorHandler with default configuration
func NewErrorHandler(logger *zap.Logger) *ErrorHandler {
	return &ErrorHandler{
		maxRetries:       ErrorHandlerMaxRetries,
		retryInterval:    ErrorHandlerRetryInterval,
		maxRetryInterval: ErrorHandlerMaxRetryInterval,
		operationTimeout: ErrorHandlerOperationTimeout,
		logger:           logger,
	}
}

// NewErrorHandlerWithConfig creates a new ErrorHandler with custom configuration
func NewErrorHandlerWithConfig(config *ErrorHandlerConfig, logger *zap.Logger) *ErrorHandler {
	eh := NewErrorHandler(logger)
	
	if config != nil {
		if config.MaxRetries > 0 {
			eh.maxRetries = config.MaxRetries
		}
		if config.RetryInterval > 0 {
			eh.retryInterval = config.RetryInterval
		}
		if config.MaxRetryInterval > 0 {
			eh.maxRetryInterval = config.MaxRetryInterval
		}
		if config.OperationTimeout > 0 {
			eh.operationTimeout = config.OperationTimeout
		}
	}
	
	return eh
}

// HandleWithRetry executes an operation with retry logic
func (eh *ErrorHandler) HandleWithRetry(ctx context.Context, operation func() error, operationName string) error {
	var lastErr error
	
	for attempt := 0; attempt < eh.maxRetries; attempt++ {
		// Add timeout to the operation
		opCtx, cancel := context.WithTimeout(ctx, eh.operationTimeout)
		
		// Execute operation with panic recovery
		err := eh.executeWithPanicRecovery(opCtx, operation, operationName)
		cancel()
		
		if err == nil {
			// Operation succeeded
			if attempt > 0 {
				eh.logger.Info("operation succeeded after retry",
					zap.String("operation", operationName),
					zap.Int("attempt", attempt+1))
			}
			return nil
		}
		
		lastErr = err
		
		// Check if error is retryable
		if !eh.isRetryableError(err) {
			eh.logger.Error("operation failed with non-retryable error",
				zap.String("operation", operationName),
				zap.Int("attempt", attempt+1),
				zap.Error(err))
			return err
		}
		
		// Log retry attempt
		eh.logger.Warn("operation failed, will retry",
			zap.String("operation", operationName),
			zap.Int("attempt", attempt+1),
			zap.Int("max_attempts", eh.maxRetries),
			zap.Error(err))
		
		// Don't sleep after the last attempt
		if attempt < eh.maxRetries-1 {
			delay := eh.calculateRetryDelay(attempt)
			
			select {
			case <-ctx.Done():
				return fmt.Errorf("operation cancelled during retry delay: %w", ctx.Err())
			case <-time.After(delay):
				// Continue to next attempt
			}
		}
	}
	
	eh.logger.Error("operation failed after all retry attempts",
		zap.String("operation", operationName),
		zap.Int("max_attempts", eh.maxRetries),
		zap.Error(lastErr))
	
	return fmt.Errorf("operation failed after %d attempts: %w", eh.maxRetries, lastErr)
}

// HandleWithGracefulDegradation executes an operation with graceful degradation
func (eh *ErrorHandler) HandleWithGracefulDegradation(ctx context.Context, operation func() error, fallback func() error, operationName string) error {
	// Try the primary operation first
	err := eh.HandleWithRetry(ctx, operation, operationName)
	if err == nil {
		return nil
	}
	
	eh.logger.Warn("primary operation failed, attempting graceful degradation",
		zap.String("operation", operationName),
		zap.Error(err))
// Try the fallback operation
	if fallback != nil {
		fallbackErr := eh.executeWithPanicRecovery(ctx, fallback, operationName+"_fallback")
		if fallbackErr == nil {
			eh.logger.Info("graceful degradation successful",
				zap.String("operation", operationName))
			return nil
		}
		
		eh.logger.Error("fallback operation also failed",
			zap.String("operation", operationName),
			zap.Error(fallbackErr))
		
		// Return the original error, not the fallback error
		return fmt.Errorf("primary operation failed: %w (fallback also failed: %v)", err, fallbackErr)
	}
	
	return err
}

// RecoverFromPanic executes an operation with panic recovery
func (eh *ErrorHandler) RecoverFromPanic(operation func(), operationName string) {
	defer func() {
		if r := recover(); r != nil {
			eh.logger.Error("panic recovered",
				zap.String("operation", operationName),
				zap.Any("panic", r),
				zap.String("stack", string(debug.Stack())))
		}
	}()
	
	operation()
}

// RecoverFromPanicWithError executes an operation with panic recovery and returns error
func (eh *ErrorHandler) RecoverFromPanicWithError(operation func() error, operationName string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			eh.logger.Error("panic recovered",
				zap.String("operation", operationName),
				zap.Any("panic", r),
				zap.String("stack", string(debug.Stack())))
			
			err = fmt.Errorf("panic in operation %s: %v", operationName, r)
		}
	}()
	
	return operation()
}

// executeWithPanicRecovery executes an operation with panic recovery
func (eh *ErrorHandler) executeWithPanicRecovery(ctx context.Context, operation func() error, operationName string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			eh.logger.Error("panic recovered during operation",
				zap.String("operation", operationName),
				zap.Any("panic", r),
				zap.String("stack", string(debug.Stack())))
			
			err = fmt.Errorf("panic in operation %s: %v", operationName, r)
		}
	}()
	
	// Check if context is already cancelled
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	
	return operation()
}

// isRetryableError determines if an error is retryable
func (eh *ErrorHandler) isRetryableError(err error) bool {
	if err == nil {
		return false
	}
	
	// Check if it's a RetryableError
	if retryableErr, ok := err.(*RetryableError); ok {
		return retryableErr.IsRetryable()
	}
	
	// Check for context errors (not retryable)
	if err == context.Canceled || err == context.DeadlineExceeded {
		return false
	}
	
	// Check for common retryable error patterns
	errStr := err.Error()
	retryablePatterns := []string{
		"connection refused",
		"connection reset",
		"timeout",
		"temporary failure",
		"service unavailable",
		"too many requests",
		"network is unreachable",
		"no route to host",
	}
	
	for _, pattern := range retryablePatterns {
		if contains(errStr, pattern) {
			return true
		}
	}
	
	return false
}

// calculateRetryDelay calculates the delay for the next retry attempt using exponential backoff
func (eh *ErrorHandler) calculateRetryDelay(attempt int) time.Duration {
	// Exponential backoff: base * 2^attempt
	delay := eh.retryInterval * time.Duration(1<<uint(attempt))
	
	// Cap the delay at maxRetryInterval
	if delay > eh.maxRetryInterval {
		delay = eh.maxRetryInterval
	}
	
	return delay
}

// contains checks if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && 
		   (s == substr || 
		    len(s) > len(substr) && 
		    (s[:len(substr)] == substr || 
		     s[len(s)-len(substr):] == substr || 
		     containsSubstring(s, substr)))
}

// containsSubstring performs a simple substring search
func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// SafeGoroutine starts a goroutine with panic recovery
func (eh *ErrorHandler) SafeGoroutine(fn func(), operationName string) {
	go eh.RecoverFromPanic(fn, operationName)
}

// SafeGoroutineWithContext starts a goroutine with context and panic recovery
func (eh *ErrorHandler) SafeGoroutineWithContext(ctx context.Context, fn func(context.Context), operationName string) {
	go func() {
		eh.RecoverFromPanic(func() {
			fn(ctx)
		}, operationName)
	}()
}

// WrapError wraps an error with additional context
func (eh *ErrorHandler) WrapError(err error, operation, message string) error {
	if err == nil {
		return nil
	}
	
	return fmt.Errorf("%s in operation %s: %w", message, operation, err)
}

// LogError logs an error with appropriate level based on severity
func (eh *ErrorHandler) LogError(err error, operation string, fields ...zap.Field) {
	if err == nil {
		return
	}
	
	allFields := append([]zap.Field{
		zap.String("operation", operation),
		zap.Error(err),
	}, fields...)
	
	// Determine log level based on error type
	if eh.isRetryableError(err) {
		eh.logger.Warn("retryable error occurred", allFields...)
	} else {
		eh.logger.Error("non-retryable error occurred", allFields...)
	}
}

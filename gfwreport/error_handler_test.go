package gfwreport

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

func TestNewErrorHandler(t *testing.T) {
	logger := zaptest.NewLogger(t)
	eh := NewErrorHandler(logger)
	
	if eh.maxRetries != ErrorHandlerMaxRetries {
		t.Errorf("expected maxRetries %d, got %d", ErrorHandlerMaxRetries, eh.maxRetries)
	}
	
	if eh.retryInterval != ErrorHandlerRetryInterval {
		t.Errorf("expected retryInterval %v, got %v", ErrorHandlerRetryInterval, eh.retryInterval)
	}
	
	if eh.logger != logger {
		t.Error("logger not set correctly")
	}
}

func TestNewErrorHandlerWithConfig(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := &ErrorHandlerConfig{
		MaxRetries:       5,
		RetryInterval:    2 * time.Second,
		MaxRetryInterval: 60 * time.Second,
		OperationTimeout: 45 * time.Second,
	}
	
	eh := NewErrorHandlerWithConfig(config, logger)
	
	if eh.maxRetries != 5 {
		t.Errorf("expected maxRetries 5, got %d", eh.maxRetries)
	}
	
	if eh.retryInterval != 2*time.Second {
		t.Errorf("expected retryInterval 2s, got %v", eh.retryInterval)
	}
	
	if eh.maxRetryInterval != 60*time.Second {
		t.Errorf("expected maxRetryInterval 60s, got %v", eh.maxRetryInterval)
	}
	
	if eh.operationTimeout != 45*time.Second {
		t.Errorf("expected operationTimeout 45s, got %v", eh.operationTimeout)
	}
}

func TestNewErrorHandlerWithNilConfig(t *testing.T) {
	logger := zaptest.NewLogger(t)
	eh := NewErrorHandlerWithConfig(nil, logger)
	
	// Should use defaults
	if eh.maxRetries != ErrorHandlerMaxRetries {
		t.Errorf("expected default maxRetries %d, got %d", ErrorHandlerMaxRetries, eh.maxRetries)
	}
}

func TestRetryableError(t *testing.T) {
	originalErr := errors.New("test error")
	retryableErr := NewRetryableError(originalErr, true, false)
	
	if !retryableErr.IsRetryable() {
		t.Error("expected error to be retryable")
	}
	
	if retryableErr.IsTemporary() {
		t.Error("expected error to not be temporary")
	}
	
	if retryableErr.Error() != "test error" {
		t.Errorf("expected error message 'test error', got '%s'", retryableErr.Error())
	}
	
	if retryableErr.Unwrap() != originalErr {
		t.Error("Unwrap() should return original error")
	}
}

func TestHandleWithRetry_Success(t *testing.T) {
	logger := zaptest.NewLogger(t)
	eh := NewErrorHandler(logger)
	ctx := context.Background()
	
	callCount := 0
	operation := func() error {
		callCount++
		return nil
	}
	
	err := eh.HandleWithRetry(ctx, operation, "test_operation")
	
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	
	if callCount != 1 {
		t.Errorf("expected operation to be called once, got %d", callCount)
	}
}

func TestHandleWithRetry_SuccessAfterRetry(t *testing.T) {
	logger := zaptest.NewLogger(t)
	eh := NewErrorHandler(logger)
	eh.retryInterval = 10 * time.Millisecond // Speed up test
	ctx := context.Background()
	
	callCount := 0
	operation := func() error {
		callCount++
		if callCount < 3 {
			return NewRetryableError(errors.New("temporary error"), true, true)
		}
		return nil
	}
	
	err := eh.HandleWithRetry(ctx, operation, "test_operation")
	
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	
	if callCount != 3 {
		t.Errorf("expected operation to be called 3 times, got %d", callCount)
	}
}

func TestHandleWithRetry_NonRetryableError(t *testing.T) {
	logger := zaptest.NewLogger(t)
	eh := NewErrorHandler(logger)
	ctx := context.Background()
	
	callCount := 0
	nonRetryableErr := errors.New("non-retryable error")
	operation := func() error {
		callCount++
		return nonRetryableErr
	}
	
	err := eh.HandleWithRetry(ctx, operation, "test_operation")
	
	if err != nonRetryableErr {
		t.Errorf("expected non-retryable error, got %v", err)
	}
	
	if callCount != 1 {
		t.Errorf("expected operation to be called once, got %d", callCount)
	}
}

func TestHandleWithRetry_MaxRetriesExceeded(t *testing.T) {
	logger := zaptest.NewLogger(t)
	eh := NewErrorHandler(logger)
	eh.retryInterval = 10 * time.Millisecond // Speed up test
	ctx := context.Background()
	
	callCount := 0
	retryableErr := NewRetryableError(errors.New("always fails"), true, true)
	operation := func() error {
		callCount++
		return retryableErr
	}
	
	err := eh.HandleWithRetry(ctx, operation, "test_operation")
	
	if err == nil {
		t.Error("expected error after max retries exceeded")
	}
	
	if callCount != ErrorHandlerMaxRetries {
		t.Errorf("expected operation to be called %d times, got %d", ErrorHandlerMaxRetries, callCount)
	}
	
	if !strings.Contains(err.Error(), "operation failed after") {
		t.Errorf("expected error message to contain 'operation failed after', got %v", err)
	}
}

func TestHandleWithRetry_ContextCancellation(t *testing.T) {
	logger := zaptest.NewLogger(t)
	eh := NewErrorHandler(logger)
	eh.retryInterval = 100 * time.Millisecond
	
	ctx, cancel := context.WithCancel(context.Background())
	
	callCount := 0
	operation := func() error {
		callCount++
		if callCount == 1 {
			// Cancel context during first retry delay
			go func() {
				time.Sleep(50 * time.Millisecond)
				cancel()
			}()
			return NewRetryableError(errors.New("retryable error"), true, true)
		}
		return nil
	}
	
	err := eh.HandleWithRetry(ctx, operation, "test_operation")
	
	if err == nil {
		t.Error("expected context cancellation error")
	}
	
	if !strings.Contains(err.Error(), "cancelled during retry delay") {
		t.Errorf("expected context cancellation error, got %v", err)
	}
}

func TestHandleWithGracefulDegradation_PrimarySuccess(t *testing.T) {
	logger := zaptest.NewLogger(t)
	eh := NewErrorHandler(logger)
	ctx := context.Background()
	
	primaryCalled := false
	fallbackCalled := false
	
	primary := func() error {
		primaryCalled = true
		return nil
	}
	
	fallback := func() error {
		fallbackCalled = true
		return nil
	}
	
	err := eh.HandleWithGracefulDegradation(ctx, primary, fallback, "test_operation")
	
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	
	if !primaryCalled {
		t.Error("expected primary operation to be called")
	}
	
	if fallbackCalled {
		t.Error("expected fallback operation not to be called")
	}
}

func TestHandleWithGracefulDegradation_FallbackSuccess(t *testing.T) {
	logger := zaptest.NewLogger(t)
	eh := NewErrorHandler(logger)
	ctx := context.Background()
	
	primaryCalled := false
	fallbackCalled := false
	
	primary := func() error {
		primaryCalled = true
		return errors.New("primary failed")
	}
	
	fallback := func() error {
		fallbackCalled = true
		return nil
	}
	
	err := eh.HandleWithGracefulDegradation(ctx, primary, fallback, "test_operation")
	
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	
	if !primaryCalled {
		t.Error("expected primary operation to be called")
	}
	
	if !fallbackCalled {
		t.Error("expected fallback operation to be called")
	}
}

func TestHandleWithGracefulDegradation_BothFail(t *testing.T) {
	logger := zaptest.NewLogger(t)
	eh := NewErrorHandler(logger)
	ctx := context.Background()
	
	primaryErr := errors.New("primary failed")
	fallbackErr := errors.New("fallback failed")
	
	primary := func() error {
		return primaryErr
	}
	
	fallback := func() error {
		return fallbackErr
	}
	
	err := eh.HandleWithGracefulDegradation(ctx, primary, fallback, "test_operation")
	
	if err == nil {
		t.Error("expected error when both operations fail")
	}
	
	if !strings.Contains(err.Error(), "primary operation failed") {
		t.Errorf("expected error to mention primary failure, got %v", err)
	}
	
	if !strings.Contains(err.Error(), "fallback also failed") {
		t.Errorf("expected error to mention fallback failure, got %v", err)
	}
}

func TestRecoverFromPanic(t *testing.T) {
	logger := zaptest.NewLogger(t)
	eh := NewErrorHandler(logger)
	
	recovered := false
	operation := func() {
		defer func() {
			if r := recover(); r != nil {
				recovered = true
			}
		}()
		
		eh.RecoverFromPanic(func() {
			panic("test panic")
		}, "test_operation")
	}
	
	operation()
	
	// The panic should be recovered by ErrorHandler, not propagated
	if recovered {
		t.Error("panic should have been recovered by ErrorHandler")
	}
}

func TestRecoverFromPanicWithError(t *testing.T) {
	logger := zaptest.NewLogger(t)
	eh := NewErrorHandler(logger)
	
	err := eh.RecoverFromPanicWithError(func() error {
		panic("test panic")
	}, "test_operation")
	
	if err == nil {
		t.Error("expected error from panic recovery")
	}
	
	if !strings.Contains(err.Error(), "panic in operation") {
		t.Errorf("expected panic error message, got %v", err)
	}
}

func TestIsRetryableError(t *testing.T) {
	logger := zaptest.NewLogger(t)
	eh := NewErrorHandler(logger)
	
	tests := []struct {
		name      string
		err       error
		retryable bool
	}{
		{
			name:      "nil error",
			err:       nil,
			retryable: false,
		},
		{
			name:      "retryable error",
			err:       NewRetryableError(errors.New("test"), true, false),
			retryable: true,
		},
		{
			name:      "non-retryable error",
			err:       NewRetryableError(errors.New("test"), false, false),
			retryable: false,
		},
		{
			name:      "context canceled",
			err:       context.Canceled,
			retryable: false,
		},
		{
			name:      "context deadline exceeded",
			err:       context.DeadlineExceeded,
			retryable: false,
		},
		{
			name:      "connection refused",
			err:       errors.New("connection refused"),
			retryable: true,
		},
		{
			name:      "timeout error",
			err:       errors.New("operation timeout"),
			retryable: true,
		},
		{
			name:      "generic error",
			err:       errors.New("generic error"),
			retryable: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := eh.isRetryableError(tt.err)
			if result != tt.retryable {
				t.Errorf("expected retryable=%v, got %v for error: %v", tt.retryable, result, tt.err)
			}
		})
	}
}

func TestCalculateRetryDelay(t *testing.T) {
	logger := zaptest.NewLogger(t)
	eh := NewErrorHandler(logger)
	eh.retryInterval = time.Second
	eh.maxRetryInterval = 10 * time.Second
	
	tests := []struct {
		attempt      int
		expectedMin  time.Duration
		expectedMax  time.Duration
	}{
		{0, time.Second, time.Second},
		{1, 2 * time.Second, 2 * time.Second},
		{2, 4 * time.Second, 4 * time.Second},
		{3, 8 * time.Second, 8 * time.Second},
		{4, 10 * time.Second, 10 * time.Second}, // Capped at maxRetryInterval
		{5, 10 * time.Second, 10 * time.Second}, // Capped at maxRetryInterval
	}
	
	for _, tt := range tests {
		t.Run(fmt.Sprintf("attempt_%d", tt.attempt), func(t *testing.T) {
			delay := eh.calculateRetryDelay(tt.attempt)
			if delay < tt.expectedMin || delay > tt.expectedMax {
				t.Errorf("expected delay between %v and %v, got %v", tt.expectedMin, tt.expectedMax, delay)
			}
		})
	}
}

func TestSafeGoroutine(t *testing.T) {
	logger := zaptest.NewLogger(t)
	eh := NewErrorHandler(logger)
	
	done := make(chan bool, 1)
	
	eh.SafeGoroutine(func() {
		defer func() { done <- true }()
		panic("test panic")
	}, "test_operation")
	
	// Wait for goroutine to complete
	select {
	case <-done:
		// Success - goroutine completed despite panic
	case <-time.After(time.Second):
		t.Error("goroutine did not complete within timeout")
	}
}

func TestWrapError(t *testing.T) {
	logger := zaptest.NewLogger(t)
	eh := NewErrorHandler(logger)
	
	originalErr := errors.New("original error")
	wrappedErr := eh.WrapError(originalErr, "test_operation", "additional context")
	
	if wrappedErr == nil {
		t.Error("expected wrapped error")
	}
	
	if !strings.Contains(wrappedErr.Error(), "additional context") {
		t.Errorf("expected wrapped error to contain context, got %v", wrappedErr)
	}
	
	if !strings.Contains(wrappedErr.Error(), "test_operation") {
		t.Errorf("expected wrapped error to contain operation name, got %v", wrappedErr)
	}
	
	if !errors.Is(wrappedErr, originalErr) {
		t.Error("wrapped error should unwrap to original error")
	}
}

func TestWrapError_NilError(t *testing.T) {
	logger := zaptest.NewLogger(t)
	eh := NewErrorHandler(logger)
	
	wrappedErr := eh.WrapError(nil, "test_operation", "additional context")
	
	if wrappedErr != nil {
		t.Errorf("expected nil error, got %v", wrappedErr)
	}
}

func TestContains(t *testing.T) {
	tests := []struct {
		s        string
		substr   string
		expected bool
	}{
		{"hello world", "hello", true},
		{"hello world", "world", true},
		{"hello world", "lo wo", true},
		{"hello world", "xyz", false},
		{"", "", true},
		{"hello", "", true},
		{"", "hello", false},
		{"connection refused", "connection refused", true},
		{"network timeout occurred", "timeout", true},
	}
	
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_contains_%s", tt.s, tt.substr), func(t *testing.T) {
			result := contains(tt.s, tt.substr)
			if result != tt.expected {
				t.Errorf("contains(%q, %q) = %v, expected %v", tt.s, tt.substr, result, tt.expected)
			}
		})
	}
}

// Benchmark tests
func BenchmarkHandleWithRetry_Success(b *testing.B) {
	logger := zap.NewNop()
	eh := NewErrorHandler(logger)
	ctx := context.Background()
	
	operation := func() error {
		return nil
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eh.HandleWithRetry(ctx, operation, "benchmark_operation")
	}
}

func BenchmarkIsRetryableError(b *testing.B) {
	logger := zap.NewNop()
	eh := NewErrorHandler(logger)
	err := errors.New("connection refused")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eh.isRetryableError(err)
	}
}

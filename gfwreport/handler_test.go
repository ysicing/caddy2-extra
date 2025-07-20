package gfwreport

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// mockHandler implements caddyhttp.Handler for testing
type mockHandler struct {
	called bool
}

func (m *mockHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	m.called = true
	w.WriteHeader(http.StatusOK)
	return nil
}

func TestGFWReportHandler_CaddyModule(t *testing.T) {
	handler := GFWReportHandler{}
	moduleInfo := handler.CaddyModule()
	
	expectedID := "http.handlers.gfwreport"
	if string(moduleInfo.ID) != expectedID {
		t.Errorf("expected module ID %s, got %s", expectedID, string(moduleInfo.ID))
	}
	
	if moduleInfo.New == nil {
		t.Error("expected New function to be set")
	}
	
	// Test that New() returns a new instance
	newHandler := moduleInfo.New()
	if newHandler == nil {
		t.Error("expected New() to return a non-nil handler")
	}
	
	if _, ok := newHandler.(*GFWReportHandler); !ok {
		t.Error("expected New() to return a *GFWReportHandler")
	}
}

func TestGFWReportHandler_Provision(t *testing.T) {
	tests := []struct {
		name       string
		configFile string
		hook       *HookConfig
		wantErr    bool
	}{
		{
			name:       "basic provision without config",
			configFile: "",
			hook:       nil,
			wantErr:    false,
		},
		{
			name:       "provision with config file",
			configFile: "testdata/patterns.txt",
			hook:       nil,
			wantErr:    false,
		},
		{
			name:       "provision with hook config",
			configFile: "",
			hook:       &HookConfig{Remote: "http://example.com/webhook"},
			wantErr:    false,
		},
		{
			name:       "provision with both config and hook",
			configFile: "testdata/patterns.txt",
			hook:       &HookConfig{Exec: "echo 'threat detected'"},
			wantErr:    false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := &GFWReportHandler{
				ConfigFile: tt.configFile,
				Hook:       tt.hook,
			}
			
			// Create a minimal context for testing
			ctx := caddy.Context{
				Context: context.Background(),
			}
			
			err := handler.Provision(ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("Provision() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			
			if err == nil {
				// Verify components are initialized
				if handler.logger == nil {
					t.Error("expected logger to be initialized")
				}
				if handler.patternMgr == nil {
					t.Error("expected pattern manager to be initialized")
				}
				if handler.reporter == nil {
					t.Error("expected reporter to be initialized")
				}
				if handler.analyzer == nil {
					t.Error("expected analyzer to be initialized")
				}
				if handler.ctx == nil {
					t.Error("expected context to be initialized")
				}
				if handler.cancel == nil {
					t.Error("expected cancel function to be initialized")
				}
				
				// Clean up
				handler.Cleanup()
			}
		})
	}
}

func TestGFWReportHandler_ServeHTTP(t *testing.T) {
	// Create and provision handler
	handler := &GFWReportHandler{}
	
	// Create a minimal context for testing
	ctx := caddy.Context{
		Context: context.Background(),
	}
	
	err := handler.Provision(ctx)
	if err != nil {
		t.Fatalf("failed to provision handler: %v", err)
	}
	defer handler.Cleanup()
	
	// Create mock next handler
	nextHandler := &mockHandler{}
	
	// Create test request
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("User-Agent", "test-agent")
	req.RemoteAddr = "192.168.1.1:12345"
	
	// Create response recorder
	w := httptest.NewRecorder()
	
	// Call ServeHTTP
	err = handler.ServeHTTP(w, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		nextHandler.called = true
		return nextHandler.ServeHTTP(w, r)
	}))
	if err != nil {
		t.Errorf("ServeHTTP() error = %v", err)
	}
	
	// Verify next handler was called
	if !nextHandler.called {
		t.Error("expected next handler to be called")
	}
	
	// Give some time for async processing
	time.Sleep(100 * time.Millisecond)
}

func TestGFWReportHandler_ServeHTTP_WithThreat(t *testing.T) {
	// Create handler with pattern that will match
	handler := &GFWReportHandler{}
	
	// Create a minimal context for testing
	ctx := caddy.Context{
		Context: context.Background(),
	}
	
	err := handler.Provision(ctx)
	if err != nil {
		t.Fatalf("failed to provision handler: %v", err)
	}
	defer handler.Cleanup()
	
	// Add a malicious path pattern
	handler.patternMgr.AddPathPattern("/admin.*")
	
	// Create mock next handler
	nextHandler := &mockHandler{}
	
	// Create test request that should trigger threat detection
	req := httptest.NewRequest("GET", "/admin/config", nil)
	req.Header.Set("User-Agent", "malicious-bot")
	req.RemoteAddr = "1.1.1.1:12345"
	
	// Create response recorder
	w := httptest.NewRecorder()
	
	// Call ServeHTTP
	err = handler.ServeHTTP(w, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		nextHandler.called = true
		return nextHandler.ServeHTTP(w, r)
	}))
	if err != nil {
		t.Errorf("ServeHTTP() error = %v", err)
	}
	
	// Verify next handler was still called (non-blocking)
	if !nextHandler.called {
		t.Error("expected next handler to be called even with threat")
	}
	
	// Give some time for async processing
	time.Sleep(100 * time.Millisecond)
}

func TestGFWReportHandler_Cleanup(t *testing.T) {
	handler := &GFWReportHandler{}
	
	// Create a minimal context for testing
	ctx := caddy.Context{
		Context: context.Background(),
	}
	
	err := handler.Provision(ctx)
	if err != nil {
		t.Fatalf("failed to provision handler: %v", err)
	}
	
	// Verify components are running
	if handler.ctx == nil {
		t.Error("expected context to be set")
	}
	
	// Call cleanup
	err = handler.Cleanup()
	if err != nil {
		t.Errorf("Cleanup() error = %v", err)
	}
	
	// Cleanup should be idempotent
	err = handler.Cleanup()
	if err != nil {
		t.Errorf("second Cleanup() error = %v", err)
	}
}

func TestGFWReportHandler_UnmarshalCaddyfile(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    *GFWReportHandler
		expectError bool
		errorMsg    string
	}{
		{
			name:  "basic config with file",
			input: "gfwreport {\n    file /path/to/patterns.txt\n}",
			expected: &GFWReportHandler{
				ConfigFile: "/path/to/patterns.txt",
			},
			expectError: false,
		},
		{
			name: "config with hook remote",
			input: `gfwreport {
    file /path/to/patterns.txt
    hook {
        remote http://example.com/webhook
    }
}`,
			expected: &GFWReportHandler{
				ConfigFile: "/path/to/patterns.txt",
				Hook: &HookConfig{
					Remote: "http://example.com/webhook",
				},
			},
			expectError: false,
		},
		{
			name: "config with hook exec",
			input: `gfwreport {
    hook {
        exec "echo 'threat detected'"
    }
}`,
			expected: &GFWReportHandler{
				Hook: &HookConfig{
					Exec: "echo 'threat detected'",
				},
			},
			expectError: false,
		},
		{
			name: "config with both hook types",
			input: `gfwreport {
    file /path/to/patterns.txt
    hook {
        remote http://example.com/webhook
        exec "echo 'threat detected'"
    }
}`,
			expected: &GFWReportHandler{
				ConfigFile: "/path/to/patterns.txt",
				Hook: &HookConfig{
					Remote: "http://example.com/webhook",
					Exec:   "echo 'threat detected'",
				},
			},
			expectError: false,
		},
		{
			name: "config with legacy remote directive",
			input: `gfwreport {
    file /path/to/patterns.txt
    remote https://webhook.example.com/api/threats
}`,
			expected: &GFWReportHandler{
				ConfigFile: "/path/to/patterns.txt",
				Hook: &HookConfig{
					Remote: "https://webhook.example.com/api/threats",
				},
			},
			expectError: false,
		},
		{
			name: "config with HTTPS URL",
			input: `gfwreport {
    hook {
        remote https://secure.example.com/webhook
    }
}`,
			expected: &GFWReportHandler{
				Hook: &HookConfig{
					Remote: "https://secure.example.com/webhook",
				},
			},
			expectError: false,
		},
		{
			name:        "invalid directive",
			input:       "gfwreport {\n    invalid_directive value\n}",
			expected:    nil,
			expectError: true,
			errorMsg:    "unknown directive",
		},
		{
			name:        "file without value",
			input:       "gfwreport {\n    file\n}",
			expected:    nil,
			expectError: true,
			errorMsg:    "wrong argument count",
		},
		{
			name:        "hook remote without value",
			input:       "gfwreport {\n    hook {\n        remote\n    }\n}",
			expected:    nil,
			expectError: true,
			errorMsg:    "wrong argument count",
		},
		{
			name:        "empty file path",
			input:       "gfwreport {\n    file \"\"\n}",
			expected:    nil,
			expectError: true,
			errorMsg:    "file path cannot be empty",
		},
		{
			name:        "empty remote URL",
			input:       "gfwreport {\n    hook {\n        remote \"\"\n    }\n}",
			expected:    nil,
			expectError: true,
			errorMsg:    "remote URL cannot be empty",
		},
		{
			name:        "empty exec command",
			input:       "gfwreport {\n    hook {\n        exec \"\"\n    }\n}",
			expected:    nil,
			expectError: true,
			errorMsg:    "exec command cannot be empty",
		},
		{
			name:        "invalid URL scheme",
			input:       "gfwreport {\n    hook {\n        remote ftp://example.com\n    }\n}",
			expected:    nil,
			expectError: true,
			errorMsg:    "invalid remote URL",
		},
		{
			name:        "malformed URL",
			input:       "gfwreport {\n    hook {\n        remote not-a-url\n    }\n}",
			expected:    nil,
			expectError: true,
			errorMsg:    "invalid remote URL",
		},
		{
			name:        "URL without scheme",
			input:       "gfwreport {\n    hook {\n        remote example.com/webhook\n    }\n}",
			expected:    nil,
			expectError: true,
			errorMsg:    "invalid remote URL",
		},
		{
			name:        "file with multiple arguments",
			input:       "gfwreport {\n    file /path/to/file.txt extra_arg\n}",
			expected:    nil,
			expectError: true,
			errorMsg:    "file directive accepts only one argument",
		},
		{
			name:        "remote with multiple arguments",
			input:       "gfwreport {\n    hook {\n        remote http://example.com extra_arg\n    }\n}",
			expected:    nil,
			expectError: true,
			errorMsg:    "remote directive accepts only one argument",
		},
		{
			name:        "exec with multiple arguments",
			input:       "gfwreport {\n    hook {\n        exec \"echo test\" extra_arg\n    }\n}",
			expected:    nil,
			expectError: true,
			errorMsg:    "exec directive accepts only one argument",
		},
		{
			name:        "gfwreport with arguments on same line",
			input:       "gfwreport arg1 {\n    file /path/to/file.txt\n}",
			expected:    nil,
			expectError: true,
			errorMsg:    "gfwreport directive does not accept arguments on the same line",
		},
		{
			name:        "hook with arguments on same line",
			input:       "gfwreport {\n    hook arg1 {\n        remote http://example.com\n    }\n}",
			expected:    nil,
			expectError: true,
			errorMsg:    "hook directive does not accept arguments on the same line",
		},
		{
			name:        "empty hook block",
			input:       "gfwreport {\n    file /path/to/file.txt\n    hook {\n    }\n}",
			expected:    nil,
			expectError: true,
			errorMsg:    "hook block requires at least one of 'remote' or 'exec' directives",
		},
		{
			name:        "no configuration provided",
			input:       "gfwreport {\n}",
			expected:    nil,
			expectError: true,
			errorMsg:    "gfwreport requires at least a file path or hook configuration",
		},
		{
			name:        "unknown hook directive",
			input:       "gfwreport {\n    hook {\n        unknown_directive value\n    }\n}",
			expected:    nil,
			expectError: true,
			errorMsg:    "unknown hook directive",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dispenser := caddyfile.NewTestDispenser(tt.input)
			handler := &GFWReportHandler{}
			
			err := handler.UnmarshalCaddyfile(dispenser)
			
			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
					return
				}
				if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error to contain '%s', got: %v", tt.errorMsg, err)
				}
				return
			}
			
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			
			// Compare results
			if handler.ConfigFile != tt.expected.ConfigFile {
				t.Errorf("expected ConfigFile %s, got %s", tt.expected.ConfigFile, handler.ConfigFile)
			}
			
			if tt.expected.Hook == nil {
				if handler.Hook != nil {
					t.Errorf("expected Hook to be nil, got %+v", handler.Hook)
				}
			} else {
				if handler.Hook == nil {
					t.Error("expected Hook to be set")
				} else {
					if handler.Hook.Remote != tt.expected.Hook.Remote {
						t.Errorf("expected Hook.Remote %s, got %s", tt.expected.Hook.Remote, handler.Hook.Remote)
					}
					if handler.Hook.Exec != tt.expected.Hook.Exec {
						t.Errorf("expected Hook.Exec %s, got %s", tt.expected.Hook.Exec, handler.Hook.Exec)
					}
				}
			}
		})
	}
}

func TestGFWReportHandler_Integration(t *testing.T) {
	// Create a complete integration test
	handler := &GFWReportHandler{
		ConfigFile: "", // No config file for this test
		Hook: &HookConfig{
			// No hooks for this test to avoid external dependencies
		},
	}
	
	// Create a minimal context for testing
	ctx := caddy.Context{
		Context: context.Background(),
	}
	
	// Provision the handler
	err := handler.Provision(ctx)
	if err != nil {
		t.Fatalf("failed to provision handler: %v", err)
	}
	defer handler.Cleanup()
	
	// Add some test patterns
	handler.patternMgr.AddIPPattern("192.168.1.0/24")
	handler.patternMgr.AddPathPattern("/admin.*")
	handler.patternMgr.AddUserAgentPattern("malicious-bot*")
	
	// Test multiple requests
	testCases := []struct {
		name       string
		method     string
		path       string
		userAgent  string
		remoteAddr string
	}{
		{"normal request", "GET", "/", "Mozilla/5.0", "10.0.0.1:12345"},
		{"malicious IP", "GET", "/", "Mozilla/5.0", "192.168.1.100:12345"},
		{"malicious path", "GET", "/admin/config", "Mozilla/5.0", "10.0.0.1:12345"},
		{"malicious UA", "GET", "/", "malicious-bot-v1.0", "10.0.0.1:12345"},
	}
	
	nextHandler := &mockHandler{}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.Header.Set("User-Agent", tc.userAgent)
			req.RemoteAddr = tc.remoteAddr
			
			w := httptest.NewRecorder()
			
			// Reset mock handler
			nextHandler.called = false
			
			err := handler.ServeHTTP(w, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				nextHandler.called = true
				return nextHandler.ServeHTTP(w, r)
			}))
			if err != nil {
				t.Errorf("ServeHTTP() error = %v", err)
			}
			
			// Verify next handler was called
			if !nextHandler.called {
				t.Error("expected next handler to be called")
			}
		})
	}
	
	// Give time for async processing
	time.Sleep(200 * time.Millisecond)
}

// Benchmark tests
func BenchmarkGFWReportHandler_ServeHTTP(b *testing.B) {
	handler := &GFWReportHandler{}
	
	// Create a minimal context for testing
	ctx := caddy.Context{
		Context: context.Background(),
	}
	
	err := handler.Provision(ctx)
	if err != nil {
		b.Fatalf("failed to provision handler: %v", err)
	}
	defer handler.Cleanup()
	
	// Add some patterns for realistic testing
	handler.patternMgr.AddIPPattern("192.168.1.0/24")
	handler.patternMgr.AddPathPattern("/admin.*")
	handler.patternMgr.AddUserAgentPattern("bot*")
	
	nextHandler := &mockHandler{}
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("User-Agent", "test-agent")
	req.RemoteAddr = "10.0.0.1:12345"
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		nextHandler.called = false
		
		err := handler.ServeHTTP(w, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			nextHandler.called = true
			return nextHandler.ServeHTTP(w, r)
		}))
		if err != nil {
			b.Errorf("ServeHTTP() error = %v", err)
		}
	}
}

// Test URL validation function
func TestIsValidURL(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected bool
	}{
		{"valid HTTP URL", "http://example.com", true},
		{"valid HTTPS URL", "https://example.com", true},
		{"valid URL with path", "https://example.com/webhook", true},
		{"valid URL with query", "https://example.com/webhook?param=value", true},
		{"valid URL with port", "http://example.com:8080", true},
		{"empty URL", "", false},
		{"URL without scheme", "example.com", false},
		{"URL with invalid scheme", "ftp://example.com", false},
		{"URL without host", "http://", false},
		{"malformed URL", "not-a-url", false},
		{"URL with only scheme", "http://", false},
		{"URL with file scheme", "file:///path/to/file", false},
		{"URL with custom scheme", "custom://example.com", false},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidURL(tt.url)
			if result != tt.expected {
				t.Errorf("isValidURL(%s) = %v, expected %v", tt.url, result, tt.expected)
			}
		})
	}
}

// Test individual parsing functions
func TestGFWReportHandler_ParseFileDirective(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid file path",
			input:       "file /path/to/patterns.txt",
			expected:    "/path/to/patterns.txt",
			expectError: false,
		},
		{
			name:        "file without argument",
			input:       "file",
			expected:    "",
			expectError: true,
			errorMsg:    "wrong argument count",
		},
		{
			name:        "empty file path",
			input:       "file \"\"",
			expected:    "",
			expectError: true,
			errorMsg:    "file path cannot be empty",
		},
		{
			name:        "file with multiple arguments",
			input:       "file /path/to/file.txt extra_arg",
			expected:    "",
			expectError: true,
			errorMsg:    "file directive accepts only one argument",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dispenser := caddyfile.NewTestDispenser(tt.input)
			dispenser.Next() // Move to the directive
			
			handler := &GFWReportHandler{}
			err := handler.parseFileDirective(dispenser)
			
			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
					return
				}
				if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error to contain '%s', got: %v", tt.errorMsg, err)
				}
				return
			}
			
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			
			if handler.ConfigFile != tt.expected {
				t.Errorf("expected ConfigFile %s, got %s", tt.expected, handler.ConfigFile)
			}
		})
	}
}

func TestGFWReportHandler_ParseRemoteHook(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid HTTP URL",
			input:       "remote http://example.com/webhook",
			expected:    "http://example.com/webhook",
			expectError: false,
		},
		{
			name:        "valid HTTPS URL",
			input:       "remote https://secure.example.com/api",
			expected:    "https://secure.example.com/api",
			expectError: false,
		},
		{
			name:        "remote without argument",
			input:       "remote",
			expected:    "",
			expectError: true,
			errorMsg:    "wrong argument count",
		},
		{
			name:        "empty remote URL",
			input:       "remote \"\"",
			expected:    "",
			expectError: true,
			errorMsg:    "remote URL cannot be empty",
		},
		{
			name:        "invalid URL",
			input:       "remote not-a-url",
			expected:    "",
			expectError: true,
			errorMsg:    "invalid remote URL",
		},
		{
			name:        "remote with multiple arguments",
			input:       "remote http://example.com extra_arg",
			expected:    "",
			expectError: true,
			errorMsg:    "remote directive accepts only one argument",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dispenser := caddyfile.NewTestDispenser(tt.input)
			dispenser.Next() // Move to the directive
			
			handler := &GFWReportHandler{
				Hook: &HookConfig{},
			}
			err := handler.parseRemoteHook(dispenser)
			
			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
					return
				}
				if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error to contain '%s', got: %v", tt.errorMsg, err)
				}
				return
			}
			
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			
			if handler.Hook.Remote != tt.expected {
				t.Errorf("expected Hook.Remote %s, got %s", tt.expected, handler.Hook.Remote)
			}
		})
	}
}

func TestGFWReportHandler_ParseExecHook(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid exec command",
			input:       "exec \"echo 'threat detected'\"",
			expected:    "echo 'threat detected'",
			expectError: false,
		},
		{
			name:        "exec with shell script",
			input:       "exec \"/usr/local/bin/notify-threat.sh\"",
			expected:    "/usr/local/bin/notify-threat.sh",
			expectError: false,
		},
		{
			name:        "exec without argument",
			input:       "exec",
			expected:    "",
			expectError: true,
			errorMsg:    "wrong argument count",
		},
		{
			name:        "empty exec command",
			input:       "exec \"\"",
			expected:    "",
			expectError: true,
			errorMsg:    "exec command cannot be empty",
		},
		{
			name:        "exec with multiple arguments",
			input:       "exec \"echo test\" extra_arg",
			expected:    "",
			expectError: true,
			errorMsg:    "exec directive accepts only one argument",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dispenser := caddyfile.NewTestDispenser(tt.input)
			dispenser.Next() // Move to the directive
			
			handler := &GFWReportHandler{
				Hook: &HookConfig{},
			}
			err := handler.parseExecHook(dispenser)
			
			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
					return
				}
				if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error to contain '%s', got: %v", tt.errorMsg, err)
				}
				return
			}
			
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			
			if handler.Hook.Exec != tt.expected {
				t.Errorf("expected Hook.Exec %s, got %s", tt.expected, handler.Hook.Exec)
			}
		})
	}
}

func TestGFWReportHandler_ValidateConfig(t *testing.T) {
	tests := []struct {
		name        string
		handler     *GFWReportHandler
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid config with file only",
			handler: &GFWReportHandler{
				ConfigFile: "/path/to/patterns.txt",
			},
			expectError: false,
		},
		{
			name: "valid config with hook only",
			handler: &GFWReportHandler{
				Hook: &HookConfig{
					Remote: "http://example.com/webhook",
				},
			},
			expectError: false,
		},
		{
			name: "valid config with both file and hook",
			handler: &GFWReportHandler{
				ConfigFile: "/path/to/patterns.txt",
				Hook: &HookConfig{
					Remote: "http://example.com/webhook",
					Exec:   "echo 'threat detected'",
				},
			},
			expectError: false,
		},
		{
			name:        "invalid config with no file or hook",
			handler:     &GFWReportHandler{},
			expectError: true,
			errorMsg:    "gfwreport requires at least a file path or hook configuration",
		},
		{
			name: "invalid config with empty hook",
			handler: &GFWReportHandler{
				Hook: &HookConfig{},
			},
			expectError: true,
			errorMsg:    "hook block requires at least one of 'remote' or 'exec' directives",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dispenser := caddyfile.NewTestDispenser("gfwreport {}")
			err := tt.handler.validateConfig(dispenser)
			
			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
					return
				}
				if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error to contain '%s', got: %v", tt.errorMsg, err)
				}
				return
			}
			
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// Test complex configuration scenarios
func TestGFWReportHandler_ComplexConfigurations(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
		validate    func(*testing.T, *GFWReportHandler)
	}{
		{
			name: "minimal valid configuration",
			input: `gfwreport {
    file /etc/caddy/patterns.txt
}`,
			expectError: false,
			validate: func(t *testing.T, h *GFWReportHandler) {
				if h.ConfigFile != "/etc/caddy/patterns.txt" {
					t.Errorf("expected ConfigFile '/etc/caddy/patterns.txt', got '%s'", h.ConfigFile)
				}
				if h.Hook != nil {
					t.Errorf("expected Hook to be nil, got %+v", h.Hook)
				}
			},
		},
		{
			name: "full configuration with all options",
			input: `gfwreport {
    file /etc/caddy/patterns.txt
    hook {
        remote https://api.security.com/threats
        exec "/usr/local/bin/alert-security-team.sh"
    }
}`,
			expectError: false,
			validate: func(t *testing.T, h *GFWReportHandler) {
				if h.ConfigFile != "/etc/caddy/patterns.txt" {
					t.Errorf("expected ConfigFile '/etc/caddy/patterns.txt', got '%s'", h.ConfigFile)
				}
				if h.Hook == nil {
					t.Fatal("expected Hook to be set")
				}
				if h.Hook.Remote != "https://api.security.com/threats" {
					t.Errorf("expected Hook.Remote 'https://api.security.com/threats', got '%s'", h.Hook.Remote)
				}
				if h.Hook.Exec != "/usr/local/bin/alert-security-team.sh" {
					t.Errorf("expected Hook.Exec '/usr/local/bin/alert-security-team.sh', got '%s'", h.Hook.Exec)
				}
			},
		},
		{
			name: "configuration with legacy remote directive",
			input: `gfwreport {
    file /etc/caddy/patterns.txt
    remote http://legacy.webhook.com/api
}`,
			expectError: false,
			validate: func(t *testing.T, h *GFWReportHandler) {
				if h.ConfigFile != "/etc/caddy/patterns.txt" {
					t.Errorf("expected ConfigFile '/etc/caddy/patterns.txt', got '%s'", h.ConfigFile)
				}
				if h.Hook == nil {
					t.Fatal("expected Hook to be set")
				}
				if h.Hook.Remote != "http://legacy.webhook.com/api" {
					t.Errorf("expected Hook.Remote 'http://legacy.webhook.com/api', got '%s'", h.Hook.Remote)
				}
			},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dispenser := caddyfile.NewTestDispenser(tt.input)
			handler := &GFWReportHandler{}
			
			err := handler.UnmarshalCaddyfile(dispenser)
			
			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}
			
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			
			if tt.validate != nil {
				tt.validate(t, handler)
			}
		})
	}
}

// Test the parseCaddyfile function integration
func TestParseCaddyfile(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
		validate    func(*testing.T, caddyhttp.MiddlewareHandler)
	}{
		{
			name:        "basic configuration",
			input:       "gfwreport {\n    file /etc/patterns.txt\n}",
			expectError: false,
			validate: func(t *testing.T, handler caddyhttp.MiddlewareHandler) {
				h, ok := handler.(*GFWReportHandler)
				if !ok {
					t.Fatal("expected *GFWReportHandler")
				}
				if h.ConfigFile != "/etc/patterns.txt" {
					t.Errorf("expected ConfigFile '/etc/patterns.txt', got '%s'", h.ConfigFile)
				}
			},
		},
		{
			name:        "configuration with hook",
			input:       "gfwreport {\n    hook {\n        remote http://example.com/webhook\n    }\n}",
			expectError: false,
			validate: func(t *testing.T, handler caddyhttp.MiddlewareHandler) {
				h, ok := handler.(*GFWReportHandler)
				if !ok {
					t.Fatal("expected *GFWReportHandler")
				}
				if h.Hook == nil {
					t.Fatal("expected Hook to be set")
				}
				if h.Hook.Remote != "http://example.com/webhook" {
					t.Errorf("expected Hook.Remote 'http://example.com/webhook', got '%s'", h.Hook.Remote)
				}
			},
		},
		{
			name:        "invalid configuration",
			input:       "gfwreport {\n}",
			expectError: true,
			validate:    nil,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dispenser := caddyfile.NewTestDispenser(tt.input)
			helper := httpcaddyfile.Helper{Dispenser: dispenser}
			
			handler, err := parseCaddyfile(helper)
			
			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}
			
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			
			if handler == nil {
				t.Fatal("expected handler to be returned")
			}
			
			if tt.validate != nil {
				tt.validate(t, handler)
			}
		})
	}
}

// Test lifecycle management
func TestGFWReportHandler_LifecycleManagement(t *testing.T) {
	tests := []struct {
		name       string
		configFile string
		hook       *HookConfig
		wantErr    bool
	}{
		{
			name:       "basic lifecycle without config",
			configFile: "",
			hook:       nil,
			wantErr:    false,
		},
		{
			name:       "lifecycle with config file",
			configFile: "testdata/patterns.txt",
			hook:       nil,
			wantErr:    false,
		},
		{
			name:       "lifecycle with hook config",
			configFile: "",
			hook:       &HookConfig{Remote: "http://example.com/webhook"},
			wantErr:    false,
		},
		{
			name:       "lifecycle with both config and hook",
			configFile: "testdata/patterns.txt",
			hook:       &HookConfig{Exec: "echo 'threat detected'"},
			wantErr:    false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := &GFWReportHandler{
				ConfigFile: tt.configFile,
				Hook:       tt.hook,
			}
			
			// Create a minimal context for testing
			ctx := caddy.Context{
				Context: context.Background(),
			}
			
			// Test Provision
			err := handler.Provision(ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("Provision() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			
			if err == nil {
				// Verify components are properly initialized
				if handler.logger == nil {
					t.Error("expected logger to be initialized")
				}
				if handler.patternMgr == nil {
					t.Error("expected pattern manager to be initialized")
				}
				if handler.reporter == nil {
					t.Error("expected reporter to be initialized")
				}
				if handler.analyzer == nil {
					t.Error("expected analyzer to be initialized")
				}
				if handler.ctx == nil {
					t.Error("expected context to be initialized")
				}
				if handler.cancel == nil {
					t.Error("expected cancel function to be initialized")
				}
				
				// Test that components are actually running
				// Submit a test request to verify analyzer is working
				requestInfo := &RequestInfo{
					IP:        GetClientIP(httptest.NewRequest("GET", "/test", nil)),
					Path:      "/test",
					UserAgent: "test-agent",
					Method:    "GET",
					Headers:   make(map[string]string),
				}
				
				// This should not panic or block
				handler.analyzer.AnalyzeRequest(requestInfo)
				
				// Give some time for async processing
				time.Sleep(50 * time.Millisecond)
				
				// Test Cleanup
				err = handler.Cleanup()
				if err != nil {
					t.Errorf("Cleanup() error = %v", err)
				}
				
				// Verify components are cleaned up
				if handler.analyzer != nil {
					t.Error("expected analyzer to be cleaned up")
				}
				if handler.reporter != nil {
					t.Error("expected reporter to be cleaned up")
				}
				if handler.patternMgr != nil {
					t.Error("expected pattern manager to be cleaned up")
				}
				if handler.ctx != nil {
					t.Error("expected context to be cleaned up")
				}
				if handler.cancel != nil {
					t.Error("expected cancel function to be cleaned up")
				}
			}
		})
	}
}

func TestGFWReportHandler_LifecycleIdempotency(t *testing.T) {
	handler := &GFWReportHandler{}
	
	// Create a minimal context for testing
	ctx := caddy.Context{
		Context: context.Background(),
	}
	
	// Test multiple provisions (should be safe)
	err := handler.Provision(ctx)
	if err != nil {
		t.Fatalf("first Provision() error = %v", err)
	}
	
	// Second provision should work (though not recommended in practice)
	// First cleanup the previous state
	handler.Cleanup()
	
	err = handler.Provision(ctx)
	if err != nil {
		t.Fatalf("second Provision() error = %v", err)
	}
	
	// Test multiple cleanups (should be idempotent)
	err = handler.Cleanup()
	if err != nil {
		t.Errorf("first Cleanup() error = %v", err)
	}
	
	err = handler.Cleanup()
	if err != nil {
		t.Errorf("second Cleanup() error = %v", err)
	}
	
	// Third cleanup should still work
	err = handler.Cleanup()
	if err != nil {
		t.Errorf("third Cleanup() error = %v", err)
	}
}

func TestGFWReportHandler_LifecycleWithConcurrency(t *testing.T) {
	handler := &GFWReportHandler{}
	
	// Create a minimal context for testing
	ctx := caddy.Context{
		Context: context.Background(),
	}
	
	err := handler.Provision(ctx)
	if err != nil {
		t.Fatalf("Provision() error = %v", err)
	}
	
	// Test concurrent access during normal operation
	var wg sync.WaitGroup
	numGoroutines := 10
	numRequests := 100
	
	// Start multiple goroutines making requests
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			
			for j := 0; j < numRequests; j++ {
				req := httptest.NewRequest("GET", fmt.Sprintf("/test-%d-%d", id, j), nil)
				req.Header.Set("User-Agent", fmt.Sprintf("test-agent-%d", id))
				req.RemoteAddr = fmt.Sprintf("192.168.1.%d:12345", (id%254)+1)
				
				w := httptest.NewRecorder()
				
				nextHandler := &mockHandler{}
				err := handler.ServeHTTP(w, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
					nextHandler.called = true
					return nextHandler.ServeHTTP(w, r)
				}))
				if err != nil {
					t.Errorf("ServeHTTP() error = %v", err)
				}
				
				if !nextHandler.called {
					t.Error("expected next handler to be called")
				}
			}
		}(i)
	}
	
	// Wait for all requests to complete
	wg.Wait()
	
	// Give some time for async processing
	time.Sleep(100 * time.Millisecond)
	
	// Now test cleanup while there might still be some processing
	err = handler.Cleanup()
	if err != nil {
		t.Errorf("Cleanup() error = %v", err)
	}
}

func TestGFWReportHandler_LifecycleWithContextCancellation(t *testing.T) {
	handler := &GFWReportHandler{}
	
	// Create a context that we can cancel
	parentCtx, parentCancel := context.WithCancel(context.Background())
	ctx := caddy.Context{
		Context: parentCtx,
	}
	
	err := handler.Provision(ctx)
	if err != nil {
		t.Fatalf("Provision() error = %v", err)
	}
	
	// Verify handler is working
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	nextHandler := &mockHandler{}
	
	err = handler.ServeHTTP(w, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		nextHandler.called = true
		return nextHandler.ServeHTTP(w, r)
	}))
	if err != nil {
		t.Errorf("ServeHTTP() error = %v", err)
	}
	
	if !nextHandler.called {
		t.Error("expected next handler to be called")
	}
	
	// Cancel the parent context
	parentCancel()
	
	// Give some time for the cancellation to propagate
	time.Sleep(100 * time.Millisecond)
	
	// Cleanup should still work
	err = handler.Cleanup()
	if err != nil {
		t.Errorf("Cleanup() error = %v", err)
	}
}

func TestGFWReportHandler_LifecycleErrorHandling(t *testing.T) {
	// Test provision with invalid config file
	handler := &GFWReportHandler{
		ConfigFile: "/nonexistent/path/to/patterns.txt",
	}
	
	ctx := caddy.Context{
		Context: context.Background(),
	}
	
	// Should not fail even with invalid config file
	err := handler.Provision(ctx)
	if err != nil {
		t.Errorf("Provision() should not fail with invalid config file, got error: %v", err)
	}
	
	// Components should still be initialized
	if handler.analyzer == nil {
		t.Error("expected analyzer to be initialized even with invalid config")
	}
	
	// Cleanup should work
	err = handler.Cleanup()
	if err != nil {
		t.Errorf("Cleanup() error = %v", err)
	}
}

func TestGFWReportHandler_LifecycleResourceManagement(t *testing.T) {
	// Test that resources are properly managed during lifecycle
	handler := &GFWReportHandler{}
	
	ctx := caddy.Context{
		Context: context.Background(),
	}
	
	// Provision multiple times with cleanup in between
	for i := 0; i < 5; i++ {
		err := handler.Provision(ctx)
		if err != nil {
			t.Fatalf("Provision() iteration %d error = %v", i, err)
		}
		
		// Verify components are initialized
		if handler.analyzer == nil {
			t.Errorf("iteration %d: expected analyzer to be initialized", i)
		}
		if handler.ctx == nil {
			t.Errorf("iteration %d: expected context to be initialized", i)
		}
		
		// Submit some requests
		for j := 0; j < 10; j++ {
			requestInfo := &RequestInfo{
				IP:        GetClientIP(httptest.NewRequest("GET", "/test", nil)),
				Path:      fmt.Sprintf("/test-%d", j),
				UserAgent: "test-agent",
				Method:    "GET",
				Headers:   make(map[string]string),
			}
			handler.analyzer.AnalyzeRequest(requestInfo)
		}
		
		// Give some time for processing
		time.Sleep(50 * time.Millisecond)
		
		// Cleanup
		err = handler.Cleanup()
		if err != nil {
			t.Errorf("Cleanup() iteration %d error = %v", i, err)
		}
		
		// Verify cleanup
		if handler.analyzer != nil {
			t.Errorf("iteration %d: expected analyzer to be cleaned up", i)
		}
		if handler.ctx != nil {
			t.Errorf("iteration %d: expected context to be cleaned up", i)
		}
	}
}

func TestGFWReportHandler_LifecycleThreadSafety(t *testing.T) {
	handler := &GFWReportHandler{}
	
	ctx := caddy.Context{
		Context: context.Background(),
	}
	
	err := handler.Provision(ctx)
	if err != nil {
		t.Fatalf("Provision() error = %v", err)
	}
	
	// Test concurrent cleanup calls
	var wg sync.WaitGroup
	numGoroutines := 10
	errors := make(chan error, numGoroutines)
	
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := handler.Cleanup()
			if err != nil {
				errors <- err
			}
		}()
	}
	
	wg.Wait()
	close(errors)
	
	// Check for errors
	for err := range errors {
		t.Errorf("concurrent Cleanup() error = %v", err)
	}
}

// Helper function to create a test logger
func createTestLogger() *zap.Logger {
	config := zap.NewDevelopmentConfig()
	config.Level = zap.NewAtomicLevelAt(zap.ErrorLevel) // Reduce log noise in tests
	logger, _ := config.Build()
	return logger
}

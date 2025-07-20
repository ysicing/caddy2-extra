package gfwreport

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// IntegrationTestSuite contains all integration tests
type IntegrationTestSuite struct {
	t           *testing.T
	tempDir     string
	patternFile string
	handler     *GFWReportHandler
	webhookSrv  *httptest.Server
	webhookData []ThreatEvent
	webhookMu   sync.Mutex
}

// NewIntegrationTestSuite creates a new integration test suite
func NewIntegrationTestSuite(t *testing.T) *IntegrationTestSuite {
	suite := &IntegrationTestSuite{
		t:           t,
		webhookData: make([]ThreatEvent, 0),
	}
	
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "gfwreport_integration_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	suite.tempDir = tempDir
	
	// Create pattern file
	suite.patternFile = filepath.Join(tempDir, "patterns.txt")
	
	return suite
}

// Cleanup cleans up test resources
func (suite *IntegrationTestSuite) Cleanup() {
	if suite.handler != nil {
		suite.handler.Cleanup()
	}
	if suite.webhookSrv != nil {
		suite.webhookSrv.Close()
	}
	if suite.tempDir != "" {
		os.RemoveAll(suite.tempDir)
	}
}

// SetupWebhookServer sets up a mock webhook server
func (suite *IntegrationTestSuite) SetupWebhookServer() {
	suite.webhookSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		
		var event ThreatEvent
		if err := json.Unmarshal(body, &event); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		
		suite.webhookMu.Lock()
		suite.webhookData = append(suite.webhookData, event)
		suite.webhookMu.Unlock()
		
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
}

// GetWebhookData returns received webhook data
func (suite *IntegrationTestSuite) GetWebhookData() []ThreatEvent {
	suite.webhookMu.Lock()
	defer suite.webhookMu.Unlock()
	
	data := make([]ThreatEvent, len(suite.webhookData))
	copy(data, suite.webhookData)
	return data
}

// ClearWebhookData clears webhook data
func (suite *IntegrationTestSuite) ClearWebhookData() {
	suite.webhookMu.Lock()
	defer suite.webhookMu.Unlock()
	suite.webhookData = suite.webhookData[:0]
}

// CreatePatternFile creates a pattern file with given content
func (suite *IntegrationTestSuite) CreatePatternFile(content string) error {
	return os.WriteFile(suite.patternFile, []byte(content), 0644)
}

// SetupHandler sets up the GFWReport handler with given configuration
func (suite *IntegrationTestSuite) SetupHandler(configFile string, hook *HookConfig) error {
	suite.handler = &GFWReportHandler{
		ConfigFile: configFile,
		Hook:       hook,
	}
	
	ctx := caddy.Context{
		Context: context.Background(),
	}
	
	return suite.handler.Provision(ctx)
}

// TestEndToEndThreatDetectionAndReporting tests complete threat detection and reporting flow
func TestEndToEndThreatDetectionAndReporting(t *testing.T) {
	suite := NewIntegrationTestSuite(t)
	defer suite.Cleanup()
	
	// Setup webhook server
	suite.SetupWebhookServer()
	
	// Create pattern file with malicious patterns
	patternContent := `# Malicious IP patterns
IP-CIDR: 192.168.1.0/24
IP-CIDR: 10.0.0.0/8

# Malicious path patterns  
PATH: /admin.*
PATH: /config
PATH: /\.env

# Malicious user agent patterns
UA: malicious-bot*
UA: scanner/**
UA: **exploit**
`
	
	err := suite.CreatePatternFile(patternContent)
	if err != nil {
		t.Fatalf("failed to create pattern file: %v", err)
	}
	
	// Setup handler with webhook
	hook := &HookConfig{
		Remote: suite.webhookSrv.URL,
	}
	
	err = suite.SetupHandler(suite.patternFile, hook)
	if err != nil {
		t.Fatalf("failed to setup handler: %v", err)
	}
	
	// Create mock next handler
	nextHandler := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
		return nil
	})
	
	// Test cases for threat detection
	testCases := []struct {
		name           string
		method         string
		path           string
		userAgent      string
		remoteAddr     string
		expectThreat   bool
		expectedType   string
	}{
		{
			name:         "normal request - no threat",
			method:       "GET",
			path:         "/",
			userAgent:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
			remoteAddr:   "8.8.8.8:12345",
			expectThreat: false,
		},
		{
			name:         "malicious IP - should detect",
			method:       "GET", 
			path:         "/",
			userAgent:    "Mozilla/5.0",
			remoteAddr:   "192.168.1.100:12345",
			expectThreat: true,
			expectedType: ThreatTypeIP,
		},
		{
			name:         "malicious path - should detect",
			method:       "GET",
			path:         "/admin/config",
			userAgent:    "Mozilla/5.0",
			remoteAddr:   "8.8.8.8:12345",
			expectThreat: true,
			expectedType: ThreatTypePath,
		},
		{
			name:         "malicious user agent - should detect",
			method:       "GET",
			path:         "/",
			userAgent:    "malicious-bot-v1.0",
			remoteAddr:   "8.8.8.8:12345",
			expectThreat: true,
			expectedType: ThreatTypeUserAgent,
		},
		{
			name:         "multiple threats - should detect all",
			method:       "POST",
			path:         "/admin/users",
			userAgent:    "scanner/1.0",
			remoteAddr:   "10.0.0.1:12345",
			expectThreat: true,
			expectedType: ThreatTypeIP, // First detected threat type
		},
		{
			name:         "config file access - should detect",
			method:       "GET",
			path:         "/.env",
			userAgent:    "curl/7.68.0",
			remoteAddr:   "203.0.113.1:12345",
			expectThreat: true,
			expectedType: ThreatTypePath,
		},
		{
			name:         "exploit user agent - should detect",
			method:       "GET",
			path:         "/",
			userAgent:    "sqlmap-exploit-scanner",
			remoteAddr:   "203.0.113.2:12345",
			expectThreat: true,
			expectedType: ThreatTypeUserAgent,
		},
	}
	
	// Execute test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Clear previous webhook data
			suite.ClearWebhookData()
			
			// Create request
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.Header.Set("User-Agent", tc.userAgent)
			req.RemoteAddr = tc.remoteAddr
			
			// Create response recorder
			w := httptest.NewRecorder()
			
			// Process request through handler
			err := suite.handler.ServeHTTP(w, req, nextHandler)
			if err != nil {
				t.Errorf("ServeHTTP failed: %v", err)
				return
			}
			
			// Verify response was successful
			if w.Code != http.StatusOK {
				t.Errorf("expected status 200, got %d", w.Code)
			}
			
			// Wait for async processing
			time.Sleep(200 * time.Millisecond)
			
			// Check webhook data
			webhookData := suite.GetWebhookData()
			
			if tc.expectThreat {
				if len(webhookData) == 0 {
					t.Errorf("expected threat to be reported, but no webhook data received")
					return
				}
				
				// Verify threat event data
				event := webhookData[0]
				if event.ThreatType != tc.expectedType {
					t.Errorf("expected threat type %s, got %s", tc.expectedType, event.ThreatType)
				}
				
				if event.Method != tc.method {
					t.Errorf("expected method %s, got %s", tc.method, event.Method)
				}
				
				if event.Path != tc.path {
					t.Errorf("expected path %s, got %s", tc.path, event.Path)
				}
				
				if event.UserAgent != tc.userAgent {
					t.Errorf("expected user agent %s, got %s", tc.userAgent, event.UserAgent)
				}
				
				// Verify IP extraction
				expectedIP, _, _ := net.SplitHostPort(tc.remoteAddr)
				if event.IP != expectedIP {
					t.Errorf("expected IP %s, got %s", expectedIP, event.IP)
				}
				
				// Verify timestamp is recent
				if time.Since(event.Timestamp) > 5*time.Second {
					t.Errorf("threat event timestamp is too old: %v", event.Timestamp)
				}
				
			} else {
				if len(webhookData) > 0 {
					t.Errorf("expected no threat, but received webhook data: %+v", webhookData[0])
				}
			}
		})
	}
}

// TestAsynchronousProcessingCorrectness tests that async processing works correctly
func TestAsynchronousProcessingCorrectness(t *testing.T) {
	suite := NewIntegrationTestSuite(t)
	defer suite.Cleanup()
	
	// Setup webhook server
	suite.SetupWebhookServer()
	
	// Create pattern file
	patternContent := `IP-CIDR: 192.168.1.0/24
PATH: /admin
UA: malicious-bot`
	
	err := suite.CreatePatternFile(patternContent)
	if err != nil {
		t.Fatalf("failed to create pattern file: %v", err)
	}
	
	// Setup handler
	hook := &HookConfig{
		Remote: suite.webhookSrv.URL,
	}
	
	err = suite.SetupHandler(suite.patternFile, hook)
	if err != nil {
		t.Fatalf("failed to setup handler: %v", err)
	}
	
	// Create next handler that tracks execution order
	var executionOrder []string
	var mu sync.Mutex
	
	nextHandler := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		mu.Lock()
		executionOrder = append(executionOrder, "next_handler")
		mu.Unlock()
		
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
		return nil
	})
	
	// Send malicious request
	req := httptest.NewRequest("GET", "/admin", nil)
	req.Header.Set("User-Agent", "malicious-bot")
	req.RemoteAddr = "192.168.1.100:12345"
	
	w := httptest.NewRecorder()
	
	// Record start time
	startTime := time.Now()
	
	// Process request
	err = suite.handler.ServeHTTP(w, req, nextHandler)
	if err != nil {
		t.Fatalf("ServeHTTP failed: %v", err)
	}
	
	// Record end time
	endTime := time.Now()
	
	// Verify response was immediate (non-blocking)
	processingTime := endTime.Sub(startTime)
	if processingTime > 50*time.Millisecond {
		t.Errorf("request processing took too long: %v (should be < 50ms)", processingTime)
	}
	
	// Verify next handler was called immediately
	mu.Lock()
	if len(executionOrder) != 1 || executionOrder[0] != "next_handler" {
		t.Errorf("next handler should be called immediately, got: %v", executionOrder)
	}
	mu.Unlock()
	
	// Wait for async processing
	time.Sleep(300 * time.Millisecond)
	
	// Verify threat was reported asynchronously
	webhookData := suite.GetWebhookData()
	if len(webhookData) == 0 {
		t.Error("threat should be reported asynchronously")
	}
	
	// Verify threat data
	if len(webhookData) > 0 {
		event := webhookData[0]
		if event.ThreatType != ThreatTypeIP {
			t.Errorf("expected threat type %s, got %s", ThreatTypeIP, event.ThreatType)
		}
	}
}

// TestMultipleConfigurationScenarios tests various configuration scenarios
func TestMultipleConfigurationScenarios(t *testing.T) {
	testCases := []struct {
		name           string
		patternContent string
		configFile     string
		hook           *HookConfig
		expectError    bool
		testRequest    func(*testing.T, *IntegrationTestSuite)
	}{
		{
			name:           "file only configuration",
			patternContent: "IP-CIDR: 192.168.1.0/24\nPATH: /admin",
			configFile:     "", // Will be set by test
			hook:           nil,
			expectError:    false,
			testRequest: func(t *testing.T, suite *IntegrationTestSuite) {
				// Test that patterns are loaded and working
				req := httptest.NewRequest("GET", "/admin", nil)
				req.RemoteAddr = "8.8.8.8:12345"
				w := httptest.NewRecorder()
				
				nextHandler := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
					w.WriteHeader(http.StatusOK)
					return nil
				})
				
				err := suite.handler.ServeHTTP(w, req, nextHandler)
				if err != nil {
					t.Errorf("ServeHTTP failed: %v", err)
				}
				
				if w.Code != http.StatusOK {
					t.Errorf("expected status 200, got %d", w.Code)
				}
			},
		},
		{
			name:           "webhook only configuration",
			patternContent: "",
			configFile:     "",
			hook:           &HookConfig{Remote: "http://example.com/webhook"},
			expectError:    false,
			testRequest: func(t *testing.T, suite *IntegrationTestSuite) {
				// Test that handler works without patterns
				req := httptest.NewRequest("GET", "/", nil)
				req.RemoteAddr = "8.8.8.8:12345"
				w := httptest.NewRecorder()
				
				nextHandler := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
					w.WriteHeader(http.StatusOK)
					return nil
				})
				
				err := suite.handler.ServeHTTP(w, req, nextHandler)
				if err != nil {
					t.Errorf("ServeHTTP failed: %v", err)
				}
			},
		},
		{
			name:           "exec command configuration",
			patternContent: "UA: malicious-bot",
			configFile:     "",
			hook:           &HookConfig{Exec: "echo 'threat detected'"},
			expectError:    false,
			testRequest: func(t *testing.T, suite *IntegrationTestSuite) {
				// Test exec command execution
				req := httptest.NewRequest("GET", "/", nil)
				req.Header.Set("User-Agent", "malicious-bot")
				req.RemoteAddr = "8.8.8.8:12345"
				w := httptest.NewRecorder()
				
				nextHandler := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
					w.WriteHeader(http.StatusOK)
					return nil
				})
				
				err := suite.handler.ServeHTTP(w, req, nextHandler)
				if err != nil {
					t.Errorf("ServeHTTP failed: %v", err)
				}
				
				// Wait for async processing
				time.Sleep(200 * time.Millisecond)
			},
		},
		{
			name:           "both webhook and exec configuration",
			patternContent: "IP-CIDR: 10.0.0.0/8",
			configFile:     "",
			hook:           &HookConfig{Remote: "http://example.com/webhook", Exec: "echo 'dual threat'"},
			expectError:    false,
			testRequest: func(t *testing.T, suite *IntegrationTestSuite) {
				// Test both reporting methods
				req := httptest.NewRequest("GET", "/", nil)
				req.RemoteAddr = "10.0.0.1:12345"
				w := httptest.NewRecorder()
				
				nextHandler := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
					w.WriteHeader(http.StatusOK)
					return nil
				})
				
				err := suite.handler.ServeHTTP(w, req, nextHandler)
				if err != nil {
					t.Errorf("ServeHTTP failed: %v", err)
				}
				
				time.Sleep(200 * time.Millisecond)
			},
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			suite := NewIntegrationTestSuite(t)
			defer suite.Cleanup()
			
			var configFile string
			if tc.patternContent != "" {
				err := suite.CreatePatternFile(tc.patternContent)
				if err != nil {
					t.Fatalf("failed to create pattern file: %v", err)
				}
				configFile = suite.patternFile
			}
			
			err := suite.SetupHandler(configFile, tc.hook)
			
			if tc.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}
			
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			
			if tc.testRequest != nil {
				tc.testRequest(t, suite)
			}
		})
	}
}

// TestCompleteWorkflowWithRealPatterns tests the complete workflow using real pattern file
func TestCompleteWorkflowWithRealPatterns(t *testing.T) {
	suite := NewIntegrationTestSuite(t)
	defer suite.Cleanup()
	
	// Setup webhook server
	suite.SetupWebhookServer()
	
	// Use the real pattern file from docker directory
	realPatternFile := "../docker/report.txt"
	
	// Check if file exists
	if _, err := os.Stat(realPatternFile); os.IsNotExist(err) {
		t.Skip("real pattern file not found, skipping test")
	}
	
	// Setup handler with real pattern file
	hook := &HookConfig{
		Remote: suite.webhookSrv.URL,
	}
	
	err := suite.SetupHandler(realPatternFile, hook)
	if err != nil {
		t.Fatalf("failed to setup handler with real patterns: %v", err)
	}
	
	// Test cases based on real patterns in docker/report.txt
	testCases := []struct {
		name         string
		method       string
		path         string
		userAgent    string
		remoteAddr   string
		expectThreat bool
	}{
		{
			name:         "IP in 1.1.1.1/8 range - should detect",
			method:       "GET",
			path:         "/",
			userAgent:    "Mozilla/5.0",
			remoteAddr:   "1.2.3.4:12345",
			expectThreat: true,
		},
		{
			name:         "exact Mozilla UA - should detect",
			method:       "GET",
			path:         "/",
			userAgent:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/000000000 Safari/537.36",
			remoteAddr:   "8.8.8.8:12345",
			expectThreat: true,
		},
		{
			name:         "Mozilla wildcard pattern - should detect",
			method:       "GET",
			path:         "/",
			userAgent:    "Mozilla/5.0 (different version)",
			remoteAddr:   "8.8.8.8:12345",
			expectThreat: true,
		},
		{
			name:         "config path - should detect",
			method:       "GET",
			path:         "/config",
			userAgent:    "curl/7.68.0",
			remoteAddr:   "8.8.8.8:12345",
			expectThreat: true,
		},
		{
			name:         "normal request - should not detect",
			method:       "GET",
			path:         "/index.html",
			userAgent:    "Chrome/91.0.4472.124",
			remoteAddr:   "203.0.113.1:12345",
			expectThreat: false,
		},
	}
	
	nextHandler := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
		return nil
	})
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Clear previous data
			suite.ClearWebhookData()
			
			// Create and process request
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.Header.Set("User-Agent", tc.userAgent)
			req.RemoteAddr = tc.remoteAddr
			
			w := httptest.NewRecorder()
			
			err := suite.handler.ServeHTTP(w, req, nextHandler)
			if err != nil {
				t.Errorf("ServeHTTP failed: %v", err)
				return
			}
			
			// Wait for async processing
			time.Sleep(300 * time.Millisecond)
			
			// Check results
			webhookData := suite.GetWebhookData()
			
			if tc.expectThreat {
				if len(webhookData) == 0 {
					t.Errorf("expected threat to be detected and reported")
				} else {
					event := webhookData[0]
					t.Logf("Detected threat: Type=%s, IP=%s, Path=%s, UA=%s", 
						event.ThreatType, event.IP, event.Path, event.UserAgent)
				}
			} else {
				if len(webhookData) > 0 {
					t.Errorf("expected no threat, but got: %+v", webhookData[0])
				}
			}
		})
	}
}

// TestErrorHandlingAndRecovery tests error handling and recovery scenarios
func TestErrorHandlingAndRecovery(t *testing.T) {
	suite := NewIntegrationTestSuite(t)
	defer suite.Cleanup()
	
	// Test with invalid pattern file
	t.Run("invalid pattern file", func(t *testing.T) {
		invalidPatternFile := filepath.Join(suite.tempDir, "invalid.txt")
		err := os.WriteFile(invalidPatternFile, []byte("INVALID: invalid-pattern\nIP-CIDR: invalid-cidr"), 0644)
		if err != nil {
			t.Fatalf("failed to create invalid pattern file: %v", err)
		}
		
		// Handler should still provision successfully with graceful degradation
		err = suite.SetupHandler(invalidPatternFile, nil)
		if err != nil {
			t.Errorf("handler should provision successfully even with invalid patterns: %v", err)
		}
		
		// Test that handler still works
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "8.8.8.8:12345"
		w := httptest.NewRecorder()
		
		nextHandler := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			w.WriteHeader(http.StatusOK)
			return nil
		})
		
		err = suite.handler.ServeHTTP(w, req, nextHandler)
		if err != nil {
			t.Errorf("ServeHTTP should work even with invalid patterns: %v", err)
		}
	})
	
	// Test with non-existent pattern file
	t.Run("non-existent pattern file", func(t *testing.T) {
		nonExistentFile := filepath.Join(suite.tempDir, "nonexistent.txt")
		
		// Handler should provision successfully with graceful degradation
		err := suite.SetupHandler(nonExistentFile, nil)
		if err != nil {
			t.Errorf("handler should provision successfully even with non-existent file: %v", err)
		}
		
		// Test that handler still works
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "8.8.8.8:12345"
		w := httptest.NewRecorder()
		
		nextHandler := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			w.WriteHeader(http.StatusOK)
			return nil
		})
		
		err = suite.handler.ServeHTTP(w, req, nextHandler)
		if err != nil {
			t.Errorf("ServeHTTP should work even with non-existent pattern file: %v", err)
		}
	})
	
	// Test with failing webhook
	t.Run("failing webhook", func(t *testing.T) {
		// Setup failing webhook server
		failingServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Internal Server Error"))
		}))
		defer failingServer.Close()
		
		// Create pattern file
		err := suite.CreatePatternFile("IP-CIDR: 192.168.1.0/24")
		if err != nil {
			t.Fatalf("failed to create pattern file: %v", err)
		}
		
		// Setup handler with failing webhook
		hook := &HookConfig{
			Remote: failingServer.URL,
		}
		
		err = suite.SetupHandler(suite.patternFile, hook)
		if err != nil {
			t.Fatalf("failed to setup handler: %v", err)
		}
		
		// Send malicious request
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "192.168.1.100:12345"
		w := httptest.NewRecorder()
		
		nextHandler := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			w.WriteHeader(http.StatusOK)
			return nil
		})
		
		// Handler should not fail even if webhook fails
		err = suite.handler.ServeHTTP(w, req, nextHandler)
		if err != nil {
			t.Errorf("ServeHTTP should not fail even if webhook fails: %v", err)
		}
		
		// Response should still be successful
		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", w.Code)
		}
		
		// Wait for async processing
		time.Sleep(300 * time.Millisecond)
	})
}

// TestConcurrentRequestHandling tests concurrent request processing
func TestConcurrentRequestHandling(t *testing.T) {
	suite := NewIntegrationTestSuite(t)
	defer suite.Cleanup()
	
	// Setup webhook server
	suite.SetupWebhookServer()
	
	// Create pattern file
	patternContent := `IP-CIDR: 192.168.1.0/24
PATH: /admin
UA: malicious-bot`
	
	err := suite.CreatePatternFile(patternContent)
	if err != nil {
		t.Fatalf("failed to create pattern file: %v", err)
	}
	
	// Setup handler
	hook := &HookConfig{
		Remote: suite.webhookSrv.URL,
	}
	
	err = suite.SetupHandler(suite.patternFile, hook)
	if err != nil {
		t.Fatalf("failed to setup handler: %v", err)
	}
	
	// Create next handler
	nextHandler := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
		return nil
	})
	
	// Test concurrent requests
	numRequests := 50
	var wg sync.WaitGroup
	var errors []error
	var errorsMu sync.Mutex
	
	wg.Add(numRequests)
	
	for i := 0; i < numRequests; i++ {
		go func(requestID int) {
			defer wg.Done()
			
			// Create different types of requests
			var req *http.Request
			switch requestID % 4 {
			case 0:
				// Normal request
				req = httptest.NewRequest("GET", "/", nil)
				req.RemoteAddr = "8.8.8.8:12345"
				req.Header.Set("User-Agent", "Mozilla/5.0")
			case 1:
				// Malicious IP
				req = httptest.NewRequest("GET", "/", nil)
				req.RemoteAddr = "192.168.1.100:12345"
				req.Header.Set("User-Agent", "Mozilla/5.0")
			case 2:
				// Malicious path
				req = httptest.NewRequest("GET", "/admin", nil)
				req.RemoteAddr = "8.8.8.8:12345"
				req.Header.Set("User-Agent", "Mozilla/5.0")
			case 3:
				// Malicious user agent
				req = httptest.NewRequest("GET", "/", nil)
				req.RemoteAddr = "8.8.8.8:12345"
				req.Header.Set("User-Agent", "malicious-bot")
			}
			
			w := httptest.NewRecorder()
			
			err := suite.handler.ServeHTTP(w, req, nextHandler)
			if err != nil {
				errorsMu.Lock()
				errors = append(errors, fmt.Errorf("request %d failed: %w", requestID, err))
				errorsMu.Unlock()
				return
			}
			
			if w.Code != http.StatusOK {
				errorsMu.Lock()
				errors = append(errors, fmt.Errorf("request %d got status %d", requestID, w.Code))
				errorsMu.Unlock()
			}
		}(i)
	}
	
	// Wait for all requests to complete
	wg.Wait()
	
	// Check for errors
	if len(errors) > 0 {
		for _, err := range errors {
			t.Errorf("concurrent request error: %v", err)
		}
	}
	
	// Wait for async processing
	time.Sleep(500 * time.Millisecond)
	
	// Verify some threats were detected
	webhookData := suite.GetWebhookData()
	expectedThreats := (numRequests / 4) * 3 // 3 out of 4 request types are malicious
	
	if len(webhookData) < expectedThreats/2 {
		t.Errorf("expected at least %d threats, got %d", expectedThreats/2, len(webhookData))
	}
	
	t.Logf("Processed %d concurrent requests, detected %d threats", numRequests, len(webhookData))
}

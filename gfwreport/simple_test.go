package gfwreport

import (
	"context"
	"net"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

func TestBasicFunctionality(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Test PatternManager
	pm := NewPatternManager(logger)

	// Add some patterns
	err := pm.AddIPPattern("192.168.1.0/24")
	if err != nil {
		t.Fatalf("Failed to add IP pattern: %v", err)
	}

	err = pm.AddPathPattern("/admin.*")
	if err != nil {
		t.Fatalf("Failed to add path pattern: %v", err)
	}

	pm.AddUserAgentPattern("malicious-bot*")

	// Test pattern matching
	ip := net.ParseIP("192.168.1.100")
	if !pm.MatchIP(ip) {
		t.Error("Expected IP to match pattern")
	}

	if !pm.MatchPath("/admin/config") {
		t.Error("Expected path to match pattern")
	}

	if !pm.MatchUserAgent("malicious-bot-v1.0") {
		t.Error("Expected user agent to match pattern")
	}

	// Test EventReporter
	config := &HookConfig{}
	reporter := NewEventReporter(config, logger)

	// Create a test event
	requestInfo := &RequestInfo{
		IP:        ip,
		Path:      "/admin/config",
		UserAgent: "malicious-bot-v1.0",
		Method:    "GET",
		Timestamp: time.Now(),
		Headers:   map[string]string{"Host": "example.com"},
	}

	event := NewThreatEvent(requestInfo, ThreatTypeIP)

	// Report the threat (should not panic or error)
	reporter.ReportThreat(event)

	// Test RequestAnalyzer
	analyzer := NewRequestAnalyzer(pm, reporter, logger)

	err = analyzer.Start(context.Background())
	if err != nil {
		t.Fatalf("Failed to start analyzer: %v", err)
	}

	// Analyze a request
	analyzer.AnalyzeRequest(requestInfo)

	// Give some time for async processing
	time.Sleep(100 * time.Millisecond)

	err = analyzer.Stop()
	if err != nil {
		t.Fatalf("Failed to stop analyzer: %v", err)
	}
}

func TestThreatEventValidation(t *testing.T) {
	event := &ThreatEvent{
		IP:         "192.168.1.1",
		Path:       "/test",
		UserAgent:  "test-agent",
		Method:     "GET",
		Timestamp:  time.Now(),
		ThreatType: ThreatTypeIP,
		Headers:    map[string]string{"Host": "example.com"},
	}

	err := event.Validate()
	if err != nil {
		t.Errorf("Valid event should not fail validation: %v", err)
	}

	// Test invalid event
	invalidEvent := &ThreatEvent{
		IP: "invalid-ip",
	}

	err = invalidEvent.Validate()
	if err == nil {
		t.Error("Invalid event should fail validation")
	}
}

func TestPatternCounts(t *testing.T) {
	logger := zaptest.NewLogger(t)
	pm := NewPatternManager(logger)

	pm.AddIPPattern("192.168.1.0/24")
	pm.AddIPPattern("10.0.0.0/8")
	pm.AddPathPattern("/admin.*")
	pm.AddUserAgentPattern("bot*")
	pm.AddUserAgentPattern("crawler*")

	ipCount, pathCount, uaCount := pm.GetPatternCounts()

	if ipCount != 2 {
		t.Errorf("Expected 2 IP patterns, got %d", ipCount)
	}

	if pathCount != 1 {
		t.Errorf("Expected 1 path pattern, got %d", pathCount)
	}

	if uaCount != 2 {
		t.Errorf("Expected 2 UA patterns, got %d", uaCount)
	}
}

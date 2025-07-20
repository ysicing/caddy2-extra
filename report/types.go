package report

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// RequestInfo contains information about an HTTP request for analysis
type RequestInfo struct {
	IP        net.IP            `json:"ip"`
	Path      string            `json:"path"`
	UserAgent string            `json:"user_agent"`
	Method    string            `json:"method"`
	Timestamp time.Time         `json:"timestamp"`
	Headers   map[string]string `json:"headers"`
}

// ThreatEvent represents a detected security threat
type ThreatEvent struct {
	IP         string            `json:"ip"`
	Path       string            `json:"path"`
	UserAgent  string            `json:"user_agent"`
	Method     string            `json:"method"`
	Timestamp  time.Time         `json:"timestamp"`
	ThreatType string            `json:"threat_type"`
	Headers    map[string]string `json:"headers"`
}

// PatternConfig represents the configuration structure for malicious patterns
type PatternConfig struct {
	IPCIDRs    []string `yaml:"ip_cidrs"`
	Paths      []string `yaml:"paths"`
	UserAgents []string `yaml:"user_agents"`
}

// ThreatType constants for different types of threats
const (
	ThreatTypeIP        = "malicious_ip"
	ThreatTypePath      = "malicious_path"
	ThreatTypeUserAgent = "malicious_user_agent"
	ThreatTypeNormal    = "normal_request"
)

// GetClientIP extracts the real client IP from the HTTP request
func GetClientIP(r *http.Request) net.IP {
	// Check X-Forwarded-For header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			if parsedIP := net.ParseIP(ip); parsedIP != nil {
				return parsedIP
			}
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		if parsedIP := net.ParseIP(xri); parsedIP != nil {
			return parsedIP
		}
	}

	// Fall back to RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return net.ParseIP(r.RemoteAddr)
	}

	return net.ParseIP(host)
}

// ExtractHeaders extracts relevant headers from the HTTP request
func ExtractHeaders(r *http.Request) map[string]string {
	headers := make(map[string]string)

	// Extract commonly used headers for threat analysis
	relevantHeaders := []string{
		"Host",
		"Referer",
		"Origin",
		"X-Forwarded-For",
		"X-Real-IP",
		"Accept",
		"Accept-Language",
		"Accept-Encoding",
		"Connection",
	}

	for _, headerName := range relevantHeaders {
		if value := r.Header.Get(headerName); value != "" {
			headers[headerName] = value
		}
	}

	return headers
}

// NewRequestInfo creates a new RequestInfo with current timestamp
func NewRequestInfo(ip net.IP, path, userAgent, method string, headers map[string]string) *RequestInfo {
	return &RequestInfo{
		IP:        ip,
		Path:      path,
		UserAgent: userAgent,
		Method:    method,
		Timestamp: time.Now(),
		Headers:   headers,
	}
}

// ExtractRequestInfo extracts complete request information from HTTP request
func ExtractRequestInfo(r *http.Request) *RequestInfo {
	ip := GetClientIP(r)
	headers := ExtractHeaders(r)
	userAgent := r.Header.Get("User-Agent")

	return NewRequestInfo(ip, r.URL.Path, userAgent, r.Method, headers)
}

// NewThreatEvent creates a new ThreatEvent from RequestInfo
func NewThreatEvent(info *RequestInfo, threatType string) *ThreatEvent {
	return &ThreatEvent{
		IP:         info.IP.String(),
		Path:       info.Path,
		UserAgent:  info.UserAgent,
		Method:     info.Method,
		Timestamp:  info.Timestamp,
		ThreatType: threatType,
		Headers:    info.Headers,
	}
}

// Validate validates the ThreatEvent structure
func (te *ThreatEvent) Validate() error {
	if te.IP == "" {
		return fmt.Errorf("IP address is required")
	}

	// Validate IP format
	if net.ParseIP(te.IP) == nil {
		return fmt.Errorf("invalid IP address format: %s", te.IP)
	}

	if te.Path == "" {
		return fmt.Errorf("path is required")
	}

	if te.Method == "" {
		return fmt.Errorf("HTTP method is required")
	}

	if te.ThreatType == "" {
		return fmt.Errorf("threat type is required")
	}

	// Validate threat type is one of the known types
	validThreatTypes := map[string]bool{
		ThreatTypeIP:        true,
		ThreatTypePath:      true,
		ThreatTypeUserAgent: true,
	}

	if !validThreatTypes[te.ThreatType] {
		return fmt.Errorf("invalid threat type: %s", te.ThreatType)
	}

	if te.Timestamp.IsZero() {
		return fmt.Errorf("timestamp is required")
	}

	return nil
}

// ToJSON serializes the ThreatEvent to JSON
func (te *ThreatEvent) ToJSON() ([]byte, error) {
	if err := te.Validate(); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	return json.Marshal(te)
}

// FromJSON deserializes JSON data into a ThreatEvent
func (te *ThreatEvent) FromJSON(data []byte) error {
	if err := json.Unmarshal(data, te); err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	return te.Validate()
}

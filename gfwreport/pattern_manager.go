package gfwreport

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"

	"go.uber.org/zap"
)

// PatternManager manages malicious patterns for threat detection
type PatternManager struct {
	ipPatterns   []*net.IPNet     // IP CIDR patterns
	pathPatterns []*regexp.Regexp // Path regex patterns
	uaPatterns   []string         // User-Agent patterns
	mutex        sync.RWMutex     // Thread-safe access
	logger       *zap.Logger
}

// NewPatternManager creates a new PatternManager instance
func NewPatternManager(logger *zap.Logger) *PatternManager {
	return &PatternManager{
		ipPatterns:   make([]*net.IPNet, 0),
		pathPatterns: make([]*regexp.Regexp, 0),
		uaPatterns:   make([]string, 0),
		logger:       logger,
	}
}

// LoadFromFile loads malicious patterns from a configuration file
func (pm *PatternManager) LoadFromFile(filePath string) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	pm.logger.Info("loading patterns from file", zap.String("file", filePath))

	file, err := os.Open(filePath)
	if err != nil {
		pm.logger.Error("failed to open pattern file", zap.String("file", filePath), zap.Error(err))
		return fmt.Errorf("failed to open pattern file %s: %w", filePath, err)
	}
	defer file.Close()

	// Clear existing patterns
	pm.ipPatterns = make([]*net.IPNet, 0)
	pm.pathPatterns = make([]*regexp.Regexp, 0)
	pm.uaPatterns = make([]string, 0)

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if err := pm.parseLine(line, lineNum); err != nil {
			pm.logger.Warn("failed to parse line",
				zap.Int("line", lineNum),
				zap.String("content", line),
				zap.Error(err))
			// Continue processing other lines instead of failing completely
		}
	}

	if err := scanner.Err(); err != nil {
		pm.logger.Error("error reading pattern file", zap.String("file", filePath), zap.Error(err))
		return fmt.Errorf("error reading pattern file %s: %w", filePath, err)
	}

	ipCount, pathCount, uaCount := len(pm.ipPatterns), len(pm.pathPatterns), len(pm.uaPatterns)
	pm.logger.Info("patterns loaded successfully",
		zap.String("file", filePath),
		zap.Int("ip_patterns", ipCount),
		zap.Int("path_patterns", pathCount),
		zap.Int("ua_patterns", uaCount))

	return nil
}

// parseLine parses a single line from the configuration file
func (pm *PatternManager) parseLine(line string, lineNum int) error {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid format: expected 'TYPE: VALUE' at line %d", lineNum)
	}

	patternType := strings.TrimSpace(parts[0])
	patternValue := strings.TrimSpace(parts[1])

	if patternValue == "" {
		return fmt.Errorf("empty pattern value at line %d", lineNum)
	}

	switch patternType {
	case "IP-CIDR", "IP":
		return pm.parseIPPattern(patternValue, lineNum)
	case "PATH":
		return pm.parsePathPattern(patternValue, lineNum)
	case "UA":
		pm.parseUAPattern(patternValue)
		return nil
	default:
		return fmt.Errorf("unknown pattern type '%s' at line %d", patternType, lineNum)
	}
}

// parseIPPattern parses and adds an IP CIDR pattern
func (pm *PatternManager) parseIPPattern(cidr string, lineNum int) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid IP CIDR '%s' at line %d: %w", cidr, lineNum, err)
	}

	pm.ipPatterns = append(pm.ipPatterns, ipNet)
	return nil
}

// parsePathPattern parses and adds a path regex pattern
func (pm *PatternManager) parsePathPattern(pattern string, lineNum int) error {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid regex pattern '%s' at line %d: %w", pattern, lineNum, err)
	}

	pm.pathPatterns = append(pm.pathPatterns, regex)
	return nil
}

// parseUAPattern parses and adds a User-Agent pattern
func (pm *PatternManager) parseUAPattern(pattern string) {
	pm.uaPatterns = append(pm.uaPatterns, pattern)
}

// MatchIP checks if an IP address matches any malicious IP patterns
func (pm *PatternManager) MatchIP(ip net.IP) bool {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	pm.logger.Debug("checking IP against patterns",
		zap.String("ip", ip.String()),
		zap.Int("pattern_count", len(pm.ipPatterns)))

	for i, ipNet := range pm.ipPatterns {
		if ipNet.Contains(ip) {
			pm.logger.Debug("IP matched malicious pattern",
				zap.String("ip", ip.String()),
				zap.String("pattern", ipNet.String()),
				zap.Int("pattern_index", i))
			return true
		}
	}

	pm.logger.Debug("IP did not match any patterns",
		zap.String("ip", ip.String()))
	return false
}

// MatchPath checks if a path matches any malicious path patterns
func (pm *PatternManager) MatchPath(path string) bool {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	pm.logger.Debug("checking path against patterns",
		zap.String("path", path),
		zap.Int("pattern_count", len(pm.pathPatterns)))

	for i, pattern := range pm.pathPatterns {
		if pattern.MatchString(path) {
			pm.logger.Debug("path matched malicious pattern",
				zap.String("path", path),
				zap.String("pattern", pattern.String()),
				zap.Int("pattern_index", i))
			return true
		}
	}

	pm.logger.Debug("path did not match any patterns",
		zap.String("path", path))
	return false
}

// MatchUserAgent checks if a User-Agent matches any malicious UA patterns
func (pm *PatternManager) MatchUserAgent(ua string) bool {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	pm.logger.Debug("checking user-agent against patterns",
		zap.String("user_agent", ua),
		zap.Int("pattern_count", len(pm.uaPatterns)))

	for i, pattern := range pm.uaPatterns {
		if matchUserAgentPattern(ua, pattern) {
			pm.logger.Debug("user-agent matched malicious pattern",
				zap.String("user_agent", ua),
				zap.String("pattern", pattern),
				zap.Int("pattern_index", i))
			return true
		}
	}

	pm.logger.Debug("user-agent did not match any patterns",
		zap.String("user_agent", ua))
	return false
}

// matchUserAgentPattern performs pattern matching for User-Agent strings
// Supports wildcard matching with * and ** patterns
func matchUserAgentPattern(ua, pattern string) bool {
	// Handle full wildcard
	if pattern == "**" || pattern == "*" {
		return true
	}

	// Handle patterns with wildcards
	if strings.Contains(pattern, "*") {
		return matchWildcard(ua, pattern)
	}

	// Exact match
	return ua == pattern
}

// matchWildcard performs wildcard pattern matching
// Supports * (matches any characters) and ** (matches any characters including empty)
func matchWildcard(text, pattern string) bool {
	// Convert ** to * for simplicity (both match any characters)
	pattern = strings.ReplaceAll(pattern, "**", "*")

	// Split pattern by * to get literal parts
	parts := strings.Split(pattern, "*")

	// If no wildcards, do exact match
	if len(parts) == 1 {
		return text == pattern
	}

	// Check if text starts with first part (if not empty)
	if parts[0] != "" && !strings.HasPrefix(text, parts[0]) {
		return false
	}

	// Check if text ends with last part (if not empty)
	if parts[len(parts)-1] != "" && !strings.HasSuffix(text, parts[len(parts)-1]) {
		return false
	}

	// For patterns with multiple parts, check if all parts exist in order
	currentPos := 0
	for i, part := range parts {
		if part == "" {
			continue
		}

		// Find the part in the remaining text
		pos := strings.Index(text[currentPos:], part)
		if pos == -1 {
			return false
		}

		// For the first part, it must be at the beginning
		if i == 0 && currentPos+pos != 0 {
			return false
		}

		// Update position for next search
		currentPos += pos + len(part)
	}

	return true
}

// AddIPPattern adds an IP CIDR pattern to the manager
func (pm *PatternManager) AddIPPattern(cidr string) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}

	pm.ipPatterns = append(pm.ipPatterns, ipNet)
	return nil
}

// AddPathPattern adds a path regex pattern to the manager
func (pm *PatternManager) AddPathPattern(pattern string) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	regex, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}

	pm.pathPatterns = append(pm.pathPatterns, regex)
	return nil
}

// AddUserAgentPattern adds a User-Agent pattern to the manager
func (pm *PatternManager) AddUserAgentPattern(pattern string) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	pm.uaPatterns = append(pm.uaPatterns, pattern)
}

// GetPatternCounts returns the number of patterns loaded
func (pm *PatternManager) GetPatternCounts() (int, int, int) {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	return len(pm.ipPatterns), len(pm.pathPatterns), len(pm.uaPatterns)
}

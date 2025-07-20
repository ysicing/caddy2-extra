package gfwreport

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"
)

const (
	// DefaultQueueSize is the default size for the analysis queue
	DefaultQueueSize = 1000
	
	// DefaultWorkerCount is the default number of worker goroutines
	DefaultWorkerCount = 4
)

// RequestAnalyzer handles asynchronous analysis of HTTP requests
type RequestAnalyzer struct {
	queue        chan *RequestInfo
	patternMgr   *PatternManager
	reporter     *EventReporter
	workers      int
	logger       *zap.Logger
	errorHandler *ErrorHandler
	
	// Lifecycle management
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	stopOnce sync.Once
}

// NewRequestAnalyzer creates a new RequestAnalyzer instance
func NewRequestAnalyzer(patternMgr *PatternManager, reporter *EventReporter, logger *zap.Logger) *RequestAnalyzer {
	return &RequestAnalyzer{
		queue:        make(chan *RequestInfo, DefaultQueueSize),
		patternMgr:   patternMgr,
		reporter:     reporter,
		workers:      DefaultWorkerCount,
		logger:       logger,
		errorHandler: NewErrorHandler(logger),
	}
}

// Start begins the asynchronous request analysis process
func (ra *RequestAnalyzer) Start(ctx context.Context) error {
	ra.ctx, ra.cancel = context.WithCancel(ctx)
	
	// Start worker goroutines
	for i := 0; i < ra.workers; i++ {
		ra.wg.Add(1)
		go ra.worker(i)
	}
	
	ra.logger.Info("request analyzer started", 
		zap.Int("workers", ra.workers),
		zap.Int("queue_size", DefaultQueueSize))
	
	return nil
}

// Stop gracefully shuts down the request analyzer
func (ra *RequestAnalyzer) Stop() error {
	ra.stopOnce.Do(func() {
		if ra.cancel != nil {
			ra.cancel()
		}
		
		// Close the queue to signal workers to stop
		close(ra.queue)
		
		// Wait for all workers to finish
		ra.wg.Wait()
		
		ra.logger.Info("request analyzer stopped")
	})
	
	return nil
}

// AnalyzeRequest submits a request for asynchronous analysis
func (ra *RequestAnalyzer) AnalyzeRequest(info *RequestInfo) {
	// Set timestamp if not already set
	if info.Timestamp.IsZero() {
		info.Timestamp = time.Now()
	}
	
	ra.logger.Debug("submitting request for analysis",
		zap.String("ip", info.IP.String()),
		zap.String("path", info.Path),
		zap.String("method", info.Method),
		zap.String("user_agent", info.UserAgent),
		zap.Time("timestamp", info.Timestamp))
	
	select {
	case ra.queue <- info:
		// Successfully queued
		ra.logger.Debug("request queued for analysis",
			zap.String("ip", info.IP.String()),
			zap.String("path", info.Path),
			zap.Int("queue_length", len(ra.queue)))
	default:
		// Queue is full, drop the request and log warning
		ra.logger.Warn("analysis queue full, dropping request",
			zap.String("ip", info.IP.String()),
			zap.String("path", info.Path),
			zap.String("method", info.Method),
			zap.Int("queue_capacity", cap(ra.queue)),
			zap.String("action", "request_dropped"))
	}
}

// worker processes requests from the analysis queue
func (ra *RequestAnalyzer) worker(id int) {
	defer ra.wg.Done()
	
	ra.logger.Debug("worker started", zap.Int("worker_id", id))
	
	for {
		select {
		case <-ra.ctx.Done():
			ra.logger.Debug("worker stopping due to context cancellation", zap.Int("worker_id", id))
			return
			
		case info, ok := <-ra.queue:
			if !ok {
				ra.logger.Debug("worker stopping due to queue closure", zap.Int("worker_id", id))
				return
			}
			
			ra.processRequest(info)
		}
	}
}

// processRequest analyzes a single request for threats
func (ra *RequestAnalyzer) processRequest(info *RequestInfo) {
	ra.errorHandler.RecoverFromPanic(func() {
		ra.analyzeRequestForThreats(info)
	}, "request_analysis")
}

// analyzeRequestForThreats performs the actual threat analysis
func (ra *RequestAnalyzer) analyzeRequestForThreats(info *RequestInfo) {
	startTime := time.Now()
	
	ra.logger.Debug("starting request analysis",
		zap.String("ip", info.IP.String()),
		zap.String("path", info.Path),
		zap.String("method", info.Method),
		zap.String("user_agent", info.UserAgent),
		zap.Time("request_timestamp", info.Timestamp))
	
	// Check for IP-based threats
	if ra.patternMgr.MatchIP(info.IP) {
		ra.logger.Info("IP threat detected",
			zap.String("ip", info.IP.String()),
			zap.String("path", info.Path),
			zap.String("method", info.Method),
			zap.String("threat_type", ThreatTypeIP),
			zap.Duration("analysis_duration", time.Since(startTime)))
		
		event := NewThreatEvent(info, ThreatTypeIP)
		if err := ra.reporter.ReportThreat(event); err != nil {
			ra.errorHandler.LogError(err, "threat_reporting",
				zap.String("threat_type", ThreatTypeIP),
				zap.String("ip", info.IP.String()))
		}
		return
	}
	
	// Check for path-based threats
	if ra.patternMgr.MatchPath(info.Path) {
		ra.logger.Info("path threat detected",
			zap.String("ip", info.IP.String()),
			zap.String("path", info.Path),
			zap.String("method", info.Method),
			zap.String("threat_type", ThreatTypePath),
			zap.Duration("analysis_duration", time.Since(startTime)))
		
		event := NewThreatEvent(info, ThreatTypePath)
		if err := ra.reporter.ReportThreat(event); err != nil {
			ra.errorHandler.LogError(err, "threat_reporting",
				zap.String("threat_type", ThreatTypePath),
				zap.String("path", info.Path))
		}
		return
	}
	
	// Check for User-Agent-based threats
	if ra.patternMgr.MatchUserAgent(info.UserAgent) {
		ra.logger.Info("user-agent threat detected",
			zap.String("ip", info.IP.String()),
			zap.String("path", info.Path),
			zap.String("user_agent", info.UserAgent),
			zap.String("threat_type", ThreatTypeUserAgent),
			zap.Duration("analysis_duration", time.Since(startTime)))
		
		event := NewThreatEvent(info, ThreatTypeUserAgent)
		if err := ra.reporter.ReportThreat(event); err != nil {
			ra.errorHandler.LogError(err, "threat_reporting",
				zap.String("threat_type", ThreatTypeUserAgent),
				zap.String("user_agent", info.UserAgent))
		}
		return
	}
	
	// No threats detected - log as debug
	ra.logger.Debug("request analyzed - no threats detected",
		zap.String("ip", info.IP.String()),
		zap.String("path", info.Path),
		zap.String("method", info.Method),
		zap.String("user_agent", info.UserAgent),
		zap.Duration("analysis_duration", time.Since(startTime)),
		zap.String("result", "clean"))
}

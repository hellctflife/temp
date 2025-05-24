package middleware

import (
	"context"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type IPAttemptTracker struct {
	attempts     map[string]*IPAttemptInfo
	mu           sync.RWMutex
	cleanupEvery time.Duration
}

type IPAttemptInfo struct {
	Count      int
	LastAttempt time.Time
	Blocked    bool
}

func NewIPAttemptTracker() *IPAttemptTracker {
	tracker := &IPAttemptTracker{
		attempts:     make(map[string]*IPAttemptInfo),
		cleanupEvery: 5 * time.Minute,
	}
	
	go tracker.startCleanup()
	
	return tracker
}

func (t *IPAttemptTracker) startCleanup() {
	ticker := time.NewTicker(t.cleanupEvery)
	defer ticker.Stop()
	
	for range ticker.C {
		t.cleanOldEntries()
	}
}

func (t *IPAttemptTracker) cleanOldEntries() {
	t.mu.Lock()
	defer t.mu.Unlock()
	
	expiry := time.Now().Add(-30 * time.Second)
	for ip, info := range t.attempts {
		if info.LastAttempt.Before(expiry) {
			delete(t.attempts, ip)
		}
	}
}

func (t *IPAttemptTracker) RecordAttempt(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	
	info, exists := t.attempts[ip]
	if !exists {
		info = &IPAttemptInfo{}
		t.attempts[ip] = info
	}
	
	info.Count++
	info.LastAttempt = time.Now()
	
	if info.Count > 5 {
		info.Blocked = true
	}
}

func (t *IPAttemptTracker) ShouldDelay(ip string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	
	info, exists := t.attempts[ip]
	if !exists {
		return false
	}
	
	return info.Blocked
}

type RequestMiddleware struct {
	logger        *zap.Logger
	attemptTracker *IPAttemptTracker
}

func NewRequestMiddleware(logger *zap.Logger) *RequestMiddleware {
	return &RequestMiddleware{
		logger:        logger,
		attemptTracker: NewIPAttemptTracker(),
	}
}

func (rm *RequestMiddleware) ProcessRequest() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := uuid.New().String()
		ctx := context.WithValue(c.Request.Context(), "request_id", requestID)
		c.Request = c.Request.WithContext(ctx)
		c.Header("X-Request-ID", requestID)
		start := time.Now()
		rm.logger.Info("Request started",
			zap.String("request_id", requestID),
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
			zap.String("client_ip", c.ClientIP()),
			zap.String("user_agent", c.Request.UserAgent()))
		c.Next()
		duration := time.Since(start)
		rm.logger.Info("Request completed",
			zap.String("request_id", requestID),
			zap.Int("status", c.Writer.Status()),
			zap.Duration("duration", duration),
			zap.Int("size", c.Writer.Size()))
	}
}

func (rm *RequestMiddleware) LoginAttemptMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == "POST" && c.FullPath() == "/login" {
			clientIP := c.ClientIP()
			rm.attemptTracker.RecordAttempt(clientIP)
			if rm.attemptTracker.ShouldDelay(clientIP) {
				rm.logger.Warn("Delaying key loading due to suspicious activity",
					zap.String("client_ip", clientIP),
					zap.String("path", c.FullPath()))
				ctx := context.WithValue(c.Request.Context(), "delay_key_loading", true)
				c.Request = c.Request.WithContext(ctx)
			}
		}
		c.Next()
	}
}

func (rm *RequestMiddleware) RecoverPanic() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				requestID, _ := c.Request.Context().Value("request_id").(string)
				rm.logger.Error("Panic recovered",
					zap.String("request_id", requestID),
					zap.Any("error", err),
					zap.Stack("stack"))
				c.AbortWithStatusJSON(500, gin.H{
					"error": "Internal server error",
				})
			}
		}()
		c.Next()
	}
}
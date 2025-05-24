package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type LoggingMiddleware struct {
	logger *zap.Logger
}

func NewLoggingMiddleware(logger *zap.Logger) *LoggingMiddleware {
	return &LoggingMiddleware{
		logger: logger,
	}
}

func (lm *LoggingMiddleware) LogRequest() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		duration := time.Since(start)

		if c.Request.URL.Path[:7] == "/static" {
			return
		}

		userID, exists := c.Get("userID")

		if exists {
			lm.logger.Info("HTTP Request",
				zap.String("method", c.Request.Method),
				zap.String("path", c.Request.URL.Path),
				zap.Int("status", c.Writer.Status()),
				zap.Duration("duration", duration),
				zap.Int("user_id", userID.(int)),
				zap.String("client_ip", c.ClientIP()))
		} else {
			lm.logger.Info("HTTP Request",
				zap.String("method", c.Request.Method),
				zap.String("path", c.Request.URL.Path),
				zap.Int("status", c.Writer.Status()),
				zap.Duration("duration", duration),
				zap.String("client_ip", c.ClientIP()))
		}
	}
}
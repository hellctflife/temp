

package logger

import (
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)


func NewLogger(environment string) (*zap.Logger, error) {
	var config zap.Config
	
	if environment == "production" {
		config = zap.NewProductionConfig()
		config.DisableCaller = false
		config.DisableStacktrace = false
	} else {
		config = zap.NewDevelopmentConfig()
		config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}
	
	
	config.OutputPaths = []string{"stdout"}
	config.ErrorOutputPaths = []string{"stderr"}
	
	
	config.EncoderConfig.TimeKey = "timestamp"
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	
	
	logger, err := config.Build()
	if err != nil {
		return nil, err
	}
	
	
	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel != "" {
		var level zapcore.Level
		if err := level.UnmarshalText([]byte(logLevel)); err == nil {
			config.Level.SetLevel(level)
		}
	}
	
	return logger, nil
}
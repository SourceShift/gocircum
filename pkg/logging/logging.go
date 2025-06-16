package logging

import (
	"os"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var globalLogger Logger

func init() {
	// Initialize with a default logger.
	// This can be replaced by calling InitLogger.
	cfg := zap.NewProductionConfig()
	level := os.Getenv("LOG_LEVEL")
	if level != "" {
		var zapLevel zapcore.Level
		if err := zapLevel.UnmarshalText([]byte(level)); err == nil {
			cfg.Level = zap.NewAtomicLevelAt(zapLevel)
		}
	}

	logger, err := cfg.Build()
	if err != nil {
		panic(err)
	}
	globalLogger = &zapLogger{logger.Sugar()}
}

// InitLogger initializes the global logger with a specific configuration.
func InitLogger(level string, format string, output zapcore.WriteSyncer) {
	var cfg zap.Config
	if format == "json" {
		cfg = zap.NewProductionConfig()
	} else {
		cfg = zap.NewDevelopmentConfig()
		cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}

	if level != "" {
		var zapLevel zapcore.Level
		if err := zapLevel.UnmarshalText([]byte(strings.ToLower(level))); err == nil {
			cfg.Level = zap.NewAtomicLevelAt(zapLevel)
		}
	}

	logger, err := cfg.Build()
	if err != nil {
		panic(err)
	}

	if output != nil {
		logger = zap.New(logger.Core(), zap.WrapCore(func(c zapcore.Core) zapcore.Core {
			encoder := zapcore.NewConsoleEncoder(cfg.EncoderConfig)
			return zapcore.NewCore(encoder, output, cfg.Level)
		}))
	}
	globalLogger = &zapLogger{logger.Sugar()}
}

// GetLogger returns the global logger instance.
func GetLogger() Logger {
	return globalLogger
}

// zapLogger is a wrapper around zap.SugaredLogger that implements our Logger interface.
type zapLogger struct {
	*zap.SugaredLogger
}

func (l *zapLogger) Debug(msg string, keysAndValues ...interface{}) {
	l.SugaredLogger.Debugw(msg, keysAndValues...)
}

func (l *zapLogger) Info(msg string, keysAndValues ...interface{}) {
	l.SugaredLogger.Infow(msg, keysAndValues...)
}

func (l *zapLogger) Warn(msg string, keysAndValues ...interface{}) {
	l.SugaredLogger.Warnw(msg, keysAndValues...)
}

func (l *zapLogger) Error(msg string, keysAndValues ...interface{}) {
	l.SugaredLogger.Errorw(msg, keysAndValues...)
}

// With creates a child logger and adds structured context to it.
func (l *zapLogger) With(keysAndValues ...interface{}) Logger {
	return &zapLogger{l.SugaredLogger.With(keysAndValues...)}
}

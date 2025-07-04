package testutils

import (
	"io"

	"github.com/gocircum/gocircum/pkg/logging"

	"go.uber.org/zap/zapcore"
)

// NewTestLogger creates a new logger for testing that discards output.
func NewTestLogger() logging.Logger {
	logging.InitLogger("debug", "dev", zapcore.AddSync(io.Discard))
	return logging.GetLogger()
}

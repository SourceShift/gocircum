//go:generate mockgen -package=mocks -destination=../../mocks/mock_logger.go gocircum/pkg/logging Logger

package logging

// Logger defines a common interface for logging.
// This is used to allow for mock loggers in tests.
type Logger interface {
	Debug(msg string, keysAndValues ...interface{})
	Info(msg string, keysAndValues ...interface{})
	Warn(msg string, keysAndValues ...interface{})
	Error(msg string, keysAndValues ...interface{})
	With(keysAndValues ...interface{}) Logger
}

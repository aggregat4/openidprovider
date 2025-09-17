package logging

import (
	"os"

	"github.com/willibrandon/mtlog"
	"github.com/willibrandon/mtlog/core"
)

// Logger exposes the default application logger configured for console output.
var Logger = mtlog.New(
	mtlog.WithConsole(),
	mtlog.WithMinimumLevel(core.InformationLevel),
)

// New creates a logger instance using the standard configuration.
func New() core.Logger {
	return mtlog.New(
		mtlog.WithConsole(),
		mtlog.WithMinimumLevel(core.InformationLevel),
	)
}

// ForComponent returns a logger enriched with a static component name.
func ForComponent(name string) core.Logger {
	return Logger.With("component", name)
}

// Info logs at information level using mtlog message templates.
func Info(logger core.Logger, template string, args ...any) {
	logger.Info(template, args...)
}

// Debug logs at debug level using mtlog message templates.
func Debug(logger core.Logger, template string, args ...any) {
	logger.Debug(template, args...)
}

// Error logs at error level using mtlog message templates.
func Error(logger core.Logger, template string, args ...any) {
	logger.Error(template, args...)
}

// Warn logs at warning level using mtlog message templates.
func Warn(logger core.Logger, template string, args ...any) {
	logger.Warn(template, args...)
}

// Fatal logs a message template and terminates the process.
func Fatal(logger core.Logger, template string, args ...any) {
	logger.Error(template, args...)
	os.Exit(1)
}

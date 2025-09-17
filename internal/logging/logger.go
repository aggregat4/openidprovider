package logging

import (
	"fmt"
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

// Info logs at information level using fmt-style formatting.
func Info(logger core.Logger, format string, args ...any) {
	logger.Info(render(format, args...))
}

// Debug logs at debug level using fmt-style formatting.
func Debug(logger core.Logger, format string, args ...any) {
	logger.Debug(render(format, args...))
}

// Error logs at error level using fmt-style formatting.
func Error(logger core.Logger, format string, args ...any) {
	logger.Error(render(format, args...))
}

// Warn logs at warning level using fmt-style formatting.
func Warn(logger core.Logger, format string, args ...any) {
	logger.Warn(render(format, args...))
}

// Fatal logs a formatted message and terminates the process.
func Fatal(logger core.Logger, format string, args ...any) {
	logger.Error(render(format, args...))
	os.Exit(1)
}

func render(format string, args ...any) string {
	if len(args) == 0 {
		return format
	}
	return fmt.Sprintf(format, args...)
}

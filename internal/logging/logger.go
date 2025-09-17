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

// Info logs at information level with optional structured fields.
func Info(logger core.Logger, msg string, kv ...any) {
	with(logger, kv...).Info(msg)
}

// Debug logs at debug level with optional structured fields.
func Debug(logger core.Logger, msg string, kv ...any) {
	with(logger, kv...).Debug(msg)
}

// Error logs at error level with optional structured fields.
func Error(logger core.Logger, msg string, kv ...any) {
	with(logger, kv...).Error(msg)
}

// Warn logs at warning level with optional structured fields.
func Warn(logger core.Logger, msg string, kv ...any) {
	with(logger, kv...).Warn(msg)
}

// Fatal logs a formatted message and terminates the process.
func Fatal(logger core.Logger, format string, args ...any) {
	message := format
	if len(args) > 0 {
		message = fmt.Sprintf(format, args...)
	}
	logger.Error(message)
	os.Exit(1)
}

func with(logger core.Logger, kv ...any) core.Logger {
	if len(kv) == 0 {
		return logger
	}
	return logger.With(kv...)
}

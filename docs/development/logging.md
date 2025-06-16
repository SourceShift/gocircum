# Structured Logging

This document outlines the structured logging approach used in the `gocircum` project. We use the `go.uber.org/zap` library, abstracted behind our own `pkg/logging` package, to ensure consistent, machine-readable, and highly-performant logging.

## Overview

All logging in the application should be performed using a `logging.Logger` instance. This interface provides a standard set of logging methods:

- `Debug(msg string, fields ...zap.Field)`
- `Info(msg string, fields ...zap.Field)`
- `Warn(msg string, fields ...zap.Field)`
- `Error(msg string, fields ...zap.Field)`
- `Fatal(msg string, fields ...zap.Field)`

Using these methods ensures that all log output is structured (as JSON by default) and includes important metadata like timestamps, log levels, and caller information.

## Initialization

The logger is initialized at the application's entry points (`cli/main.go` and `mobile/bridge/bridge.go`). The configuration is controlled by command-line flags in the CLI.

### CLI Configuration

The `heybabe-cli` accepts the following flags to control logging behavior:

- `--log-level`: Sets the minimum level for logs to be emitted. Can be one of `debug`, `info`, `warn`, `error`, `fatal`. (Default: `info`)
- `--log-format`: Sets the output format. Can be `json` or `console`. (Default: `json`)

Example:
```shell
./heybabe-cli proxy --log-level debug --log-format console
```

This will start the proxy with debug-level logging in a human-readable console format.

## Usage

### Getting a Logger Instance

Components like `Engine` and `Ranker` receive a `logging.Logger` instance via dependency injection. They should use this provided logger for all their logging activities.

```go
type Engine struct {
    // ... other fields
    logger logging.Logger
}

func (e *Engine) SomeMethod() {
    e.logger.Info("Starting some method", zap.String("param", "value"))
}
```

### Adding Context with Fields

The primary benefit of structured logging is the ability to add key-value context to your log messages. This makes them easily searchable and filterable in log analysis platforms.

You should add relevant fields to every log message. The `go.uber.org/zap` package provides typed `Field` constructors for this purpose.

**✅ DO:**
```go
// Use strong types like zap.Error, zap.String, zap.Int, etc.
logger.Error("Failed to connect to address",
    zap.Error(err),
    zap.String("address", addr),
    zap.Int("attempt", attempt),
)
```

**❌ DON'T:**
```go
// Avoid using fmt.Sprintf to format log messages.
// This loses the structured context.
logger.Error(fmt.Sprintf("Failed to connect to %s: %v", addr, err))
```

### Logging Errors

Always use `zap.Error(err)` to log an error object. This ensures the full error message and potentially a stack trace (at `Debug` level) are captured correctly.

### Choosing the Right Log Level

- `Debug`: Verbose information useful for deep debugging. This includes things like function entry/exit, detailed state, etc. Should be disabled in production unless actively troubleshooting.
- `Info`: General application flow and state messages. Confirms that things are working as expected.
- `Warn`: Indicates a potential problem or an unexpected situation that doesn't prevent the current operation from completing but might require attention.
- `Error`: A significant failure that prevents the current operation from completing but doesn't crash the application.
- `Fatal`: An error so critical that the application cannot continue. Calling `Fatal` will terminate the program after writing the log message. 
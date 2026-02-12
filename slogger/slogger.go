package slogger

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/fatih/color"
	"github.com/google/uuid"
)

const (
	LevelFatal = slog.Level(12)
)

var (
	Log        *slog.Logger // Log is a global slogger instance used across the application.
	LevelNames = map[slog.Leveler]string{
		LevelFatal: "FATAL",
	}
)

// NewPrettyHandler creates a new PrettyHandler with a given output writer and options.
func NewPrettyHandler(
	out io.Writer,
	opts PrettyHandlerOptions,
) *PrettyHandler {
	h := &PrettyHandler{
		Handler: slog.NewJSONHandler(out, &opts.SlogOpts),
		l:       log.New(out, "", 0),
	}

	return h
}

// PrettyHandlerOptions contains options specific to the PrettyHandler, mainly around slog handling.
type PrettyHandlerOptions struct {
	SlogOpts slog.HandlerOptions
}

// PrettyHandler implements slog.Handler and provides a structured, colored logging output.
type PrettyHandler struct {
	slog.Handler
	l *log.Logger
}

// MakeLogger initializes and configures the global slogger instance.
func MakeLogger(debug bool) {

	level := slog.LevelDebug
	if !debug {
		level = slog.LevelInfo
	}
	opts := PrettyHandlerOptions{
		SlogOpts: slog.HandlerOptions{
			Level:     level,
			AddSource: true,
		},
	}

	handler := NewPrettyHandler(os.Stdout, opts)
	Log = slog.New(handler)

}

// Handle processes a single log record, formats it, and outputs it to the configured io.Writer.
func (h *PrettyHandler) Handle(ctx context.Context, r slog.Record) error {
	// Change color based on log level
	level := r.Level.String()

	customeLevelName, ok := LevelNames[r.Level]
	if ok {
		level = customeLevelName
	}

	switch r.Level {
	case slog.LevelDebug:
		level = color.MagentaString(level)
	case slog.LevelInfo:
		level = color.GreenString(level + " ")
	case slog.LevelWarn:
		level = color.YellowString(level + " ")
	case slog.LevelError:
		level = color.RedString(level)
	case LevelFatal:
		level = color.RedString(level)

	}

	// Collect log attributes
	fields := make(map[string]interface{}, r.NumAttrs())

	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "err" && a.Value.Any() != nil {
			err, ok := a.Value.Any().(error)
			if ok {
				fields[a.Key] = err.Error()
			} else {
				fields[a.Key] = a.Value.Any()
			}
		} else {
			fields[a.Key] = a.Value.Any()
		}
		return true
	})

	// Capture the source from runtime call stack
	source := make(map[string]interface{}, r.NumAttrs())

	fs := runtime.CallersFrames([]uintptr{r.PC})
	frame, _ := fs.Next()
	source["file"] = filepath.Base(frame.File)
	source["line"] = frame.Line
	source["func"] = color.CyanString(filepath.Base(frame.Function))

	// Format the timestamp
	timeStr := color.GreenString(r.Time.Format(time.DateTime))
	msg := color.BlueString(r.Message)

	// Check for a trace ID in the context and add it to the log fields if present
	traceID, ok := ctx.Value("trace-id").(uuid.UUID)
	if ok {
		fields["trace-id"] = traceID
	}
	b, err := json.MarshalIndent(fields, "", "  ")
	if err != nil {
		return err
	}

	// Print the formatted log entry
	h.l.Printf("%v | %v | %v | %v | %v:%v %v", timeStr, level, msg, source["func"], source["file"], source["line"], string(b))

	return nil
}

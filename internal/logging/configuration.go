package logging

import (
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/x"
)

func NewLogger(conf config.LoggingConfig) zerolog.Logger {
	if conf.Format == config.LogTextFormat {
		return zerolog.New(zerolog.NewConsoleWriter(func(w *zerolog.ConsoleWriter) {
			w.TimeFormat = time.RFC3339
		})).Level(conf.Level).With().Timestamp().Logger()
	}

	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.TimestampFieldName = "timestamp"
	zerolog.LevelFieldName = "_level_name"
	zerolog.LevelFieldMarshalFunc = func(l zerolog.Level) string {
		return strings.ToUpper(l.String())
	}
	zerolog.MessageFieldName = "short_message"
	zerolog.ErrorFieldName = "full_message"
	zerolog.CallerFieldName = "_caller"
	hostname, err := os.Hostname()

	return zerolog.New(os.Stdout).Level(conf.Level).With().
		Str("version", "1.1").
		Str("host", x.IfThenElse(err != nil, hostname, "unknown")).
		Timestamp().
		Caller().
		Logger().
		Hook(zerolog.HookFunc(func(e *zerolog.Event, level zerolog.Level, message string) {
			if level != zerolog.NoLevel {
				e.Int8("level", int8(toSyslogLevel(level)))
			}
		}))
}

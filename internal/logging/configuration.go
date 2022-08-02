package logging

import (
	"fmt"
	"os"
	"strings"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/config"
)

func NewLogger(conf config.LoggingConfig) zerolog.Logger {
	if conf.Format == config.LogTextFormat {
		return zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout}).Level(conf.Level)
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
	if err != nil {
		hostname = "unknown"

		// nolint
		fmt.Println("Warn: failed to retrieve the hostname: " + err.Error())
	}

	return zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout}).Level(conf.Level).With().
		Str("version", "1.1").
		Str("host", hostname).
		Timestamp().
		Caller().
		Logger().
		Hook(zerolog.HookFunc(func(e *zerolog.Event, level zerolog.Level, message string) {
			if level != zerolog.NoLevel {
				e.Int8("level", int8(toSyslogLevel(level)))
			}
		}))
}

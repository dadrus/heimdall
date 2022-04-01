package logging

import (
	"fmt"
	"os"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/dadrus/heimdall/internal/config"
)

// ConfigureLogging uses the given conf to configure the global log.Logger variable.
func ConfigureLogging(conf config.Logging) {
	if conf.Format == config.LogTextFormat {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	} else {
		zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
		zerolog.TimestampFieldName = "timestamp"
		zerolog.LevelFieldName = "_level_name"
		zerolog.LevelFieldMarshalFunc = func(l zerolog.Level) string {
			return strings.ToUpper(l.String())
		}
		zerolog.MessageFieldName = "short_message"
		zerolog.ErrorFieldName = "full_message"
		zerolog.CallerFieldName = "_caller"
		zerolog.SetGlobalLevel(conf.Level)

		hostname, err := os.Hostname()
		if err != nil {
			hostname = "unknown"
			fmt.Println("Failed to retrieve the hostname: " + err.Error())
		}

		log.Logger = zerolog.New(os.Stdout).With().
			Str("version", "1.1").
			Str("host", hostname).
			Timestamp().
			Caller().
			Logger().Hook(zerolog.HookFunc(
			func(e *zerolog.Event, level zerolog.Level, message string) {
				if level != zerolog.NoLevel {
					e.Int("level", toSyslogLevel(level))
				}
			}))
	}
}

func toSyslogLevel(level zerolog.Level) int {
	const (
		Emergency     = 0
		Alert         = 1
		Critical      = 2
		Error         = 3
		Warning       = 4
		Notice        = 5
		Informational = 6
		Debugging     = 7
	)

	switch level {
	case zerolog.DebugLevel, zerolog.TraceLevel:
		return Debugging
	case zerolog.InfoLevel:
		return Informational
	case zerolog.WarnLevel:
		return Warning
	case zerolog.ErrorLevel:
		return Error
	case zerolog.FatalLevel:
		return Critical
	case zerolog.PanicLevel:
		return Alert
	default:
		return Emergency
	}
}

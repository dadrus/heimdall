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
func ConfigureLogging(conf config.LoggingConfig) {
	zerolog.SetGlobalLevel(conf.Level)

	if conf.Format == config.LogTextFormat {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout})
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

		hostname, err := os.Hostname()
		if err != nil {
			hostname = "unknown"

			// nolint
			fmt.Println("Warn: failed to retrieve the hostname: " + err.Error())
		}

		log.Logger = zerolog.New(os.Stdout).With().
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
}

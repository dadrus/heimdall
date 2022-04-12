package jaeger

import "github.com/rs/zerolog/log"

type stdLogger struct{}

func (l *stdLogger) Error(msg string) {
	log.Error().Msg(msg)
}

// Infof logs a message at info priority.
func (l *stdLogger) Infof(msg string, args ...interface{}) {
	log.Info().Msgf(msg, args...)
}

// Debugf logs a message at debug priority.
func (l *stdLogger) Debugf(msg string, args ...interface{}) {
	log.Debug().Msgf(msg, args...)
}

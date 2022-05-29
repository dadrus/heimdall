package jaeger

import (
	"github.com/rs/zerolog"
)

type logger struct {
	l zerolog.Logger
}

func (l *logger) Error(msg string) {
	l.l.Error().Msg(msg)
}

// Infof logs a message at info priority.
func (l *logger) Infof(msg string, args ...interface{}) {
	l.l.Info().Msgf(msg, args...)
}

// Debugf logs a message at debug priority.
func (l *logger) Debugf(msg string, args ...interface{}) {
	l.l.Debug().Msgf(msg, args...)
}

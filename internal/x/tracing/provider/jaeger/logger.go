package jaeger

import (
	"fmt"

	"github.com/rs/zerolog"
)

type logger struct {
	l zerolog.Logger
}

func (l *logger) Error(msg string) {
	l.l.Error().Msg(fmt.Sprintf("jaeger: %s", msg))
}

// Infof logs a message at info priority.
func (l *logger) Infof(msg string, args ...any) {
	l.l.Info().Msg(fmt.Sprintf("jaeger: %s", fmt.Sprintf(msg, args...)))
}

// Debugf logs a message at debug priority.
func (l *logger) Debugf(msg string, args ...any) {
	l.l.Debug().Msg(fmt.Sprintf("jaeger: %s", fmt.Sprintf(msg, args...)))
}

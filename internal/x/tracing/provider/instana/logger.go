package instana

import (
	"fmt"

	"github.com/rs/zerolog"
)

type logger struct {
	l zerolog.Logger
}

func (l *logger) Debug(v ...interface{}) {
	l.l.Debug().Msg(fmt.Sprint(v...))
}

func (l *logger) Info(v ...interface{}) {
	l.l.Info().Msg(fmt.Sprint(v...))
}

func (l *logger) Warn(v ...interface{}) {
	l.l.Warn().Msg(fmt.Sprint(v...))
}

func (l *logger) Error(v ...interface{}) {
	l.l.Error().Msg(fmt.Sprint(v...))
}

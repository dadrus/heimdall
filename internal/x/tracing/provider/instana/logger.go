package instana

import (
	"fmt"

	"github.com/rs/zerolog"
)

type logger struct {
	l zerolog.Logger
}

func (l *logger) Debug(v ...any) {
	l.l.Debug().Msg(fmt.Sprintf("instana: %s", fmt.Sprint(v...)))
}

func (l *logger) Info(v ...any) {
	l.l.Info().Msg(fmt.Sprintf("instana: %s", fmt.Sprint(v...)))
}

func (l *logger) Warn(v ...any) {
	l.l.Warn().Msg(fmt.Sprintf("instana: %s", fmt.Sprint(v...)))
}

func (l *logger) Error(v ...any) {
	l.l.Error().Msg(fmt.Sprintf("instana: %s", fmt.Sprint(v...)))
}

package proxy2

import (
	stdlog "log"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/x/stringx"
)

type adapter struct {
	log zerolog.Logger
}

func newStdLogger(logger zerolog.Logger) *stdlog.Logger {
	return stdlog.New(adapter{logger}, "", 0)
}

func (a adapter) Write(p []byte) (int, error) {
	n := len(p)
	if n > 0 && p[n-1] == '\n' {
		p = p[0 : n-1]
	}

	a.log.Error().Msg(stringx.ToString(p))

	return n, nil

}

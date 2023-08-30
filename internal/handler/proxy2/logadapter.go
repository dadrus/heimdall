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

func (a adapter) Write(data []byte) (int, error) {
	length := len(data)
	if length > 0 && data[length-1] == '\n' {
		data = data[0 : length-1]
	}

	a.log.Error().Msg(stringx.ToString(data))

	return length, nil
}

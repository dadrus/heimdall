package config

import (
	"reflect"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/x"
)

type LogFormat int

const (
	LogTextFormat    = 0
	LogGelfFormat    = 1
	LogUnknownFormat = 2
)

func (f LogFormat) String() string {
	return x.IfThenElse(f == LogTextFormat, "text", "gelf")
}

func logFormatDecodeHookFunc(from reflect.Type, to reflect.Type, val any) (any, error) {
	if from.Kind() == reflect.String && to.Name() == "LogFormat" {
		return x.IfThenElse(val == "text", LogTextFormat, LogGelfFormat), nil
	}

	return val, nil
}

type LoggingConfig struct {
	Format LogFormat     `koanf:"format"`
	Level  zerolog.Level `koanf:"level"`
}

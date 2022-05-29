package config

import (
	"reflect"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/x"
)

// Decode zeroLog LogLevels from strings.
// nolint: cyclop
func logLevelDecodeHookFunc(from reflect.Type, to reflect.Type, data any) (any, error) {
	if from.Kind() != reflect.String {
		return data, nil
	}

	if to != reflect.TypeOf(zerolog.Level(0)) {
		return data, nil
	}

	switch data {
	case "panic":
		return zerolog.PanicLevel, nil
	case "fatal":
		return zerolog.FatalLevel, nil
	case "error":
		return zerolog.ErrorLevel, nil
	case "warn":
		return zerolog.WarnLevel, nil
	case "debug":
		return zerolog.DebugLevel, nil
	case "trace":
		return zerolog.TraceLevel, nil
	case "no":
		return zerolog.NoLevel, nil
	case "disabled":
		return zerolog.Disabled, nil
	case "info":
		return zerolog.InfoLevel, nil
	default:
		return zerolog.InfoLevel, nil
	}
}

func logFormatDecodeHookFunc(from reflect.Type, to reflect.Type, val any) (any, error) {
	if from.Kind() == reflect.String && to.Name() == "LogFormat" {
		return x.IfThenElse(val == "gelf", LogGelfFormat, LogTextFormat), nil
	}

	return val, nil
}

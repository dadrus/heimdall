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

func logFormatDecodeHookFunc(from reflect.Type, to reflect.Type, val interface{}) (interface{}, error) {
	var format LogFormat

	if from.Kind() != reflect.String {
		return val, nil
	}

	dect := reflect.ValueOf(&format).Elem().Type()
	if !dect.AssignableTo(to) {
		return val, nil
	}

	return x.IfThenElse(val == "gelf", LogGelfFormat, LogTextFormat), nil
}

type Logging struct {
	Format            LogFormat     `koanf:"format"`
	Level             zerolog.Level `koanf:"level"`
	LeakSensitiveData bool          `koanf:"leak_sensitive_data"`
}

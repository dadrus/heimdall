package config

import (
	"reflect"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/x"
)

type LogFormat int

const (
	LogTextFormat    = 0
	LogJsonFormat    = 1
	LogUnknownFormat = 2
)

func (f LogFormat) String() string {
	return x.IfThenElse(f == LogTextFormat, "text", "json")
}

func logFormatDecode(from reflect.Type, to reflect.Type, val interface{}) (interface{}, error) {
	if from.Kind() == reflect.String && to.Name() == "LogFormat" {
		return x.IfThenElse(val == "text", LogTextFormat, LogJsonFormat), nil
	}

	return val, nil
}

type Logging struct {
	Format            LogFormat     `koanf:"format"`
	Level             zerolog.Level `koanf:"level"`
	LeakSensitiveData bool          `koanf:"leak_sensitive_data"`
}

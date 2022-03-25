package config

import (
	"reflect"

	"github.com/rs/zerolog"
)

type LogFormat int

const (
	LogTextFormat    = 0
	LogJsonFormat    = 1
	LogUnknownFormat = 2
)

func (f LogFormat) String() string {
	if f == LogTextFormat {
		return "text"
	} else {
		return "json"
	}
}

func logFormatDecode(from reflect.Type, to reflect.Type, v interface{}) (interface{}, error) {
	if from.Kind() == reflect.String && to.Name() == "LogFormat" {
		if v == "text" {
			return LogTextFormat, nil
		} else {
			return LogJsonFormat, nil
		}
	}
	return v, nil
}

type Logging struct {
	Format            LogFormat     `koanf:"format"`
	Level             zerolog.Level `koanf:"level"`
	LeakSensitiveData bool          `koanf:"leak_sensitive_data"`
}

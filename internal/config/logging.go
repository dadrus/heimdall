package config

import (
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/x"
)

type LogFormat int

const (
	LogTextFormat LogFormat = iota
	LogGelfFormat
)

func (f LogFormat) String() string { return x.IfThenElse(f == LogTextFormat, "text", "gelf") }

type LoggingConfig struct {
	Format LogFormat     `koanf:"format,string"`
	Level  zerolog.Level `koanf:"level,string"`
}

func LogConfiguration(configuration *Configuration) LoggingConfig { return configuration.Log }

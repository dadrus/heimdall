package logging

import (
	"github.com/rs/zerolog"
)

type LogConfig struct {
	Format            LogFormat     `koanf:"format"`
	Level             zerolog.Level `koanf:"level"`
	LeakSensitiveData bool          `koanf:"leak_sensitive_data"`
}

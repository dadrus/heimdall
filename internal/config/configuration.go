package config

import (
	"time"

	"github.com/rs/zerolog"
)

type Configuration struct {
	Proxy       Serve      `koanf:"serve.proxy"`
	DecisionApi Serve      `koanf:"serve.api"`
	Prometheus  Prometheus `koanf:"serve.prometheus"`
	Log         Logging    `koanf:"log"`
	Pipeline    struct {
		Authenticators []PipelineObject `koanf:"authenticators"`
		Authorizers    []PipelineObject `koanf:"authorizers"`
		Hydrators      []PipelineObject `koanf:"hydrators"`
		Mutators       []PipelineObject `koanf:"mutators"`
		ErrorHandlers  []PipelineObject `koanf:"error_handlers"`
	} `koanf:"pipeline"`
	Rules struct {
		Default   Pipeline `koanf:"default"`
		Providers struct {
			File struct {
				Src   string `koanf:"src"`
				Watch bool   `koanf:"watch"`
			} `koanf:"file"`
		} `koanf:"providers"`
	} `koanf:"rules"`
}

func NewConfiguration(configFile string) Configuration {
	// defaults
	result := Configuration{
		Proxy: Serve{
			Port: 4455,
			Timeout: Timeout{
				Read:  time.Second * 5,
				Write: time.Second * 10,
				Idle:  time.Second * 120,
			},
		},
		DecisionApi: Serve{
			Port: 4456,
			Timeout: Timeout{
				Read:  time.Second * 5,
				Write: time.Second * 10,
				Idle:  time.Second * 120,
			},
		},
		Prometheus: Prometheus{
			Port:                 9000,
			MetricsPath:          "/metrics",
			CollapseRequestPaths: true,
		},
		Log: Logging{
			Level:             zerolog.DebugLevel,
			Format:            LogTextFormat,
			LeakSensitiveData: false,
		},
	}
	err := LoadConfig(&result, configFile)
	if err != nil {
		panic(err)
	}
	return result
}

func LogConfiguration(configuration Configuration) Logging {
	return configuration.Log
}

package config

import (
	"time"

	"github.com/rs/zerolog"
)

const (
	defaultReadTimeout  = time.Second * 5
	defaultWriteTimeout = time.Second * 10
	defaultIdleTimeout  = time.Second * 120

	defaultProxyPort       = 4455
	defaultDecisionAPIPort = 4456
	defaultPrometheusPort  = 9000
)

type Configuration struct {
	Serve    ServeConfig    `koanf:"serve"`
	Log      LoggingConfig  `koanf:"log"`
	Signer   SignerConfig   `koanf:"signer"`
	Pipeline PipelineConfig `koanf:"pipeline"`
	Rules    RulesConfig    `koanf:"rules"`
}

func NewConfiguration(configFile string) Configuration {
	// defaults
	result := Configuration{
		Serve: ServeConfig{
			Proxy: ServiceConfig{
				Port: defaultProxyPort,
				Timeout: Timeout{
					Read:  defaultReadTimeout,
					Write: defaultWriteTimeout,
					Idle:  defaultIdleTimeout,
				},
			},
			DecisionAPI: ServiceConfig{
				Port: defaultDecisionAPIPort,
				Timeout: Timeout{
					Read:  defaultReadTimeout,
					Write: defaultWriteTimeout,
					Idle:  defaultIdleTimeout,
				},
			},
			Prometheus: PrometheusConfig{
				Port:        defaultPrometheusPort,
				MetricsPath: "/metrics",
			},
		},
		Log: LoggingConfig{
			Level:  zerolog.DebugLevel,
			Format: LogTextFormat,
		},
		Signer: SignerConfig{
			Name: "heimdall",
		},
	}

	err := LoadConfig(&result, configFile)
	if err != nil {
		panic(err)
	}

	return result
}

func LogConfiguration(configuration Configuration) LoggingConfig {
	return configuration.Log
}

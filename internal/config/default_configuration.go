package config

import "github.com/rs/zerolog"

// nolint: gochecknoglobals
var defaultConfig = Configuration{
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
		Level:  zerolog.ErrorLevel,
		Format: LogTextFormat,
	},
	Tracing: TracingConfig{
		ServiceName: "heimdall",
	},
	Signer: SignerConfig{
		Name: "heimdall",
	},
	Pipeline: PipelineConfig{
		Authenticators: []PipelineObject{},
		Authorizers:    []PipelineObject{},
		Hydrators:      []PipelineObject{},
		Mutators:       []PipelineObject{},
		ErrorHandlers:  []PipelineObject{},
	},
}

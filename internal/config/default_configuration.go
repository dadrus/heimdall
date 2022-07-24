package config

import (
	"time"

	"github.com/rs/zerolog"
)

const (
	defaultReadTimeout  = time.Second * 5
	defaultWriteTimeout = time.Second * 10
	defaultIdleTimeout  = time.Second * 120

	defaultProxyPort         = 4455
	defaultDecisionAPIPort   = 4456
	defaultManagementAPIPort = 4457
	defaultPrometheusPort    = 9000
)

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
		Decision: ServiceConfig{
			Port: defaultDecisionAPIPort,
			Timeout: Timeout{
				Read:  defaultReadTimeout,
				Write: defaultWriteTimeout,
				Idle:  defaultIdleTimeout,
			},
		},
		Management: ServiceConfig{
			Port: defaultManagementAPIPort,
			Timeout: Timeout{
				Read:  defaultReadTimeout,
				Write: defaultWriteTimeout,
				Idle:  defaultIdleTimeout,
			},
		},
	},
	Log: LoggingConfig{
		Level:  zerolog.ErrorLevel,
		Format: LogTextFormat,
	},
	Tracing: TracingConfig{
		ServiceName: "heimdall",
	},
	Metrics: MetricsConfig{
		Prometheus: PrometheusConfig{
			Port:        defaultPrometheusPort,
			MetricsPath: "/metrics",
		},
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

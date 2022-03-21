package config

import (
	"time"

	"github.com/dadrus/heimdall/logging"
	"github.com/rs/zerolog"
)

var DefaultConfiguration = Configuration{
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
	Log: logging.LogConfig{
		Level:             zerolog.DebugLevel,
		Format:            logging.LogTextFormat,
		LeakSensitiveData: false,
	},
}

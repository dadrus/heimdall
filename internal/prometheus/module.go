package prometheus

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"go.uber.org/fx"
)

var Module = fx.Options( //nolint:gochecknoglobals
	fx.Provide(initPrometheusRegistry),
)

func initPrometheusRegistry() (prometheus.Registerer, prometheus.Gatherer) {
	reg := prometheus.NewRegistry()

	reg.MustRegister(collectors.NewBuildInfoCollector())
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	reg.MustRegister(collectors.NewGoCollector(collectors.WithGoCollections(collectors.GoRuntimeMetricsCollection)))

	return reg, reg
}

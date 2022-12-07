package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
)

type handlerArgs struct {
	fx.In

	Registrer prometheus.Registerer
	Gatherer  prometheus.Gatherer
	Config    config.Configuration
	Logger    zerolog.Logger
}

func newHandler(args handlerArgs) http.Handler {
	args.Logger.Debug().Msg("Registering Metrics routes")

	handler := promhttp.InstrumentMetricHandler(
		args.Registrer,
		promhttp.HandlerFor(args.Gatherer, promhttp.HandlerOpts{}),
	)

	mux := http.NewServeMux()
	mux.Handle(args.Config.Metrics.Prometheus.MetricsPath, handler)

	return mux
}

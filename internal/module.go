package internal

import (
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/handler/management"
	"github.com/dadrus/heimdall/internal/handler/metrics"
	"github.com/dadrus/heimdall/internal/logging"
	"github.com/dadrus/heimdall/internal/prometheus"
	"github.com/dadrus/heimdall/internal/rules"
	"github.com/dadrus/heimdall/internal/rules/mechanisms"
	"github.com/dadrus/heimdall/internal/tracing"
)

// nolint
var Module = fx.Options(
	config.Module,
	logging.Module,
	tracing.Module,
	cache.Module,
	mechanisms.Module,
	prometheus.Module,
	rules.Module,
	management.Module,
	metrics.Module,
)

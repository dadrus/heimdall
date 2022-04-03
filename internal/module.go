package internal

import (
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/handler/prometheus"
	"github.com/dadrus/heimdall/internal/logging"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/rules"
)

// nolint
var Module = fx.Options(
	config.Module,
	logging.Module,
	cache.Module,
	pipeline.Module,
	rules.Module,
	prometheus.Module,
)

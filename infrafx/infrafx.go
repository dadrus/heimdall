package infrafx

import (
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/config"
	"github.com/dadrus/heimdall/logging"
)

var Module = fx.Options(
	config.Module,
	logging.Module,
)

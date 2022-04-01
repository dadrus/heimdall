package logging

import (
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go.uber.org/fx"
)

// nolint
var Module = fx.Options(
	fx.Invoke(ConfigureLogging),
	fx.Provide(func() zerolog.Logger { return log.Logger }),
)

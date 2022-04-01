package pipeline

import (
	"go.uber.org/fx"
)

// nolint
var Module = fx.Options(
	fx.Provide(NewHandlerFactory),
)

package config

import "go.uber.org/fx"

// nolint
var Module = fx.Options(
	fx.Provide(NewConfiguration),
	fx.Provide(LogConfiguration),
)

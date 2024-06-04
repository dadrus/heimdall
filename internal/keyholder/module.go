package keyholder

import "go.uber.org/fx"

var Module = fx.Options( // nolint: gochecknoglobals
	fx.Provide(newRegistry),
)

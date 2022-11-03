package cloudblob

import "go.uber.org/fx"

// Module is used on app bootstrap.
// nolint: gochecknoglobals
var Module = fx.Options(
	fx.Invoke(registerProvider),
)

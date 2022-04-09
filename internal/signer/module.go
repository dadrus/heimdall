package signer

import "go.uber.org/fx"

// nolint
var Module = fx.Options(
	fx.Provide(newJWTSigner),
)

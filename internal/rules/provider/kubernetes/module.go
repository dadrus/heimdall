package kubernetes

import (
	"go.uber.org/fx"
	"k8s.io/client-go/rest"
)

// Module is used on app bootstrap.
// nolint: gochecknoglobals
var Module = fx.Options(
	fx.Provide(func() ConfigFactory { return rest.InClusterConfig }),
	fx.Invoke(registerProvider),
)

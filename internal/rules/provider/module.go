package provider

import "go.uber.org/fx"

// nolint
var Module = fx.Options(
	fx.Invoke(
		registerFileSystemProvider,
		registerDockerProvider,
		registerK8sConfigMapProvider,
	),
)

package provider

import "go.uber.org/fx"

var Module = fx.Options(
	fx.Invoke(
		registerFileSystemProvider,
		registerDockerProvider,
		registerK8sConfigMapProvider,
	),
)

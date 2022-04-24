package filesystem

import "go.uber.org/fx"

// nolint: gochecknoglobals
var Module = fx.Options(
	fx.Invoke(registerFileSystemProvider),
)

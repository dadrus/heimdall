package watcher

import (
	"context"

	"go.uber.org/fx"
)

// Module is used on app bootstrap.
// nolint: gochecknoglobals
var Module = fx.Options(
	fx.Provide(
		fx.Annotate(
			newWatcher,
			fx.OnStart(func(ctx context.Context, w *watcher) error { return w.Start(ctx) }),
			fx.OnStop(func(ctx context.Context, w *watcher) error { return w.Stop(ctx) }),
		),
		func(w *watcher) Watcher { return w },
	),
)

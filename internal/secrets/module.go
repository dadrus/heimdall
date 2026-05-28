package secrets

import (
	"context"

	"go.uber.org/fx"
)

var Module = fx.Module( //nolint:gochecknoglobals
	"secrets",
	fx.Provide(
		fx.Private,
		fx.Annotate(
			NewManager,
			fx.OnStart(func(ctx context.Context, manager Manager) error { return manager.Start(ctx) }),
			fx.OnStop(func(ctx context.Context, manager Manager) error { return manager.Stop(ctx) }),
		),
	),
	fx.Provide(
		func(manager Manager) Resolver { return manager.Resolver() },
		func(manager Manager) ScopedResolverFactory { return manager.ScopedResolverFactory() },
	),
)

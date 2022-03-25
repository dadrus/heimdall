package rules

import (
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/rules/provider"
)

var Module = fx.Options(
	fx.Provide(NewRepository),
	fx.Provide(func() provider.RuleSetChangedEventQueue {
		return make(provider.RuleSetChangedEventQueue, 20)
	}),
	provider.Module,
)

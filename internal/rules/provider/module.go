package provider

import (
	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/rules/provider/filesystem"
)

// nolint
var Module = fx.Options(
	fx.Invoke(checkRuleProvider),
	filesystem.Module,
)

func checkRuleProvider(logger zerolog.Logger, c config.Configuration) {
	if c.Rules.Provider.File == nil {
		logger.Warn().Msg("No rule provider configured. Only defaults will be used.")
	}
}

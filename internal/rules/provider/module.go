package provider

import (
	"github.com/dadrus/heimdall/internal/rules/provider/httpendpoint"
	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/rules/provider/filesystem"
)

// Module is used on app bootstrap.
// nolint: gochecknoglobals
var Module = fx.Options(
	fx.Invoke(checkRuleProvider),
	filesystem.Module,
	httpendpoint.Module,
)

func checkRuleProvider(logger zerolog.Logger, c config.Configuration) {
	var ruleProviderConfigured bool

	switch {
	case c.Rules.Providers.FileSystem != nil:
		ruleProviderConfigured = true
	case c.Rules.Providers.HTTPEndpoint != nil:
		ruleProviderConfigured = true
	}

	if !ruleProviderConfigured {
		logger.Warn().Msg("No rule provider configured. Only defaults will be used.")
	}
}

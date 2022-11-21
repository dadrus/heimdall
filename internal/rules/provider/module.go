package provider

import (
	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/rules/provider/cloudblob"
	"github.com/dadrus/heimdall/internal/rules/provider/filesystem"
	"github.com/dadrus/heimdall/internal/rules/provider/httpendpoint"
	"github.com/dadrus/heimdall/internal/rules/provider/kubernetes"
)

// Module is used on app bootstrap.
// nolint: gochecknoglobals
var Module = fx.Options(
	fx.Invoke(checkRuleProvider),
	filesystem.Module,
	httpendpoint.Module,
	cloudblob.Module,
	kubernetes.Module,
)

func checkRuleProvider(logger zerolog.Logger, conf config.Configuration) {
	var ruleProviderConfigured bool

	switch {
	case conf.Rules.Providers.FileSystem != nil:
		ruleProviderConfigured = true
	case conf.Rules.Providers.HTTPEndpoint != nil:
		ruleProviderConfigured = true
	case conf.Rules.Providers.CloudBlob != nil:
		ruleProviderConfigured = true
	case conf.Rules.Providers.Kubernetes != nil:
		ruleProviderConfigured = true
	}

	if !ruleProviderConfigured {
		logger.Warn().Msg("No rule provider configured. Only defaults will be used.")
	}
}

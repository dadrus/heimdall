package flags

import (
	"github.com/spf13/cobra"

	"github.com/dadrus/heimdall/internal/config"
)

func EnforcementSettings(cmd *cobra.Command) config.EnforcementSettings {
	insecure, _ := cmd.Flags().GetBool(SkipAllSecurityEnforcement)
	insecureDefaultRule, _ := cmd.Flags().GetBool(SkipSecureDefaultRuleEnforcement)
	insecureTrustedProxies, _ := cmd.Flags().GetBool(SkipSecureTrustedProxiesEnforcement)
	insecureNotTLS, _ := cmd.Flags().GetBool(SkipAllTLSEnforcement)
	insecureNoIngressTLS, _ := cmd.Flags().GetBool(SkipIngressTLSEnforcement)
	insecureNoEgressTLS, _ := cmd.Flags().GetBool(SkipEgressTLSEnforcement)
	insecureNoUpstreamTLS, _ := cmd.Flags().GetBool(SkipUpstreamTLSEnforcement)

	if insecure {
		insecureDefaultRule = true
		insecureNotTLS = true
		insecureTrustedProxies = true
	}

	if insecureNotTLS {
		insecureNoIngressTLS = true
		insecureNoEgressTLS = true
		insecureNoUpstreamTLS = true
	}

	return config.EnforcementSettings{
		EnforceSecureDefaultRule:    !insecureDefaultRule,
		EnforceSecureTrustedProxies: !insecureTrustedProxies,
		EnforceIngressTLS:           !insecureNoIngressTLS,
		EnforceEgressTLS:            !insecureNoEgressTLS,
		EnforceUpstreamTLS:          !insecureNoUpstreamTLS,
	}
}

package flags

import (
	"github.com/spf13/cobra"

	"github.com/dadrus/heimdall/internal/config"
)

func EnforcementSettings(cmd *cobra.Command) config.EnforcementSettings {
	insecure, _ := cmd.Flags().GetBool(SkipAllSecurityEnforcement)
	insecureNotTLS, _ := cmd.Flags().GetBool(SkipAllTLSEnforcement)
	insecureDefaultRule, _ := cmd.Flags().GetBool(SkipSecureDefaultRuleEnforcement)
	insecureNoIngressTLS, _ := cmd.Flags().GetBool(SkipIngressTLSEnforcement)
	insecureNoEgressTLS, _ := cmd.Flags().GetBool(SkipEgressTLSEnforcement)
	insecureNoUpstreamTLS, _ := cmd.Flags().GetBool(SkipUpstreamTLSEnforcement)

	if insecure {
		insecureDefaultRule = true
		insecureNotTLS = true
	}

	if insecureNotTLS {
		insecureNoIngressTLS = true
		insecureNoEgressTLS = true
		insecureNoUpstreamTLS = true
	}

	return config.EnforcementSettings{
		EnforceSecureDefaultRule: !insecureDefaultRule,
		EnforceIngressTLS:        !insecureNoIngressTLS,
		EnforceEgressTLS:         !insecureNoEgressTLS,
		EnforceUpstreamTLS:       !insecureNoUpstreamTLS,
	}
}

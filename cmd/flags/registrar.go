package flags

import "github.com/spf13/cobra"

func RegisterGlobalFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringP(Config, "c", "",
		"Path to heimdall's configuration file.\n"+
			"If not provided, the lookup sequence is:\n  1. $PWD\n  2. $HOME/.config\n  3. /etc/heimdall/")
	cmd.PersistentFlags().String(EnvironmentConfigPrefix, "HEIMDALLCFG_",
		"Prefix for the environment variables to consider for\nloading configuration from")
	cmd.PersistentFlags().Bool(SkipAllSecurityEnforcement, false,
		"Disables enforcement of all secure configurations entirely.\n"+
			"Effectively it enables all the --skip-*-enforcement flags below.")
	cmd.PersistentFlags().Bool(SkipAllTLSEnforcement, false,
		"Disables enforcement of TLS for every in- and outbound connection.\n"+
			"Effectively it enables all the --skip-*-tls-enforcement flags.")
	cmd.PersistentFlags().Bool(SkipIngressTLSEnforcement, false,
		"Disables enforcement of TLS configuration for ingress traffic.")
	cmd.PersistentFlags().Bool(SkipEgressTLSEnforcement, false,
		"Disables enforcement of TLS configuration for egress traffic.")
	cmd.PersistentFlags().Bool(SkipUpstreamTLSEnforcement, false,
		"Disables enforcement of TLS while proxying the requests to the\nupstream services.")
	cmd.PersistentFlags().Bool(SkipSecureDefaultRuleEnforcement, false,
		"Disables enforcement of secure configuration of the default\nrule.")
	cmd.PersistentFlags().Bool(SkipSecureTrustedProxiesEnforcement, false,
		"Disables enforcement of secure configuration of the trusted\nproxies.")
}

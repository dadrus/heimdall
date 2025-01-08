package flags

const (
	Config                  = "config"
	EnvironmentConfigPrefix = "env-config-prefix"

	SkipAllSecurityEnforcement          = "insecure"
	SkipSecureTrustedProxiesEnforcement = "insecure-skip-secure-trusted-proxies-enforcement"
	SkipSecureDefaultRuleEnforcement    = "insecure-skip-secure-default-rule-enforcement"
	SkipAllTLSEnforcement               = "insecure-skip-all-tls-enforcement"
	SkipIngressTLSEnforcement           = "insecure-skip-ingress-tls-enforcement"
	SkipEgressTLSEnforcement            = "insecure-skip-egress-tls-enforcement"
	SkipUpstreamTLSEnforcement          = "insecure-skip-upstream-tls-enforcement"

	ValidationInProxyMode = "proxy-mode"
)

package config

type EnforcementSettings struct {
	EnforceSecureDefaultRule bool
	EnforceIngressTLS        bool
	EnforceEgressTLS         bool
}

package config

type EnforcementSettings struct {
	EnforceSecureDefaultRule bool
	EnforceManagementTLS     bool
	EnforceIngressTLS        bool
	EnforceEgressTLS         bool
	EnforceUpstreamTLS       bool
}

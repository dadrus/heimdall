package config

import (
	"reflect"
	"slices"
	"strings"
)

var InsecureNetworks = []string{ // nolint: gochecknoglobals
	"0.0.0.0/0",
	"0/0",
	"0000:0000:0000:0000:0000:0000:0000:0000/0",
	"::/0",
}

const (
	paramIsTLS          = "istls"
	paramNotNil         = "notnil"
	paramFalse          = "false"
	paramSecureNetworks = "secure_networks"
	paramHTTPS          = "https"
)

type EnforcementSettings struct {
	EnforceSecureDefaultRule    bool
	EnforceSecureTrustedProxies bool
	EnforceIngressTLS           bool
	EnforceEgressTLS            bool
	EnforceUpstreamTLS          bool
}

func (v EnforcementSettings) Tag() string { return "enforced" }

func (v EnforcementSettings) Validate(param string, field reflect.Value) bool { // nolint: cyclop
	switch param {
	case paramIsTLS:
		if !v.EnforceEgressTLS {
			return true
		}

		return strings.HasPrefix(field.String(), "https://")
	case paramNotNil:
		if !v.EnforceIngressTLS {
			return true
		}

		return field.Kind() == reflect.Struct
	case paramFalse:
		if !v.EnforceEgressTLS {
			return true
		}

		return !field.Bool()
	case paramSecureNetworks:
		if !v.EnforceSecureTrustedProxies {
			return true
		}

		for i := range field.Len() {
			elem := field.Index(i)
			if slices.Contains(InsecureNetworks, elem.String()) {
				return false
			}
		}

		return true
	case paramHTTPS:
		if !v.EnforceUpstreamTLS {
			return true
		}

		return field.String() == "https"
	default:
		return false
	}
}

func (v EnforcementSettings) AlwaysValidate() bool { return true }

func (v EnforcementSettings) MessageTemplate() string { return "{0} {1}" }

func (v EnforcementSettings) ErrorMessage(param string) string {
	switch param {
	case paramNotNil:
		return "must be configured"
	case paramIsTLS:
		return "scheme must be https"
	case paramFalse:
		return "must be false"
	case paramSecureNetworks:
		return "contains insecure networks"
	case paramHTTPS:
		return "must be https"
	default:
		return "parameter is unknown"
	}
}

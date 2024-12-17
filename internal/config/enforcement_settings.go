package config

import (
	"reflect"
	"strings"
)

type EnforcementSettings struct {
	EnforceSecureDefaultRule bool
	EnforceIngressTLS        bool
	EnforceEgressTLS         bool
	EnforceUpstreamTLS       bool
}

func (v EnforcementSettings) Tag() string { return "enforced" }

func (v EnforcementSettings) Validate(param string, field reflect.Value) bool {
	switch param {
	case "istls":
		if !v.EnforceEgressTLS {
			return true
		}

		return strings.HasPrefix(field.String(), "https://")
	case "notnil":
		if !v.EnforceIngressTLS {
			return true
		}

		return field.Kind() == reflect.Struct
	case "false":
		if !v.EnforceEgressTLS {
			return true
		}

		return !field.Bool()
	default:
		return false
	}
}

func (v EnforcementSettings) AlwaysValidate() bool { return true }

func (v EnforcementSettings) MessageTemplate() string { return "{0} {1}" }

func (v EnforcementSettings) ErrorMessage(param string) string {
	switch param {
	case "notnil":
		return "must be configured"
	case "istls":
		return "scheme must be https"
	case "false":
		return "must be false"
	default:
		return "parameter is unknown"
	}
}

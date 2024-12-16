package config

import (
	"reflect"
	"strings"

	ut "github.com/go-playground/universal-translator"
	"github.com/go-playground/validator/v10"
)

type EnforcementSettings struct {
	EnforceSecureDefaultRule bool
	EnforceIngressTLS        bool
	EnforceEgressTLS         bool
	EnforceUpstreamTLS       bool
}

func (v EnforcementSettings) Tag() string { return "enforced" }

func (v EnforcementSettings) Validate(fl validator.FieldLevel) bool {
	switch fl.Param() {
	case "istls":
		if !v.EnforceEgressTLS {
			return true
		}

		return strings.HasPrefix(fl.Field().String(), "https://")
	case "notnil":
		if !v.EnforceIngressTLS {
			return true
		}

		return fl.Field().Kind() == reflect.Struct
	case "false":
		if !v.EnforceEgressTLS {
			return true
		}

		return !fl.Field().Bool()
	default:
		return false
	}
}

func (v EnforcementSettings) AlwaysValidate() bool { return true }

func (v EnforcementSettings) MessageTemplate() string { return "{0} {1}" }

func (v EnforcementSettings) Translate(ut ut.Translator, fe validator.FieldError) string {
	var msg string

	switch fe.Param() {
	case "notnil":
		msg = "must be configured"
	case "istls":
		msg = "scheme must be https"
	case "false":
		msg = "must be false"
	}

	translation, err := ut.T("enforced", fe.Field(), msg)
	if err != nil {
		return fe.Error()
	}

	return translation
}

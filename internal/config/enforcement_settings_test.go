package config

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEnforcementSettingsTag(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "enforced", EnforcementSettings{}.Tag())
}

func TestEnforcementSettingsAlwaysValidate(t *testing.T) {
	t.Parallel()

	assert.True(t, EnforcementSettings{}.AlwaysValidate())
}

func TestEnforcementSettingsMessageTemplate(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "{0} {1}", EnforcementSettings{}.MessageTemplate())
}

func TestEnforcementSettingsValidate(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		es            EnforcementSettings
		field         reflect.Value
		param         string
		shouldBeValid bool
	}{
		"istls is not enforced": {
			param:         paramIsTLS,
			shouldBeValid: true,
		},
		"istls is enforced and fails": {
			param: paramIsTLS,
			es:    EnforcementSettings{EnforceEgressTLS: true},
			field: reflect.ValueOf("http://foo.bar"),
		},
		"istls is enforced and succeeds": {
			param:         paramIsTLS,
			es:            EnforcementSettings{EnforceEgressTLS: true},
			field:         reflect.ValueOf("https://foo.bar"),
			shouldBeValid: true,
		},
		"notnil is not enforced": {
			param:         paramNotNil,
			shouldBeValid: true,
		},
		"notnil is enforced and fails": {
			param: paramNotNil,
			es:    EnforcementSettings{EnforceIngressTLS: true},
			field: reflect.ValueOf(""),
		},
		"notnil is enforced and succeeds": {
			param:         paramNotNil,
			es:            EnforcementSettings{EnforceIngressTLS: true},
			field:         reflect.ValueOf(TLS{}),
			shouldBeValid: true,
		},
		"false is not enforced": {
			param:         paramFalse,
			shouldBeValid: true,
		},
		"false is enforced and fails": {
			param: paramFalse,
			es:    EnforcementSettings{EnforceEgressTLS: true},
			field: reflect.ValueOf(true),
		},
		"false is enforced and succeeds": {
			param:         paramFalse,
			es:            EnforcementSettings{EnforceEgressTLS: true},
			field:         reflect.ValueOf(false),
			shouldBeValid: true,
		},
		"https is not enforced": {
			param:         paramHTTPS,
			shouldBeValid: true,
		},
		"https is enforced and fails": {
			param: paramHTTPS,
			es:    EnforcementSettings{EnforceUpstreamTLS: true},
			field: reflect.ValueOf(true),
		},
		"https is enforced and succeeds": {
			param:         paramHTTPS,
			es:            EnforcementSettings{EnforceUpstreamTLS: true},
			field:         reflect.ValueOf("https"),
			shouldBeValid: true,
		},
		"unknown param": {
			param: "unknown",
		},
	} {
		t.Run(uc, func(t *testing.T) {
			assert.Equal(t, tc.shouldBeValid, tc.es.Validate(tc.param, tc.field))
		})
	}
}

func TestEnforcementSettingsErrorMessage(t *testing.T) {
	t.Parallel()

	for param, msg := range map[string]string{
		paramIsTLS:  "scheme must be https",
		paramNotNil: "must be configured",
		paramFalse:  "must be false",
		paramHTTPS:  "must be https",
		"foo":       "parameter is unknown",
	} {
		t.Run(param, func(t *testing.T) {
			assert.Equal(t, msg, EnforcementSettings{}.ErrorMessage(param))
		})
	}
}

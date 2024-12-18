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
			param:         "istls",
			shouldBeValid: true,
		},
		"istls is enforced and fails": {
			param: "istls",
			es:    EnforcementSettings{EnforceEgressTLS: true},
			field: reflect.ValueOf("http://foo.bar"),
		},
		"istls is enforced and succeeds": {
			param:         "istls",
			es:            EnforcementSettings{EnforceEgressTLS: true},
			field:         reflect.ValueOf("https://foo.bar"),
			shouldBeValid: true,
		},
		"notnil is not enforced": {
			param:         "notnil",
			shouldBeValid: true,
		},
		"notnil is enforced and fails": {
			param: "notnil",
			es:    EnforcementSettings{EnforceIngressTLS: true},
			field: reflect.ValueOf(""),
		},
		"notnil is enforced and succeeds": {
			param:         "notnil",
			es:            EnforcementSettings{EnforceIngressTLS: true},
			field:         reflect.ValueOf(TLS{}),
			shouldBeValid: true,
		},
		"false is not enforced": {
			param:         "false",
			shouldBeValid: true,
		},
		"false is enforced and fails": {
			param: "false",
			es:    EnforcementSettings{EnforceEgressTLS: true},
			field: reflect.ValueOf(true),
		},
		"false is enforced and succeeds": {
			param:         "false",
			es:            EnforcementSettings{EnforceEgressTLS: true},
			field:         reflect.ValueOf(false),
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
		"istls":  "scheme must be https",
		"notnil": "must be configured",
		"false":  "must be false",
		"foo":    "parameter is unknown",
	} {
		t.Run(param, func(t *testing.T) {
			assert.Equal(t, msg, EnforcementSettings{}.ErrorMessage(param))
		})
	}
}

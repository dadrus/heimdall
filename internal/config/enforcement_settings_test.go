// Copyright 2022-2025 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

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
		"secure networks is not enforced": {
			param:         paramSecureNetworks,
			es:            EnforcementSettings{EnforceSecureTrustedProxies: false},
			field:         reflect.ValueOf([]string{"0.0.0.0.0/0"}),
			shouldBeValid: true,
		},
		"secure networks is enforced and succeeds": {
			param:         paramSecureNetworks,
			es:            EnforcementSettings{EnforceSecureTrustedProxies: true},
			field:         reflect.ValueOf([]string{"10.2.10.0/16"}),
			shouldBeValid: true,
		},
		"secure networks is enforced and fails for IPv4": {
			param:         paramSecureNetworks,
			es:            EnforcementSettings{EnforceSecureTrustedProxies: true},
			field:         reflect.ValueOf([]string{"10.2.0.0/0"}),
			shouldBeValid: false,
		},
		"secure networks is enforced and fails for IPv6": {
			param:         paramSecureNetworks,
			es:            EnforcementSettings{EnforceSecureTrustedProxies: true},
			field:         reflect.ValueOf([]string{"04c9:3cda:907e:eb5a:b55d:ebc2:186c:9995/0"}),
			shouldBeValid: false,
		},
		"secure networks is enforced and fails for ::/0": {
			param:         paramSecureNetworks,
			es:            EnforcementSettings{EnforceSecureTrustedProxies: true},
			field:         reflect.ValueOf([]string{"::/0"}),
			shouldBeValid: false,
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
		paramIsTLS:          "scheme must be https",
		paramNotNil:         "must be configured",
		paramFalse:          "must be false",
		paramHTTPS:          "must be https",
		paramSecureNetworks: "contains insecure networks",
		"foo":               "parameter is unknown",
	} {
		t.Run(param, func(t *testing.T) {
			assert.Equal(t, msg, EnforcementSettings{}.ErrorMessage(param))
		})
	}
}

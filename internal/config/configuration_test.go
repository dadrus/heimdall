// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
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
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/validation"
)

func TestNewConfigurationFromStructWithDefaultsOnly(t *testing.T) {
	t.Parallel()

	// GIVEN
	validator, err := validation.NewValidator(
		validation.WithTagValidator(EnforcementSettings{}),
	)
	require.NoError(t, err)

	rawExp, err := yaml.Marshal(defaultConfig()) //nolint:musttag
	require.NoError(t, err)

	// WHEN
	config, err := NewConfiguration("HEIMDALLCFG_", "", validator)

	// THEN
	require.NoError(t, err)

	rawConf, err := yaml.Marshal(config) //nolint:musttag
	require.NoError(t, err)

	require.Equal(t, string(rawExp), string(rawConf))
}

func TestNewConfigurationWithConfigFile(t *testing.T) {
	t.Parallel()

	// GIVEN
	validator, err := validation.NewValidator(
		validation.WithTagValidator(EnforcementSettings{}),
	)
	require.NoError(t, err)

	rawExp, err := yaml.Marshal(defaultConfig()) //nolint:musttag
	require.NoError(t, err)

	// WHEN
	config, err := NewConfiguration("HEIMDALLCFG_", "./test_data/test_config.yaml", validator)

	// THEN
	require.NoError(t, err)

	rawConf, err := yaml.Marshal(config) //nolint:musttag
	require.NoError(t, err)

	require.NotEqual(t, string(rawExp), string(rawConf))
}

func TestNewConfigurationWithEnvironmentPrefix(t *testing.T) {
	tests := []struct {
		name                string
		prefix              EnvVarPrefix
		envName             string
		envValue            string
		expectedError       string
		expectedMaxInFlight int64
	}{
		{
			name:          "rejects unknown property with default prefix",
			prefix:        "HEIMDALLCFG_",
			envName:       "HEIMDALLCFG_FOO",
			envValue:      "bar",
			expectedError: "'foo' not allowed",
		},
		{
			name:          "rejects unknown property with custom prefix",
			prefix:        "IRGENDWAS_",
			envName:       "IRGENDWAS_FOO",
			envValue:      "bar",
			expectedError: "'foo' not allowed",
		},
		{
			name:                "ignores property outside configured prefix",
			prefix:              "IRGENDWAS_",
			envName:             "HEIMDALLCFG_SERVE_REQUESTS_MAX__IN__FLIGHT",
			envValue:            "123",
			expectedMaxInFlight: defaultConfig().Serve.Requests.MaxInFlight,
		},
		{
			name:                "applies property within configured prefix",
			prefix:              "IRGENDWAS_",
			envName:             "IRGENDWAS_SERVE_REQUESTS_MAX__IN__FLIGHT",
			envValue:            "123",
			expectedMaxInFlight: 123,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(tc.envName, tc.envValue)

			validator, err := validation.NewValidator(
				validation.WithTagValidator(EnforcementSettings{}),
			)
			require.NoError(t, err)

			config, err := NewConfiguration(tc.prefix, "", validator)
			if len(tc.expectedError) != 0 {
				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, tc.expectedError)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.expectedMaxInFlight, config.Serve.Requests.MaxInFlight)
		})
	}
}

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

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

package endpoint

import (
	"testing"

	"github.com/go-viper/mapstructure/v2"
	"github.com/knadh/koanf/maps"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/dadrus/heimdall/internal/rules/mechanisms/template"
)

func TestDecodeEndpointHookFunc(t *testing.T) {
	t.Parallel()

	type Type struct {
		EP Endpoint `mapstructure:"endpoint"`
	}

	// GIVEN

	for uc, tc := range map[string]struct {
		config []byte
		assert func(t *testing.T, err error, ep Endpoint)
	}{
		"can decode from just url as string": {
			config: []byte(`endpoint: http://foo.bar`),
			assert: func(t *testing.T, err error, ep Endpoint) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "http://foo.bar", ep.URL.String())
			},
		},
		"can still decode from structured definition": {
			config: []byte(`
endpoint:
  url: http://foo.bar
  method: PATCH
`),
			assert: func(t *testing.T, err error, ep Endpoint) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "http://foo.bar", ep.URL.String())
				assert.Equal(t, "PATCH", ep.Method)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			conf, err := decodeTestConfig(tc.config)
			require.NoError(t, err)

			var typ Type

			dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
				DecodeHook: mapstructure.ComposeDecodeHookFunc(
					DecodeEndpointHookFunc(),
					template.DecodeTemplateHookFunc(),
				),
				Result: &typ,
			})
			require.NoError(t, err)

			// WHEN
			err = dec.Decode(conf)

			// THEN
			tc.assert(t, err, typ.EP)
		})
	}
}

func decodeTestConfig(data []byte) (map[string]any, error) {
	var out map[string]any

	err := yaml.Unmarshal(data, &out)
	maps.IntfaceKeysToStrings(out)

	return out, err
}

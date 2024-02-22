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

package extractors

import (
	"testing"

	"github.com/go-viper/mapstructure/v2"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/rawbytes"
	"github.com/knadh/koanf/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnmarshalAuthenticationDataSourceFromValidYaml(t *testing.T) {
	t.Parallel()

	var (
		ces      CompositeExtractStrategy
		settings map[string]any
	)

	config := []byte(`
authentication_data_source:
  - cookie: foo_cookie
  - header: foo_header
    scheme: hfoo
  - query_parameter: foo_qparam
  - body_parameter: foo_bparam
`)

	parser := koanf.New(".")

	err := parser.Load(rawbytes.Provider(config), yaml.Parser())
	require.NoError(t, err)

	settings = parser.All()

	dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			DecodeCompositeExtractStrategyHookFunc(),
		),
		Result: &ces,
	})
	require.NoError(t, err)

	err = dec.Decode(settings["authentication_data_source"])
	require.NoError(t, err)
	assert.Len(t, ces, 4)

	ce, ok := ces[0].(*CookieValueExtractStrategy)
	require.True(t, ok)
	assert.Equal(t, "foo_cookie", ce.Name)

	he, ok := ces[1].(*HeaderValueExtractStrategy)
	require.True(t, ok)
	assert.Equal(t, "foo_header", he.Name)
	assert.Equal(t, "hfoo", he.Scheme)

	qe, ok := ces[2].(*QueryParameterExtractStrategy)
	require.True(t, ok)
	assert.Equal(t, "foo_qparam", qe.Name)

	be, ok := ces[3].(*BodyParameterExtractStrategy)
	require.True(t, ok)
	assert.Equal(t, "foo_bparam", be.Name)
}

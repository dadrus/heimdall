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

package matcher

import (
	"testing"

	"github.com/mitchellh/mapstructure"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestDecodeCIDRMatcherHookFunc(t *testing.T) {
	t.Parallel()

	type Type struct {
		Matcher CIDRMatcher `mapstructure:"cidr"`
	}

	rawConfig := []byte(`
cidr:
  - 10.10.20.0/16
  - 192.168.1.0/24
`)

	var typ Type

	dec, err := mapstructure.NewDecoder(
		&mapstructure.DecoderConfig{
			DecodeHook: mapstructure.ComposeDecodeHookFunc(
				DecodeCIDRMatcherHookFunc(),
			),
			Result:      &typ,
			ErrorUnused: true,
		})
	require.NoError(t, err)

	mapConfig, err := testsupport.DecodeTestConfig(rawConfig)
	require.NoError(t, err)

	err = dec.Decode(mapConfig)
	require.NoError(t, err)

	assert.True(t, typ.Matcher.Match("192.168.1.10"))
}

func TestDecodeErrorTypeMatcherHookFunc(t *testing.T) {
	t.Parallel()

	type Type struct {
		Matcher ErrorMatcher `mapstructure:"error"`
	}

	for _, tc := range []struct {
		uc     string
		config []byte
		assert func(t *testing.T, err error, result Type)
	}{
		{
			uc: "successful decoding of multiple entries",
			config: []byte(`
error:
  - type: authentication_error
    raised_by: foo
  - type: authorization_error
    raised_by: bar
  - type: internal_error
  - type: precondition_error
`),
			assert: func(t *testing.T, err error, result Type) {
				t.Helper()

				require.NoError(t, err)

				require.Len(t, result.Matcher, 4)
				assert.ElementsMatch(t, result.Matcher[0].Errors, []error{heimdall.ErrAuthentication})
				assert.Equal(t, "foo", result.Matcher[0].HandlerID)
				assert.ElementsMatch(t, result.Matcher[1].Errors, []error{heimdall.ErrAuthorization})
				assert.Equal(t, "bar", result.Matcher[1].HandlerID)
				assert.ElementsMatch(t, result.Matcher[2].Errors, []error{heimdall.ErrInternal, heimdall.ErrConfiguration})
				assert.Empty(t, result.Matcher[2].HandlerID)
				assert.ElementsMatch(t, result.Matcher[3].Errors, []error{heimdall.ErrArgument})
				assert.Empty(t, result.Matcher[3].HandlerID)
			},
		},
		{
			uc: "unsupported error type",
			config: []byte(`
error:
  - type: auth_error
`),
			assert: func(t *testing.T, err error, result Type) {
				t.Helper()

				require.Error(t, err)
				// mapstruct does not chain errors
				// assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "unsupported error type")
			},
		},
		{
			uc: "bad type for raised_by reference",
			config: []byte(`
error:
  - type: authentication_error
    raised_by: 1
`),
			assert: func(t *testing.T, err error, result Type) {
				t.Helper()

				require.Error(t, err)
				// mapstruct does not chain errors
				// assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "raised_by must be a string")
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			var result Type

			dec, err := mapstructure.NewDecoder(
				&mapstructure.DecoderConfig{
					DecodeHook: mapstructure.ComposeDecodeHookFunc(
						DecodeErrorTypeMatcherHookFunc(),
					),
					Result:      &result,
					ErrorUnused: true,
				})
			require.NoError(t, err)

			mapConfig, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			err = dec.Decode(mapConfig)

			tc.assert(t, err, result)
		})
	}
}

func TestDecodeErrorTypeMatcherHookFuncBadErrorType(t *testing.T) {
	t.Parallel()

	type Type struct {
		Matcher ErrorMatcher `mapstructure:"error"`
	}

	rawConfig := []byte(`
error:
  - type: auth_error
`)

	var typ Type

	dec, err := mapstructure.NewDecoder(
		&mapstructure.DecoderConfig{
			DecodeHook: mapstructure.ComposeDecodeHookFunc(
				DecodeErrorTypeMatcherHookFunc(),
			),
			Result:      &typ,
			ErrorUnused: true,
		})

	require.NoError(t, err)

	mapConfig, err := testsupport.DecodeTestConfig(rawConfig)
	require.NoError(t, err)

	err = dec.Decode(mapConfig)
	require.Error(t, err)
}

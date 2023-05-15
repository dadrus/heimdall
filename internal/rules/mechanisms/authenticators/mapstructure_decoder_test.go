package authenticators

import (
	"testing"

	"github.com/mitchellh/mapstructure"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestDecodeAuthenticationDataForwardStrategy(t *testing.T) {
	t.Parallel()

	type Type struct {
		Strategy AuthDataForwardStrategy `mapstructure:"strategy"`
	}

	for _, tc := range []struct {
		uc     string
		config []byte
		assert func(t *testing.T, err error, strategy AuthDataForwardStrategy)
	}{
		{
			uc: "body auth data forward strategy",
			config: []byte(`
strategy:
  type: body
  config:
    name: foo
`),
			assert: func(t *testing.T, err error, strategy AuthDataForwardStrategy) {
				t.Helper()

				require.NoError(t, err)
				str, ok := strategy.(*BodyParameterForwardStrategy)
				require.True(t, ok)
				assert.Equal(t, "foo", str.Name)
			},
		},
		{
			uc: "cookie auth data forward strategy",
			config: []byte(`
strategy:
  type: cookie
  config:
    name: foo
`),
			assert: func(t *testing.T, err error, strategy AuthDataForwardStrategy) {
				t.Helper()

				require.NoError(t, err)
				str, ok := strategy.(*CookieForwardStrategy)
				require.True(t, ok)
				assert.Equal(t, "foo", str.Name)
			},
		},
		{
			uc: "header auth data forward strategy",
			config: []byte(`
strategy:
  type: header
  config:
    name: foo
    scheme: Bar
`),
			assert: func(t *testing.T, err error, strategy AuthDataForwardStrategy) {
				t.Helper()

				require.NoError(t, err)
				str, ok := strategy.(*HeaderForwardStrategy)
				require.True(t, ok)
				assert.Equal(t, "foo", str.Name)
				assert.Equal(t, "Bar", str.Scheme)
			},
		},
		{
			uc: "query auth data forward strategy",
			config: []byte(`
strategy:
  type: query
  config:
    name: foo
    scheme: Bar
`),
			assert: func(t *testing.T, err error, strategy AuthDataForwardStrategy) {
				t.Helper()

				require.NoError(t, err)
				str, ok := strategy.(*QueryForwardStrategy)
				require.True(t, ok)
				assert.Equal(t, "foo", str.Name)
			},
		},
		{
			uc: "unknown auth data forward strategy",
			config: []byte(`
strategy:
  type: foobar
`),
			assert: func(t *testing.T, err error, strategy AuthDataForwardStrategy) {
				t.Helper()

				require.Error(t, err)
				assert.Contains(t, err.Error(), "unsupported")
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			var typ Type

			dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
				DecodeHook: mapstructure.ComposeDecodeHookFunc(
					DecodeAuthenticationDataForwardStrategy(),
				),
				Result: &typ,
			})
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			// WHEN
			err = dec.Decode(conf)

			// THEN
			tc.assert(t, err, typ.Strategy)
		})
	}
}

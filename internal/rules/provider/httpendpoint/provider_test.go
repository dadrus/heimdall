package httpendpoint

import (
	"net/http"
	"testing"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/event"
	"github.com/dadrus/heimdall/internal/testsupport"
)

func TestNewProvider(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		conf   []byte
		assert func(t *testing.T, err error, prov *provider)
	}{
		{
			uc:   "with invalid configuration, unknown field",
			conf: []byte(`foo: bar`),
			assert: func(t *testing.T, err error, prov *provider) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to decode")
			},
		},
		{
			uc: "with endpoint without url configured",
			conf: []byte(`
endpoint:
  method: POST
`),
			assert: func(t *testing.T, err error, prov *provider) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to validate http_endpoint")
			},
		},
		{
			uc: "with unsupported endpoint method configured",
			conf: []byte(`
endpoint:
  url: https://foo.bar
  method: POST
`),
			assert: func(t *testing.T, err error, prov *provider) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "only GET is supported")
			},
		},
		{
			uc: "with only endpoint and its url configured",
			conf: []byte(`
endpoint:
  url: https://foo.bar
`),
			assert: func(t *testing.T, err error, prov *provider) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, prov)
				assert.Equal(t, "https://foo.bar", prov.e.URL)
				assert.Equal(t, http.MethodGet, prov.e.Method)
				assert.Equal(t, 0*time.Second, prov.wi)
				assert.NotNil(t, prov.q)
			},
		},
		{
			uc: "with only endpoint, its url and supported method configured",
			conf: []byte(`
endpoint:
  url: https://foo.bar
  method: GET
`),
			assert: func(t *testing.T, err error, prov *provider) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, prov)
				assert.Equal(t, "https://foo.bar", prov.e.URL)
				assert.Equal(t, http.MethodGet, prov.e.Method)
				assert.Equal(t, 0*time.Second, prov.wi)
				assert.NotNil(t, prov.q)
			},
		},
		{
			uc: "with endpoint and watch interval configured",
			conf: []byte(`
endpoint:
  url: https://foo.bar
watch_interval: 5m
`),
			assert: func(t *testing.T, err error, prov *provider) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, prov)
				assert.Equal(t, "https://foo.bar", prov.e.URL)
				assert.Equal(t, http.MethodGet, prov.e.Method)
				assert.Equal(t, 5*time.Minute, prov.wi)
				assert.NotNil(t, prov.q)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			providerConf, err := testsupport.DecodeTestConfig(tc.conf)
			require.NoError(t, err)

			queue := make(event.RuleSetChangedEventQueue, 10)

			// WHEN
			prov, err := newProvider(providerConf, queue, log.Logger)

			// THEN
			tc.assert(t, err, prov)
		})
	}
}

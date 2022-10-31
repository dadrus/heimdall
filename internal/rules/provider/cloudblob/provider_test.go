package cloudblob

import (
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/cache/mocks"
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
			uc:   "with unknown field",
			conf: []byte(`foo: bar`),
			assert: func(t *testing.T, err error, prov *provider) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to decode")
			},
		},
		{
			uc:   "without buckets",
			conf: []byte(`watch_interval: 5s`),
			assert: func(t *testing.T, err error, prov *provider) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no buckets configured")
			},
		},
		{
			uc: "without url in one of the configured bucket",
			conf: []byte(`
buckets:
  - url: s3://foobar
  - prefix: bar
`),
			assert: func(t *testing.T, err error, prov *provider) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "missing url for #1")
			},
		},
		{
			uc: "with watch interval and unsupported property in one of the buckets configured",
			conf: []byte(`
watch_interval: 5s
buckets:
  - url: s3://foobar
  - foo: bar
`),
			assert: func(t *testing.T, err error, prov *provider) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to decode")
			},
		},
		{
			uc: "with watch interval and two buckets configured",
			conf: []byte(`
watch_interval: 5s
buckets:
  - url: s3://foobar
  - url: s3://barfoo/foo&foo=bar
    prefix: bar
    rules_path_prefix: baz
`),
			assert: func(t *testing.T, err error, prov *provider) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, prov)
				assert.NotNil(t, prov.s)
				assert.NotNil(t, prov.q)
				assert.NotNil(t, prov.cancel)
				assert.False(t, prov.s.IsRunning())
				assert.Len(t, prov.s.Jobs(), 2)
				assert.False(t, prov.s.Jobs()[0].IsRunning())
				assert.False(t, prov.s.Jobs()[1].IsRunning())
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			providerConf, err := testsupport.DecodeTestConfig(tc.conf)
			require.NoError(t, err)

			cch := &mocks.MockCache{}
			queue := make(event.RuleSetChangedEventQueue, 10)

			// WHEN
			prov, err := newProvider(providerConf, cch, queue, log.Logger)

			// THEN
			tc.assert(t, err, prov)
		})
	}
}

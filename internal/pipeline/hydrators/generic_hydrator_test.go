package hydrators

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/template"
	"github.com/dadrus/heimdall/internal/pipeline/testsupport"
)

func TestCreateGenericHydrator(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		config []byte
		assert func(t *testing.T, err error, hydrator *genericHydrator)
	}{
		{
			uc: "with unsupported fields",
			config: []byte(`
endpoint:
  url: http://foo.bar
foo: bar
`),
			assert: func(t *testing.T, err error, hydrator *genericHydrator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to unmarshal")
			},
		},
		{
			uc: "with invalid endpoint configuration",
			config: []byte(`
endpoint:
  method: POST
payload: bar
`),
			assert: func(t *testing.T, err error, hydrator *genericHydrator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to validate endpoint")
			},
		},
		{
			uc: "with default cache",
			config: []byte(`
endpoint:
  url: http://foo.bar
payload: bar
`),
			assert: func(t *testing.T, err error, hydrator *genericHydrator) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, hydrator)

				assert.Equal(t, "http://foo.bar", hydrator.e.URL)
				assert.Equal(t, template.Template("bar"), hydrator.payload)
				assert.Empty(t, hydrator.fwdCookies)
				assert.Empty(t, hydrator.fwdHeaders)
				assert.Equal(t, defaultTTL, hydrator.ttl)
			},
		},
		{
			uc: "with all fields configured",
			config: []byte(`
endpoint:
  url: http://bar.foo
forward_headers:
  - X-User-ID
  - X-Foo-Bar
forward_cookies:
  - My-Foo-Session
payload: "{{ .ID }}"
cache_ttl: 5s
`),
			assert: func(t *testing.T, err error, hydrator *genericHydrator) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, hydrator)

				assert.Equal(t, "http://bar.foo", hydrator.e.URL)
				assert.Equal(t, template.Template("{{ .ID }}"), hydrator.payload)
				assert.Len(t, hydrator.fwdCookies, 1)
				assert.Contains(t, hydrator.fwdCookies, "My-Foo-Session")
				assert.Len(t, hydrator.fwdHeaders, 2)
				assert.Contains(t, hydrator.fwdHeaders, "X-User-ID")
				assert.Contains(t, hydrator.fwdHeaders, "X-Foo-Bar")
				assert.Equal(t, 5*time.Second, hydrator.ttl)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			// WHEN
			hydrator, err := newGenericHydrator(tc.uc, conf)

			// THEN
			if err == nil {
				assert.Equal(t, tc.uc, hydrator.name)
			}

			tc.assert(t, err, hydrator)
		})
	}
}

func TestCreateGenericHydratorFromPrototype(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc              string
		prototypeConfig []byte
		config          []byte
		assert          func(t *testing.T, err error, prototype *genericHydrator, configured *genericHydrator)
	}{
		{
			uc: "with empty config",
			prototypeConfig: []byte(`
endpoint:
  url: http://foo.bar
payload: bar
`),
			assert: func(t *testing.T, err error, prototype *genericHydrator, configured *genericHydrator) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, prototype, configured)
			},
		},
		{
			uc: "with unsupported fields",
			prototypeConfig: []byte(`
endpoint:
  url: http://foo.bar
payload: bar
`),
			config: []byte(`foo: bar`),
			assert: func(t *testing.T, err error, prototype *genericHydrator, configured *genericHydrator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to unmarshal")
			},
		},
		{
			uc: "with only payload reconfigured",
			prototypeConfig: []byte(`
endpoint:
  url: http://foo.bar
payload: bar
forward_headers:
  - X-User-ID
  - X-Foo-Bar
forward_cookies:
  - My-Foo-Session
cache_ttl: 5s
`),
			config: []byte(`
payload: foo
`),
			assert: func(t *testing.T, err error, prototype *genericHydrator, configured *genericHydrator) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.name, configured.name)
				assert.NotEqual(t, prototype.payload, configured.payload)
				assert.Equal(t, template.Template("foo"), configured.payload)
				assert.Equal(t, prototype.fwdHeaders, configured.fwdHeaders)
				assert.Equal(t, prototype.fwdCookies, configured.fwdCookies)
				assert.Equal(t, prototype.ttl, configured.ttl)
			},
		},
		{
			uc: "with payload and forward_headers reconfigured",
			prototypeConfig: []byte(`
endpoint:
  url: http://foo.bar
payload: bar
forward_headers:
  - X-User-ID
  - X-Foo-Bar
forward_cookies:
  - My-Foo-Session
cache_ttl: 5s
`),
			config: []byte(`
payload: foo
forward_headers:
  - Foo-Bar
`),
			assert: func(t *testing.T, err error, prototype *genericHydrator, configured *genericHydrator) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.name, configured.name)
				assert.NotEqual(t, prototype.payload, configured.payload)
				assert.Equal(t, template.Template("foo"), configured.payload)
				assert.NotEqual(t, prototype.fwdHeaders, configured.fwdHeaders)
				assert.Len(t, configured.fwdHeaders, 1)
				assert.Contains(t, configured.fwdHeaders, "Foo-Bar")
				assert.Equal(t, prototype.fwdCookies, configured.fwdCookies)
				assert.Equal(t, prototype.ttl, configured.ttl)
			},
		},
		{
			uc: "with payload, forward_headers and forward_cookies reconfigured",
			prototypeConfig: []byte(`
endpoint:
  url: http://foo.bar
payload: bar
forward_headers:
  - X-User-ID
  - X-Foo-Bar
forward_cookies:
  - My-Foo-Session
cache_ttl: 5s
`),
			config: []byte(`
payload: foo
forward_headers:
  - Foo-Bar
forward_cookies:
  - Foo-Session
`),
			assert: func(t *testing.T, err error, prototype *genericHydrator, configured *genericHydrator) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.name, configured.name)
				assert.NotEqual(t, prototype.payload, configured.payload)
				assert.Equal(t, template.Template("foo"), configured.payload)
				assert.NotEqual(t, prototype.fwdHeaders, configured.fwdHeaders)
				assert.Len(t, configured.fwdHeaders, 1)
				assert.Contains(t, configured.fwdHeaders, "Foo-Bar")
				assert.NotEqual(t, prototype.fwdCookies, configured.fwdCookies)
				assert.Len(t, configured.fwdCookies, 1)
				assert.Contains(t, configured.fwdCookies, "Foo-Session")
				assert.Equal(t, prototype.ttl, configured.ttl)
			},
		},
		{
			uc: "with everything reconfigured",
			prototypeConfig: []byte(`
endpoint:
  url: http://foo.bar
payload: bar
forward_headers:
  - X-User-ID
  - X-Foo-Bar
forward_cookies:
  - My-Foo-Session
cache_ttl: 5s
`),
			config: []byte(`
payload: foo
forward_headers:
  - Foo-Bar
forward_cookies:
  - Foo-Session
cache_ttl: 15s
`),
			assert: func(t *testing.T, err error, prototype *genericHydrator, configured *genericHydrator) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.name, configured.name)
				assert.NotEqual(t, prototype.payload, configured.payload)
				assert.Equal(t, template.Template("foo"), configured.payload)
				assert.NotEqual(t, prototype.fwdHeaders, configured.fwdHeaders)
				assert.Len(t, configured.fwdHeaders, 1)
				assert.Contains(t, configured.fwdHeaders, "Foo-Bar")
				assert.NotEqual(t, prototype.fwdCookies, configured.fwdCookies)
				assert.Len(t, configured.fwdCookies, 1)
				assert.Contains(t, configured.fwdCookies, "Foo-Session")
				assert.NotEqual(t, prototype.ttl, configured.ttl)
				assert.Equal(t, 15*time.Second, configured.ttl)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			pc, err := testsupport.DecodeTestConfig(tc.prototypeConfig)
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			prototype, err := newGenericHydrator(tc.uc, pc)
			require.NoError(t, err)

			// WHEN
			auth, err := prototype.WithConfig(conf)

			// THEN
			var (
				locAuth *genericHydrator
				ok      bool
			)

			if err == nil {
				locAuth, ok = auth.(*genericHydrator)
				require.True(t, ok)
			}

			tc.assert(t, err, prototype, locAuth)
		})
	}
}

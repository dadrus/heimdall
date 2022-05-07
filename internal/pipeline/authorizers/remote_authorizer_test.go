package authorizers

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/template"
	"github.com/dadrus/heimdall/internal/pipeline/testsupport"
)

func TestCreateRemoteAuthorizer(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		config []byte
		assert func(t *testing.T, err error, auth *remoteAuthorizer)
	}{
		{
			uc: "configuration with unknown properties",
			config: []byte(`
endpoint:
  url: http://foo.bar
foo: bar
`),
			assert: func(t *testing.T, err error, auth *remoteAuthorizer) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to unmarshal")
			},
		},
		{
			uc: "configuration with invalid endpoint config",
			config: []byte(`
endpoint:
  method: FOO
payload: FooBar
`),
			assert: func(t *testing.T, err error, auth *remoteAuthorizer) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to validate endpoint")
			},
		},
		{
			uc: "configuration without both payload and header",
			config: []byte(`
endpoint:
  url: http://foo.bar
`),
			assert: func(t *testing.T, err error, auth *remoteAuthorizer) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "either a payload or at least one header")
			},
		},
		{
			uc: "configuration with endpoint and header",
			config: []byte(`
endpoint:
  url: http://foo.bar
header:
  Foo-Bar: Baz
`),
			assert: func(t *testing.T, err error, auth *remoteAuthorizer) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, auth)
				assert.Len(t, auth.header, 1)
				assert.Equal(t, template.Template("Baz"), auth.header["Foo-Bar"])
				assert.Empty(t, auth.payload)
				assert.Empty(t, auth.headerForUpstream)
				assert.Nil(t, auth.ttl)
			},
		},
		{
			uc: "configuration with endpoint and payload",
			config: []byte(`
endpoint:
  url: http://foo.bar
payload: "{{ .ID }}"
`),
			assert: func(t *testing.T, err error, auth *remoteAuthorizer) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, auth)
				assert.Empty(t, auth.header)
				assert.Equal(t, template.Template("{{ .ID }}"), auth.payload)
				assert.Empty(t, auth.headerForUpstream)
				assert.Nil(t, auth.ttl)
			},
		},
		{
			uc: "full configuration",
			config: []byte(`
endpoint:
  url: http://foo.bar
header:
  Foo-Bar: Baz
  Baz-Foo: Bar
payload: "{{ .Attributes.foo }}"
forward_response_header_to_upstream:
  - Foo
  - Bar
cache_ttl: 5s
`),
			assert: func(t *testing.T, err error, auth *remoteAuthorizer) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, auth)
				assert.Len(t, auth.header, 2)
				assert.Equal(t, template.Template("Baz"), auth.header["Foo-Bar"])
				assert.Equal(t, template.Template("Bar"), auth.header["Baz-Foo"])
				assert.Equal(t, template.Template("{{ .Attributes.foo }}"), auth.payload)
				assert.Len(t, auth.headerForUpstream, 2)
				assert.Contains(t, auth.headerForUpstream, "Foo")
				assert.Contains(t, auth.headerForUpstream, "Bar")
				assert.NotNil(t, auth.ttl)
				assert.Equal(t, 5*time.Second, *auth.ttl)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			// WHEN
			auth, err := newRemoteAuthorizer(tc.uc, conf)

			// THEN
			if err == nil {
				assert.Equal(t, tc.uc, auth.name)
			}

			tc.assert(t, err, auth)
		})
	}
}

func TestCreateRemoteAuthorizerFromPrototype(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc              string
		prototypeConfig []byte
		config          []byte
		assert          func(t *testing.T, err error, prototype *remoteAuthorizer, configured *remoteAuthorizer)
	}{
		{
			uc: "without new configuration",
			prototypeConfig: []byte(`
endpoint:
  url: http://foo.bar
payload: bar
`),
			assert: func(t *testing.T, err error, prototype *remoteAuthorizer, configured *remoteAuthorizer) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, prototype, configured)
			},
		},
		{
			uc: "with empty configuration",
			prototypeConfig: []byte(`
endpoint:
  url: http://foo.bar
payload: bar
`),
			config: []byte(``),
			assert: func(t *testing.T, err error, prototype *remoteAuthorizer, configured *remoteAuthorizer) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, prototype, configured)
			},
		},
		{
			uc: "configuration with unknown properties",
			prototypeConfig: []byte(`
endpoint:
  url: http://foo.bar
payload: bar
`),
			config: []byte(`
foo: bar
`),
			assert: func(t *testing.T, err error, prototype *remoteAuthorizer, configured *remoteAuthorizer) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to unmarshal")
			},
		},
		{
			uc: "with overwritten empty payload",
			prototypeConfig: []byte(`
endpoint:
  url: http://foo.bar
payload: bar
`),
			config: []byte(`
payload: ""
cache_ttl: 1s
`),
			assert: func(t *testing.T, err error, prototype *remoteAuthorizer, configured *remoteAuthorizer) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.NotNil(t, configured)
				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.name, configured.name)
				assert.Equal(t, prototype.payload, configured.payload)
				assert.Empty(t, configured.headerForUpstream)
				assert.Empty(t, configured.header)
				assert.NotNil(t, configured.ttl)
			},
		},
		{
			uc: "with overwritten empty header",
			prototypeConfig: []byte(`
endpoint:
  url: http://foo.bar
header:
  Foo: Bar
`),
			config: []byte(`
header:
cache_ttl: 1s
`),
			assert: func(t *testing.T, err error, prototype *remoteAuthorizer, configured *remoteAuthorizer) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.NotNil(t, configured)
				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.name, configured.name)
				assert.Empty(t, configured.payload)
				assert.Empty(t, configured.headerForUpstream)
				assert.Equal(t, prototype.header, configured.header)
				assert.NotNil(t, configured.ttl)
			},
		},
		{
			uc: "with everything possible reconfigured",
			prototypeConfig: []byte(`
endpoint:
  url: http://foo.bar
header:
  Foo: Bar
`),
			config: []byte(`
header:
  Bar: Foo
payload: Baz
forward_response_header_to_upstream:
  - Bar
  - Foo
cache_ttl: 15s
`),
			assert: func(t *testing.T, err error, prototype *remoteAuthorizer, configured *remoteAuthorizer) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.NotNil(t, configured)
				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.name, configured.name)
				assert.Equal(t, template.Template("Baz"), configured.payload)
				assert.Len(t, configured.headerForUpstream, 2)
				assert.Contains(t, configured.headerForUpstream, "Bar")
				assert.Contains(t, configured.headerForUpstream, "Foo")
				assert.Len(t, configured.header, 1)
				assert.Equal(t, template.Template("Foo"), configured.header["Bar"])
				assert.Equal(t, 15*time.Second, *configured.ttl)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			pc, err := testsupport.DecodeTestConfig(tc.prototypeConfig)
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			prototype, err := newRemoteAuthorizer(tc.uc, pc)
			require.NoError(t, err)

			// WHEN
			auth, err := prototype.WithConfig(conf)

			// THEN
			var (
				locAuth *remoteAuthorizer
				ok      bool
			)

			if err == nil {
				locAuth, ok = auth.(*remoteAuthorizer)
				require.True(t, ok)
			}

			tc.assert(t, err, prototype, locAuth)
		})
	}
}

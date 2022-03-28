package authenticators

import (
	"testing"

	"github.com/dadrus/heimdall/internal/pipeline/handler/authenticators/extractors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateJwtAuthenticator(t *testing.T) {
	for _, tc := range []struct {
		uc     string
		config []byte
		assert func(t *testing.T, err error, a *jwtAuthenticator)
	}{
		{
			uc: "missing jwks url config",
			config: []byte(`
jwt_token_from:
  - header: foo-header
jwt_assertions:
  trusted_issuers:
    - foobar
session:
  subject_from: some_template`),
			assert: func(t *testing.T, err error, a *jwtAuthenticator) {
				assert.Error(t, err)
			},
		},
		{
			uc: "missing jwt_token_from config",
			config: []byte(`
jwks_endpoint:
  url: http://test.com
jwt_assertions:
  trusted_issuers:
    - foobar
session:
  subject_from: some_template`),
			assert: func(t *testing.T, err error, a *jwtAuthenticator) {
				require.NoError(t, err)

				assert.IsType(t, extractors.CompositeExtractStrategy{}, a.AuthDataGetter)

				assert.Contains(t, a.AuthDataGetter, extractors.HeaderValueExtractStrategy{Name: "Authorization", Prefix: "Bearer"})
				assert.Contains(t, a.AuthDataGetter, extractors.FormParameterExtractStrategy{Name: "access_token"})
				assert.Contains(t, a.AuthDataGetter, extractors.QueryParameterExtractStrategy{Name: "access_token"})
			},
		},
		{
			uc: "missing trusted_issuers config",
			config: []byte(`
jwks_endpoint:
  url: http://test.com
jwt_assertions:
  target_audiences:
    - foobar
session:
  subject_from: some_template`),
			assert: func(t *testing.T, err error, a *jwtAuthenticator) {
				assert.Error(t, err)
			},
		},
		{
			uc: "missing session configuration",
			config: []byte(`
jwks_endpoint:
  url: http://test.com
jwt_token_from:
  - header: foo-header
jwt_assertions:
  trusted_issuers:
    - foobar`),
			assert: func(t *testing.T, err error, a *jwtAuthenticator) {
				assert.NoError(t, err)
				assert.IsType(t, &Session{}, a.SubjectExtractor)
				s := a.SubjectExtractor.(*Session)
				assert.Equal(t, "sub", s.SubjectFrom)
			},
		},
		{
			uc: "config with undefined fields",
			config: []byte(`
jwks_endpoint:
  url: http://test.com
jwt_token_from:
  - header: foo-header
jwt_assertions:
  trusted_issuers:
    - foobar
foo: bar`),
			assert: func(t *testing.T, err error, a *jwtAuthenticator) {
				assert.Error(t, err)
			},
		},
		{
			uc: "valid configuration",
			config: []byte(`
jwks_endpoint:
  url: http://test.com
jwt_token_from:
  - header: foo-header
jwt_assertions:
  trusted_issuers:
    - foobar
session:
  subject_from: some_template`),
			assert: func(t *testing.T, err error, a *jwtAuthenticator) {
				assert.NoError(t, err)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// WHEN
			a, err := NewJwtAuthenticatorFromYAML(tc.config)

			// THEN
			tc.assert(t, err, a)
		})
	}
}

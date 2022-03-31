package authenticators

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/endpoint"
	"github.com/dadrus/heimdall/internal/pipeline/handler/authenticators/extractors"
	"github.com/dadrus/heimdall/internal/pipeline/oauth2"
)

func TestCreateJwtAuthenticator(t *testing.T) {
	t.Parallel()

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
				t.Helper()
				assert.Error(t, err)
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
				t.Helper()
				assert.Error(t, err)
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
				t.Helper()
				assert.Error(t, err)
			},
		},
		{
			uc: "valid configuration with defaults",
			config: []byte(`
jwks_endpoint:
  url: http://test.com
jwt_assertions:
  trusted_issuers:
    - foobar`),
			assert: func(t *testing.T, err error, auth *jwtAuthenticator) {
				t.Helper()
				require.NoError(t, err)

				// endpoint settings
				ept, ok := auth.e.(endpoint.Endpoint)
				require.True(t, ok)
				assert.Equal(t, "http://test.com", ept.URL)
				assert.Equal(t, "GET", ept.Method)
				assert.Equal(t, 1, len(ept.Headers))
				assert.Contains(t, ept.Headers, "Accept-Type")
				assert.Equal(t, ept.Headers["Accept-Type"], "application/json")

				// token extractor settings
				assert.IsType(t, extractors.CompositeExtractStrategy{}, auth.adg)
				assert.Contains(t, auth.adg, extractors.HeaderValueExtractStrategy{Name: "Authorization", Prefix: "Bearer"})
				assert.Contains(t, auth.adg, extractors.FormParameterExtractStrategy{Name: "access_token"})
				assert.Contains(t, auth.adg, extractors.QueryParameterExtractStrategy{Name: "access_token"})

				// assertions settings
				assert.Nil(t, auth.a.ScopeStrategy)
				assert.Empty(t, auth.a.RequiredScopes)
				assert.Empty(t, auth.a.TargetAudiences)
				assert.Len(t, auth.a.TrustedIssuers, 1)
				assert.Contains(t, auth.a.TrustedIssuers, "foobar")
				assert.Len(t, auth.a.AllowedAlgorithms, 6)

				assert.ElementsMatch(t, auth.a.AllowedAlgorithms, []string{
					string(jose.ES256), string(jose.ES384), string(jose.ES512),
					string(jose.PS256), string(jose.PS384), string(jose.PS512),
				})
				assert.Equal(t, oauth2.Duration(0), auth.a.ValidityLeeway)

				// session settings
				sess, ok := auth.se.(*Session)
				require.True(t, ok)
				assert.Equal(t, "sub", sess.SubjectFrom)
				assert.Empty(t, sess.AttributesFrom)
			},
		},
		{
			uc: "valid configuration with overwrites",
			config: []byte(`
jwks_endpoint:
  url: http://test.com
  method: POST
  headers:
    Accept-Type: application/foobar
jwt_token_from:
  - header: foo-header
jwt_assertions:
  scope_strategy: wildcard
  required_scopes:
    - foo
  trusted_issuers:
    - foobar
  allowed_algorithms:
    - ES256
session:
  subject_from: some_claim`),
			assert: func(t *testing.T, err error, auth *jwtAuthenticator) {
				t.Helper()
				require.NoError(t, err)

				// endpoint settings
				ept, ok := auth.e.(endpoint.Endpoint)
				require.True(t, ok)
				assert.Equal(t, "http://test.com", ept.URL)
				assert.Equal(t, "POST", ept.Method)
				assert.Equal(t, 1, len(ept.Headers))
				assert.Contains(t, ept.Headers, "Accept-Type")
				assert.Equal(t, ept.Headers["Accept-Type"], "application/foobar")

				// token extractor settings
				assert.IsType(t, extractors.CompositeExtractStrategy{}, auth.adg)
				assert.Len(t, auth.adg, 1)
				assert.Contains(t, auth.adg, &extractors.HeaderValueExtractStrategy{Name: "foo-header"})

				// assertions settings
				assert.NotNil(t, auth.a.ScopeStrategy)
				assert.ElementsMatch(t, auth.a.RequiredScopes, []string{"foo"})
				assert.Empty(t, auth.a.TargetAudiences)
				assert.Len(t, auth.a.TrustedIssuers, 1)
				assert.Contains(t, auth.a.TrustedIssuers, "foobar")
				assert.Len(t, auth.a.AllowedAlgorithms, 1)

				assert.ElementsMatch(t, auth.a.AllowedAlgorithms, []string{string(jose.ES256)})
				assert.Equal(t, oauth2.Duration(0), auth.a.ValidityLeeway)

				// session settings
				sess, ok := auth.se.(*Session)
				require.True(t, ok)
				assert.Equal(t, "some_claim", sess.SubjectFrom)
				assert.Empty(t, sess.AttributesFrom)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			t.Parallel()

			// WHEN
			a, err := NewJwtAuthenticatorFromYAML(tc.config)

			// THEN
			tc.assert(t, err, a)
		})
	}
}

func setup(t *testing.T, subject, issuer, audience string) ([]byte, string) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{Key: privateKey.Public(), KeyID: "bar", Algorithm: string(jose.PS512)},
		},
	}
	rawJwks, err := json.Marshal(jwks)
	require.NoError(t, err)

	signerOpts := jose.SignerOptions{}
	signerOpts.WithType("JWT").WithHeader("kid", "bar")
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.PS512, Key: privateKey}, &signerOpts)
	require.NoError(t, err)

	builder := jwt.Signed(signer)
	builder = builder.Claims(map[string]interface{}{
		"sub": subject,
		"iss": issuer,
		"jti": "foo",
		"iat": time.Now().Unix() - 1,
		"nbf": time.Now().Unix() - 1,
		"exp": time.Now().Unix() + 2,
		"aud": []string{audience},
		"scp": []string{"foo", "bar"},
	})
	rawJwt, err := builder.CompactSerialize()
	require.NoError(t, err)

	return rawJwks, rawJwt
}

func TestCreateJwtAuthenticatorFromPrototype(t *testing.T) {
	t.Parallel()

	// GIVEN
	prototypeConfig := []byte(`
jwks_endpoint:
  url: http://test.com
jwt_assertions:
  trusted_issuers:
    - foobar`)

	config := []byte(`
jwt_assertions:
  trusted_issuers:
    - barfoo
  allowed_algorithms:
    - ES512`)

	prototype, err := NewJwtAuthenticatorFromYAML(prototypeConfig)
	require.NoError(t, err)

	// WHEN
	auth, err := prototype.WithConfig(config)

	// THEN
	require.NoError(t, err)

	jwta, ok := auth.(*jwtAuthenticator)
	require.True(t, ok)
	assert.Equal(t, prototype.e, jwta.e)
	assert.Equal(t, prototype.adg, jwta.adg)
	assert.Equal(t, prototype.se, jwta.se)
	assert.NotEqual(t, prototype.a, jwta.a)

	assert.Nil(t, jwta.a.ScopeStrategy)
	assert.Empty(t, jwta.a.RequiredScopes)
	assert.Empty(t, jwta.a.TargetAudiences)
	assert.ElementsMatch(t, jwta.a.TrustedIssuers, []string{"barfoo"})
	assert.ElementsMatch(t, jwta.a.AllowedAlgorithms, []string{string(jose.ES512)})
}

func TestSuccessfulExecutionOfJwtAuthenticator(t *testing.T) {
	t.Parallel()

	// GIVEN
	subject := "foo"
	issuer := "foobar"
	audience := "bar"
	jwks, jwt := setup(t, subject, issuer, audience)

	as := oauth2.Expectation{
		ScopeStrategy:     oauth2.ExactScopeStrategy,
		RequiredScopes:    []string{"foo"},
		TargetAudiences:   []string{audience},
		TrustedIssuers:    []string{issuer},
		AllowedAlgorithms: []string{string(jose.PS512)},
		ValidityLeeway:    oauth2.Duration(1 * time.Minute),
	}

	sc := &heimdall.SubjectContext{}
	sub := &heimdall.Subject{ID: subject}
	ctx := context.Background()
	mrc := &MockRequestContext{}

	adg := &MockAuthDataGetter{}
	adg.On("GetAuthData", mrc).Return(jwt, nil)

	ept := &MockEndpoint{}
	ept.On("SendRequest", mock.Anything, mock.MatchedBy(func(r io.Reader) bool {
		return r == nil
	}),
	).Return(jwks, nil)

	encJwtPayload := strings.Split(jwt, ".")[1]
	rawPaload, err := base64.RawStdEncoding.DecodeString(encJwtPayload)
	require.NoError(t, err)

	se := &MockSubjectExtractor{}
	se.On("GetSubject", rawPaload).Return(sub, nil)

	auth := jwtAuthenticator{
		e:   ept,
		a:   as,
		se:  se,
		adg: adg,
	}

	// WHEN
	err = auth.Authenticate(ctx, mrc, sc)

	// THEN
	require.NoError(t, err)
	assert.Equal(t, sub, sc.Subject)

	ept.AssertExpectations(t)
	se.AssertExpectations(t)
	adg.AssertExpectations(t)
}

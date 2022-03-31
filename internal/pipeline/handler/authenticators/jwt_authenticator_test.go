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

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/endpoint"
	"github.com/dadrus/heimdall/internal/pipeline/oauth2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/dadrus/heimdall/internal/pipeline/handler/authenticators/extractors"
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
			uc: "valid configuration with defaults",
			config: []byte(`
jwks_endpoint:
  url: http://test.com
jwt_assertions:
  trusted_issuers:
    - foobar`),
			assert: func(t *testing.T, err error, a *jwtAuthenticator) {
				require.NoError(t, err)

				// endpoint settings
				require.IsType(t, endpoint.Endpoint{}, a.e)
				e := a.e.(endpoint.Endpoint)
				assert.Equal(t, "http://test.com", e.Url)
				assert.Equal(t, "GET", e.Method)
				assert.Equal(t, 1, len(e.Headers))
				assert.Contains(t, e.Headers, "Accept-Type")
				assert.Equal(t, e.Headers["Accept-Type"], "application/json")

				// token extractor settings
				assert.IsType(t, extractors.CompositeExtractStrategy{}, a.adg)
				assert.Contains(t, a.adg, extractors.HeaderValueExtractStrategy{Name: "Authorization", Prefix: "Bearer"})
				assert.Contains(t, a.adg, extractors.FormParameterExtractStrategy{Name: "access_token"})
				assert.Contains(t, a.adg, extractors.QueryParameterExtractStrategy{Name: "access_token"})

				// assertions settings
				assert.Nil(t, a.a.ScopeStrategy)
				assert.Empty(t, a.a.RequiredScopes)
				assert.Empty(t, a.a.TargetAudiences)
				assert.Len(t, a.a.TrustedIssuers, 1)
				assert.Contains(t, a.a.TrustedIssuers, "foobar")
				assert.Len(t, a.a.AllowedAlgorithms, 6)

				assert.ElementsMatch(t, a.a.AllowedAlgorithms, []string{
					string(jose.ES256), string(jose.ES384), string(jose.ES512),
					string(jose.PS256), string(jose.PS384), string(jose.PS512),
				})
				assert.Equal(t, oauth2.Duration(0), a.a.ValidityLeeway)

				// session settings
				require.IsType(t, &Session{}, a.se)
				sess := a.se.(*Session)
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
			assert: func(t *testing.T, err error, a *jwtAuthenticator) {
				require.NoError(t, err)

				// endpoint settings
				require.IsType(t, endpoint.Endpoint{}, a.e)
				e := a.e.(endpoint.Endpoint)
				assert.Equal(t, "http://test.com", e.Url)
				assert.Equal(t, "POST", e.Method)
				assert.Equal(t, 1, len(e.Headers))
				assert.Contains(t, e.Headers, "Accept-Type")
				assert.Equal(t, e.Headers["Accept-Type"], "application/foobar")

				// token extractor settings
				assert.IsType(t, extractors.CompositeExtractStrategy{}, a.adg)
				assert.Len(t, a.adg, 1)
				assert.Contains(t, a.adg, &extractors.HeaderValueExtractStrategy{Name: "foo-header"})

				// assertions settings
				assert.NotNil(t, a.a.ScopeStrategy)
				assert.ElementsMatch(t, a.a.RequiredScopes, []string{"foo"})
				assert.Empty(t, a.a.TargetAudiences)
				assert.Len(t, a.a.TrustedIssuers, 1)
				assert.Contains(t, a.a.TrustedIssuers, "foobar")
				assert.Len(t, a.a.AllowedAlgorithms, 1)

				assert.ElementsMatch(t, a.a.AllowedAlgorithms, []string{string(jose.ES256)})
				assert.Equal(t, oauth2.Duration(0), a.a.ValidityLeeway)

				// session settings
				require.IsType(t, &Session{}, a.se)
				sess := a.se.(*Session)
				assert.Equal(t, "some_claim", sess.SubjectFrom)
				assert.Empty(t, sess.AttributesFrom)
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

func setup(t *testing.T, subject, issuer, audience string) ([]byte, string) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{Key: privateKey.Public(), KeyID: "bar", Algorithm: string(jose.PS512)},
		},
	}
	rawJwks, err := json.Marshal(jwks)
	require.NoError(t, err)

	var signerOpts = jose.SignerOptions{}
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

func TestSuccessfulExecutionOfJwtAuthenticator(t *testing.T) {
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
	sub := &heimdall.Subject{Id: subject}
	ctx := context.Background()
	mrc := &MockRequestContext{}

	adg := &MockAuthDataGetter{}
	adg.On("GetAuthData", mrc).Return(jwt, nil)

	e := &MockEndpoint{}
	e.On("SendRequest", mock.Anything, mock.MatchedBy(func(r io.Reader) bool {
		return r == nil
	}),
	).Return(jwks, nil)

	encJwtPayload := strings.Split(jwt, ".")[1]
	rawPaload, err := base64.RawStdEncoding.DecodeString(encJwtPayload)
	require.NoError(t, err)

	se := &MockSubjectExtractor{}
	se.On("GetSubject", rawPaload).Return(sub, nil)

	a := jwtAuthenticator{
		e:   e,
		a:   as,
		se:  se,
		adg: adg,
	}

	// WHEN
	err = a.Authenticate(ctx, mrc, sc)

	// THEN
	require.NoError(t, err)
	assert.Equal(t, sub, sc.Subject)

	e.AssertExpectations(t)
	se.AssertExpectations(t)
	adg.AssertExpectations(t)
}

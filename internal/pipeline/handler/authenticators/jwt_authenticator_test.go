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

				assert.IsType(t, extractors.CompositeExtractStrategy{}, a.adg)

				assert.Contains(t, a.adg, extractors.HeaderValueExtractStrategy{Name: "Authorization", Prefix: "Bearer"})
				assert.Contains(t, a.adg, extractors.FormParameterExtractStrategy{Name: "access_token"})
				assert.Contains(t, a.adg, extractors.QueryParameterExtractStrategy{Name: "access_token"})
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
				assert.IsType(t, &Session{}, a.se)
				s := a.se.(*Session)
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

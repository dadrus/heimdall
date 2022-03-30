package authenticators

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"testing"

	"github.com/dadrus/heimdall/internal/heimdall"
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

func setup(t *testing.T, subject string, issuer string) ([]byte, string) {
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
	builder = builder.Claims(&jwt.Claims{
		Subject: subject,
		Issuer:  issuer,
		ID:      "foo",
	})
	rawJwt, err := builder.CompactSerialize()
	require.NoError(t, err)

	return rawJwks, rawJwt
}

func TestSuccessfulExecutionOfJwtAuthenticator(t *testing.T) {
	// GIVEN
	subject := "foo"
	issuer := "foobar"
	jwks, jwt := setup(t, subject, issuer)

	as := &MockClaimAsserter{}
	as.On("AssertIssuer", mock.Anything).Return(nil)
	as.On("AssertAudience", mock.Anything).Return(nil)
	as.On("AssertScopes", mock.Anything).Return(nil)
	as.On("AssertValidity", mock.Anything, mock.Anything).Return(nil)
	as.On("IsAlgorithmAllowed", string(jose.PS512)).Return(true)

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

	se := &MockSubjectExtractor{}
	se.On("GetSubject", []byte(`{"iss":"foobar","jti":"foo","sub":"foo"}`)).Return(sub, nil)

	a := jwtAuthenticator{
		Endpoint:         e,
		SubjectExtractor: se,
		AuthDataGetter:   adg,
		Session:          as,
	}

	// WHEN
	err := a.Authenticate(ctx, mrc, sc)

	// THEN
	require.NoError(t, err)
	assert.Equal(t, sub, sc.Subject)

	e.AssertExpectations(t)
	se.AssertExpectations(t)
	adg.AssertExpectations(t)
}

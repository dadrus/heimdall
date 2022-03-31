package authenticators

import (
	"context"
	"io"

	"github.com/stretchr/testify/mock"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
)

type MockEndpoint struct {
	mock.Mock
}

func (m *MockEndpoint) SendRequest(ctx context.Context, body io.Reader) ([]byte, error) {
	args := m.Called(ctx, body)

	if val := args.Get(0); val != nil {
		res, ok := val.([]byte)
		if !ok {
			panic("[]byte expected")
		}

		return res, args.Error(1)
	}

	return nil, args.Error(1)
}

type MockAuthDataGetter struct {
	mock.Mock
}

func (m *MockAuthDataGetter) GetAuthData(s handler.RequestContext) (string, error) {
	args := m.Called(s)

	return args.String(0), args.Error(1)
}

type MockSubjectExtractor struct {
	mock.Mock
}

func (m *MockSubjectExtractor) GetSubject(data []byte) (*heimdall.Subject, error) {
	args := m.Called(data)

	if val := args.Get(0); val != nil {
		res, ok := val.(*heimdall.Subject)
		if !ok {
			panic("*heimdal.Subject expected")
		}

		return res, args.Error(1)
	}

	return nil, args.Error(1)
}

type MockAuthenticator struct {
	mock.Mock
}

func (a *MockAuthenticator) Authenticate(
	c context.Context,
	rc handler.RequestContext,
	sc *heimdall.SubjectContext,
) error {
	args := a.Called(c, rc, sc)

	return args.Error(0)
}

func (a *MockAuthenticator) WithConfig(c []byte) (handler.Authenticator, error) {
	args := a.Called(c)

	if val := args.Get(0); val != nil {
		res, ok := val.(handler.Authenticator)
		if !ok {
			panic("handler.Authenticator expected")
		}

		return res, args.Error(1)
	}

	return nil, args.Error(1)
}

type MockRequestContext struct {
	mock.Mock
}

func (a *MockRequestContext) Header(key string) string {
	args := a.Called(key)

	return args.String(0)
}

func (a *MockRequestContext) Cookie(key string) string {
	args := a.Called(key)

	return args.String(0)
}

func (a *MockRequestContext) Query(key string) string {
	args := a.Called(key)

	return args.String(0)
}

func (a *MockRequestContext) Form(key string) string {
	args := a.Called(key)

	return args.String(0)
}

func (a *MockRequestContext) Body() []byte {
	args := a.Called()

	if val := args.Get(0); val != nil {
		res, ok := val.([]byte)
		if !ok {
			panic("[]byte expected")
		}

		return res
	}

	return nil
}

type MockClaimAsserter struct {
	mock.Mock
}

func (a *MockClaimAsserter) AssertIssuer(issuer string) error {
	args := a.Called(issuer)

	return args.Error(0)
}

func (a *MockClaimAsserter) AssertAudience(audience []string) error {
	args := a.Called(audience)

	return args.Error(0)
}

func (a *MockClaimAsserter) AssertScopes(scopes []string) error {
	args := a.Called(scopes)

	return args.Error(0)
}

func (a *MockClaimAsserter) AssertValidity(nbf, exp int64) error {
	args := a.Called(nbf, exp)

	return args.Error(0)
}

func (a *MockClaimAsserter) IsAlgorithmAllowed(alg string) bool {
	args := a.Called(alg)

	return args.Bool(0)
}

package authenticators

import (
	"context"
	"encoding/json"
	"io"

	"github.com/dadrus/heimdall/internal/pipeline/handler"
	"github.com/stretchr/testify/mock"

	"github.com/dadrus/heimdall/internal/heimdall"
)

type MockEndpoint struct {
	mock.Mock
}

func (m *MockEndpoint) SendRequest(ctx context.Context, body io.Reader) ([]byte, error) {
	args := m.Called(ctx, body)
	return args.Get(0).(json.RawMessage), args.Error(1)
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

func (m *MockSubjectExtractor) GetSubject(data json.RawMessage) (*heimdall.Subject, error) {
	args := m.Called(data)
	i := args.Get(0)
	if i != nil {
		return i.(*heimdall.Subject), args.Error(1)
	}
	return nil, args.Error(1)
}

type MockAuthenticator struct {
	mock.Mock
}

func (a *MockAuthenticator) Authenticate(c context.Context, rc handler.RequestContext, sc *heimdall.SubjectContext) error {
	args := a.Called(c, rc, sc)
	return args.Error(0)
}

func (a *MockAuthenticator) WithConfig(c []byte) (handler.Authenticator, error) {
	args := a.Called(c)
	i := args.Get(0)
	if i != nil {
		return i.(handler.Authenticator), args.Error(1)
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
	i := args.Get(0)
	if i != nil {
		return i.([]byte)
	}
	return nil
}

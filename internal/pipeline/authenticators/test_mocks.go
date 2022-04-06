package authenticators

import (
	"net/http"

	"github.com/stretchr/testify/mock"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/authenticators/extractors"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
)

type DummyAuthData struct {
	Val string
}

func (c DummyAuthData) ApplyTo(req *http.Request) { req.Header.Add("Dummy", c.Val) }
func (c DummyAuthData) Value() string             { return c.Val }

type MockAuthDataGetter struct {
	mock.Mock
}

func (m *MockAuthDataGetter) GetAuthData(s heimdall.Context) (extractors.AuthData, error) {
	args := m.Called(s)

	if val := args.Get(0); val != nil {
		res, ok := val.(extractors.AuthData)
		if !ok {
			panic("extractors.AuthData expected")
		}

		return res, args.Error(1)
	}

	return nil, args.Error(1)
}

type MockAuthenticator struct {
	mock.Mock
}

func (a *MockAuthenticator) Authenticate(ctx heimdall.Context) (*subject.Subject, error) {
	args := a.Called(ctx)

	if val := args.Get(0); val != nil {
		res, ok := val.(*subject.Subject)
		if !ok {
			panic("*subject.Subject expected")
		}

		return res, args.Error(1)
	}

	return nil, args.Error(1)
}

func (a *MockAuthenticator) WithConfig(c map[string]interface{}) (Authenticator, error) {
	args := a.Called(c)

	if val := args.Get(0); val != nil {
		res, ok := val.(Authenticator)
		if !ok {
			panic("handler.Authenticator expected")
		}

		return res, args.Error(1)
	}

	return nil, args.Error(1)
}

package authenticators

import (
	"net/http"

	"github.com/stretchr/testify/mock"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/authenticators/extractors"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
)

type dummyAuthData struct {
	Val string
}

func (c dummyAuthData) ApplyTo(req *http.Request) { req.Header.Add("Dummy", c.Val) }
func (c dummyAuthData) Value() string             { return c.Val }

type mockAuthDataGetter struct {
	mock.Mock
}

func (m *mockAuthDataGetter) GetAuthData(s heimdall.Context) (extractors.AuthData, error) {
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

type mockAuthenticator struct {
	mock.Mock
}

func (a *mockAuthenticator) Authenticate(ctx heimdall.Context) (*subject.Subject, error) {
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

func (a *mockAuthenticator) WithConfig(c map[string]interface{}) (Authenticator, error) {
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

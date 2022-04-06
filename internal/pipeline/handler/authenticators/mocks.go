package authenticators

import (
	"net/http"

	"github.com/stretchr/testify/mock"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler/authenticators/extractors"
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

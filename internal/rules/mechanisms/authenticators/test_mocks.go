package authenticators

import (
	"github.com/dadrus/heimdall/internal/rules/pipeline/authenticators/extractors"
	"net/http"

	"github.com/stretchr/testify/mock"

	"github.com/dadrus/heimdall/internal/heimdall"
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

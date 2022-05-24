package mocks

import (
	"context"
	"net/url"

	"github.com/stretchr/testify/mock"

	"github.com/dadrus/heimdall/internal/heimdall"
)

func convertTo[T any](val any) T {
	var def T

	if val != nil {
		// nolint: forcetypeassert
		return val.(T)
	}

	return def
}

type MockContext struct {
	mock.Mock
}

func (m *MockContext) RequestMethod() string { return m.Called().String(0) }

func (m *MockContext) RequestHeaders() map[string]string {
	return convertTo[map[string]string](m.Called().Get(0))
}

func (m *MockContext) RequestHeader(name string) string { return m.Called(name).String(0) }

func (m *MockContext) RequestCookie(name string) string { return m.Called(name).String(0) }

func (m *MockContext) RequestQueryParameter(name string) string { return m.Called(name).String(0) }

func (m *MockContext) RequestFormParameter(name string) string { return m.Called(name).String(0) }

func (m *MockContext) RequestBody() []byte { return convertTo[[]byte](m.Called().Get(0)) }

func (m *MockContext) AppContext() context.Context {
	return convertTo[context.Context](m.Called().Get(0))
}

func (m *MockContext) SetPipelineError(err error) { m.Called(err) }

func (m *MockContext) AddResponseHeader(name, value string) { m.Called(name, value) }

func (m *MockContext) AddResponseCookie(name, value string) { m.Called(name, value) }

func (m *MockContext) Signer() heimdall.JWTSigner {
	return convertTo[heimdall.JWTSigner](m.Called().Get(0))
}

func (m *MockContext) RequestURL() *url.URL { return convertTo[*url.URL](m.Called().Get(0)) }

func (m *MockContext) RequestClientIPs() []string { return convertTo[[]string](m.Called().Get(0)) }

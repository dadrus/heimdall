package mocks

import (
	"context"
	"net/url"

	"github.com/stretchr/testify/mock"

	"github.com/dadrus/heimdall/internal/heimdall"
)

type MockContext struct {
	mock.Mock
}

func (m *MockContext) RequestMethod() string {
	return m.Called().String(0)
}

func (m *MockContext) RequestHeaders() map[string]string {
	args := m.Called()

	if i := args.Get(0); i != nil {
		// nolint: forcetypeassert
		return i.(map[string]string)
	}

	return nil
}

func (m *MockContext) RequestHeader(name string) string {
	return m.Called(name).String(0)
}

func (m *MockContext) RequestCookie(name string) string {
	return m.Called(name).String(0)
}

func (m *MockContext) RequestQueryParameter(name string) string {
	return m.Called(name).String(0)
}

func (m *MockContext) RequestFormParameter(name string) string {
	return m.Called(name).String(0)
}

func (m *MockContext) RequestBody() []byte {
	args := m.Called()

	if i := args.Get(0); i != nil {
		// nolint: forcetypeassert
		return i.([]byte)
	}

	return nil
}

func (m *MockContext) AppContext() context.Context {
	args := m.Called()

	if i := args.Get(0); i != nil {
		// nolint: forcetypeassert
		return i.(context.Context)
	}

	return nil
}

func (m *MockContext) SetPipelineError(err error) {
	m.Called(err)
}

func (m *MockContext) AddResponseHeader(name, value string) {
	m.Called(name, value)
}

func (m *MockContext) AddResponseCookie(name, value string) {
	m.Called(name, value)
}

func (m *MockContext) Signer() heimdall.JWTSigner {
	args := m.Called()

	if i := args.Get(0); i != nil {
		// nolint: forcetypeassert
		return i.(heimdall.JWTSigner)
	}

	return nil
}

func (m *MockContext) RequestURL() *url.URL {
	args := m.Called()

	if i := args.Get(0); i != nil {
		// nolint: forcetypeassert
		return i.(*url.URL)
	}

	return nil
}

func (m *MockContext) RequestClientIPs() []string {
	args := m.Called()

	if i := args.Get(0); i != nil {
		// nolint: forcetypeassert
		return i.([]string)
	}

	return nil
}

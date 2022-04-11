package testsupport

import (
	"context"
	"errors"
	"net/url"
	"time"

	"github.com/stretchr/testify/mock"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
)

var ErrTestPurpose = errors.New("error raised in a test")

type MockSubjectFactory struct {
	mock.Mock
}

func (m *MockSubjectFactory) CreateSubject(data []byte) (*subject.Subject, error) {
	args := m.Called(data)

	if val := args.Get(0); val != nil {
		res, ok := val.(*subject.Subject)
		if !ok {
			panic("*heimdal.Subject expected")
		}

		return res, args.Error(1)
	}

	return nil, args.Error(1)
}

type MockContext struct {
	mock.Mock
}

func (m *MockContext) RequestHeaders() map[string]string {
	args := m.Called()

	if i := args.Get(0); i != nil {
		val, ok := i.(map[string]string)
		if !ok {
			panic("map[string]string expected")
		}

		return val
	}

	return nil
}

func (m *MockContext) RequestHeader(name string) string {
	args := m.Called(name)

	return args.String(0)
}

func (m *MockContext) RequestCookie(name string) string {
	args := m.Called(name)

	return args.String(0)
}

func (m *MockContext) RequestQueryParameter(name string) string {
	args := m.Called(name)

	return args.String(0)
}

func (m *MockContext) RequestFormParameter(name string) string {
	args := m.Called(name)

	return args.String(0)
}

func (m *MockContext) RequestBody() []byte {
	args := m.Called()

	if i := args.Get(0); i != nil {
		val, ok := i.([]byte)
		if !ok {
			panic("[]byte expected")
		}

		return val
	}

	return nil
}

func (m *MockContext) AppContext() context.Context {
	args := m.Called()

	if i := args.Get(0); i != nil {
		val, ok := i.(context.Context)
		if !ok {
			panic("context.Context")
		}

		return val
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
		val, ok := i.(heimdall.JWTSigner)
		if !ok {
			panic("heimdall.JWTSigner")
		}

		return val
	}

	return nil
}

func (m *MockContext) RequestURL() *url.URL {
	args := m.Called()

	if i := args.Get(0); i != nil {
		val, ok := i.(*url.URL)
		if !ok {
			panic("*url.URL expected")
		}

		return val
	}

	return nil
}

func (m *MockContext) RequestClientIPs() []string {
	args := m.Called()

	if i := args.Get(0); i != nil {
		val, ok := i.([]string)
		if !ok {
			panic("[]string expected")
		}

		return val
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

type MockCache struct {
	mock.Mock
}

func (m *MockCache) Start() { m.Called() }

func (m *MockCache) Stop() { m.Called() }

func (m *MockCache) Get(key string) any {
	args := m.Called(key)

	return args.Get(0)
}

func (m *MockCache) Set(key string, value any, ttl time.Duration) { m.Called(key, value, ttl) }

func (m *MockCache) Delete(key string) { m.Called() }

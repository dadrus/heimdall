package oauth2

import (
	"github.com/stretchr/testify/mock"
)

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

package mocks

import (
	"time"

	"github.com/stretchr/testify/mock"
	"gopkg.in/square/go-jose.v2"
)

type MockJWTSigner struct {
	mock.Mock
}

func (m *MockJWTSigner) Hash() []byte { return convertTo[[]byte](m.Called().Get(0)) }

func (m *MockJWTSigner) Sign(subjectID string, ttl time.Duration, claims map[string]any) (string, error) {
	args := m.Called(subjectID, ttl, claims)

	return args.String(0), args.Error(1)
}

func (m *MockJWTSigner) Keys() []jose.JSONWebKey {
	return convertTo[[]jose.JSONWebKey](m.Called().Get(0))
}

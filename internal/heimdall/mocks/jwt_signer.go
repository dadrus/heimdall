package mocks

import (
	"time"

	"github.com/stretchr/testify/mock"
)

type MockJWTSigner struct {
	mock.Mock
}

func (m *MockJWTSigner) Hash() []byte { return convertTo[[]byte](m.Called().Get(0)) }

func (m *MockJWTSigner) Sign(subjectID string, ttl time.Duration, claims map[string]any) (string, error) {
	args := m.Called(subjectID, ttl, claims)

	return args.String(0), args.Error(1)
}

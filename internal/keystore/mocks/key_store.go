package mocks

import (
	"github.com/stretchr/testify/mock"

	"github.com/dadrus/heimdall/internal/keystore"
)

type MockKeyStore struct {
	mock.Mock
}

func (m *MockKeyStore) GetKey(id string) (*keystore.Entry, error) {
	args := m.Called(id)

	if val := args.Get(0); val != nil {
		// nolint: forcetypeassert
		return val.(*keystore.Entry), nil
	}

	return nil, args.Error(1)
}

func (m *MockKeyStore) Entries() []*keystore.Entry {
	if val := m.Called().Get(0); val != nil {
		// nolint: forcetypeassert
		return val.([]*keystore.Entry)
	}

	return nil
}

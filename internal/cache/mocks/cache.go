package mocks

import (
	"time"

	"github.com/stretchr/testify/mock"
)

type MockCache struct {
	mock.Mock
}

func (m *MockCache) Start() { m.Called() }

func (m *MockCache) Stop() { m.Called() }

func (m *MockCache) Get(key string) any { return m.Called(key).Get(0) }

func (m *MockCache) Set(key string, value any, ttl time.Duration) { m.Called(key, value, ttl) }

func (m *MockCache) Delete(key string) { m.Called(key) }

package mocks

import (
	"context"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/stretchr/testify/mock"
)

type MockHandler struct {
	mock.Mock
}

func (m *MockHandler) Check(ctx context.Context, req *envoy_auth.CheckRequest) (*envoy_auth.CheckResponse, error) {
	args := m.Called(ctx, req)

	if val := args.Get(0); val != nil {
		// nolint: forcetypeassert
		return val.(*envoy_auth.CheckResponse), nil
	}

	return nil, args.Error(1)
}

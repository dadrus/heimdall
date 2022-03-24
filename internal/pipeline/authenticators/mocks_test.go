package authenticators

import (
	"context"
	"encoding/json"
	"io"

	"github.com/stretchr/testify/mock"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline"
)

type MockEndpoint struct {
	mock.Mock
}

func (m *MockEndpoint) SendRequest(ctx context.Context, body io.Reader) ([]byte, error) {
	args := m.Called(ctx, body)
	return args.Get(0).(json.RawMessage), args.Error(1)
}

type MockAuthDataGetter struct {
	mock.Mock
}

func (m *MockAuthDataGetter) GetAuthData(s pipeline.AuthDataSource) (string, error) {
	args := m.Called(s)
	return args.String(0), args.Error(1)
}

type MockSubjectExtractor struct {
	mock.Mock
}

func (m *MockSubjectExtractor) GetSubject(data json.RawMessage) (*heimdall.Subject, error) {
	args := m.Called(data)
	return args.Get(0).(*heimdall.Subject), args.Error(1)
}

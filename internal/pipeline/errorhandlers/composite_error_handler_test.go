package errorhandlers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/testsupport"
)

type mockErrorHandler struct {
	mock.Mock
}

func (m *mockErrorHandler) HandleError(ctx heimdall.Context, e error) error {
	args := m.Called(ctx, e)

	return args.Error(0)
}

func (m *mockErrorHandler) WithConfig(conf map[string]any) (ErrorHandler, error) {
	args := m.Called(conf)

	if i := args.Get(0); i != nil {
		val, ok := i.(ErrorHandler)
		if !ok {
			panic("ErrorHandler expected")
		}

		return val, nil
	}

	return nil, args.Error(1)
}

func TestCompositeErrorHandlerExecutionWithFallback(t *testing.T) {
	t.Parallel()

	// GIVEN
	ctx := &testsupport.MockContext{}
	ctx.On("AppContext").Return(context.Background())

	eh1 := &mockErrorHandler{}
	eh1.On("HandleError", ctx, testsupport.ErrTestPurpose).Return(testsupport.ErrTestPurpose)

	eh2 := &mockErrorHandler{}
	eh2.On("HandleError", ctx, testsupport.ErrTestPurpose).Return(nil)

	eh := CompositeErrorHandler{eh1, eh2}

	// WHEN
	err := eh.HandleError(ctx, testsupport.ErrTestPurpose)

	// THEN
	assert.NoError(t, err)

	eh1.AssertExpectations(t)
	eh2.AssertExpectations(t)
}

func TestCompositeErrorHandlerExecutionWithoutFallback(t *testing.T) {
	t.Parallel()

	// GIVEN
	ctx := &testsupport.MockContext{}
	ctx.On("AppContext").Return(context.Background())

	eh1 := &mockErrorHandler{}
	eh1.On("HandleError", ctx, testsupport.ErrTestPurpose).Return(nil)

	eh2 := &mockErrorHandler{}

	eh := CompositeErrorHandler{eh1, eh2}

	// WHEN
	err := eh.HandleError(ctx, testsupport.ErrTestPurpose)

	// THEN
	assert.NoError(t, err)

	eh1.AssertExpectations(t)
	eh2.AssertExpectations(t)
}

func TestCompositErrorHandlerFromPrototypeIsNotAllowed(t *testing.T) {
	t.Parallel()

	// GIVEN
	eh := CompositeErrorHandler{}

	// WHEN
	_, err := eh.WithConfig(nil)

	// THEN
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "configuration error")
}

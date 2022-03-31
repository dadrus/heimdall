package authenticators

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dadrus/heimdall/internal/heimdall"
)

func TestCompositeAuthenticatorExecutionWithFallback(t *testing.T) {
	t.Parallel()

	// GIVEN
	ctx := context.Background()
	reqCtx := &MockRequestContext{}
	subCtx := &heimdall.SubjectContext{}

	auth1 := &MockAuthenticator{}
	auth1.On("Authenticate", ctx, reqCtx, subCtx).Return(ErrTestPurpose)

	auth2 := &MockAuthenticator{}
	auth2.On("Authenticate", ctx, reqCtx, subCtx).Return(nil)

	auth := CompositeAuthenticator{auth1, auth2}

	// WHEN
	err := auth.Authenticate(ctx, reqCtx, subCtx)

	// THEN
	assert.NoError(t, err)

	auth1.AssertExpectations(t)
	auth2.AssertExpectations(t)
}

func TestCompositeAuthenticatorExecutionWithoutFallback(t *testing.T) {
	t.Parallel()

	// GIVEN
	ctx := context.Background()
	reqCtx := &MockRequestContext{}
	subCtx := &heimdall.SubjectContext{}

	auth1 := &MockAuthenticator{}
	auth2 := &MockAuthenticator{}
	auth2.On("Authenticate", ctx, reqCtx, subCtx).Return(nil)

	auth := CompositeAuthenticator{auth2, auth1}

	// WHEN
	err := auth.Authenticate(ctx, reqCtx, subCtx)

	// THEN
	assert.NoError(t, err)

	auth1.AssertExpectations(t)
	auth2.AssertExpectations(t)
}

func TestCompositeAuthenticatorFromPrototypeIsNotAllowed(t *testing.T) {
	t.Parallel()

	// GIVEN
	auth := CompositeAuthenticator{}

	// WHEN
	_, err := auth.WithConfig([]byte{})

	// THEN
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "configuration error")
}

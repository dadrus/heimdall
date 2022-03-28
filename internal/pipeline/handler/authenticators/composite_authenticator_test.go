package authenticators

import (
	"context"
	"errors"
	"testing"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/stretchr/testify/assert"
)

func TestCompositeAuthenticatorExecutionWithFallback(t *testing.T) {
	// GIVEN
	ctx := context.Background()
	rc := &MockRequestContext{}
	sc := &heimdall.SubjectContext{}
	authErr := errors.New("error")

	m1 := &MockAuthenticator{}
	m1.On("Authenticate", ctx, rc, sc).Return(authErr)

	m2 := &MockAuthenticator{}
	m2.On("Authenticate", ctx, rc, sc).Return(nil)

	ca := CompositeAuthenticator{m1, m2}

	// WHEN
	err := ca.Authenticate(ctx, rc, sc)

	// THEN
	assert.NoError(t, err)

	m1.AssertExpectations(t)
	m2.AssertExpectations(t)
}

func TestCompositeAuthenticatorExecutionWithoutFallback(t *testing.T) {
	// GIVEN
	ctx := context.Background()
	rc := &MockRequestContext{}
	sc := &heimdall.SubjectContext{}

	m1 := &MockAuthenticator{}
	m2 := &MockAuthenticator{}
	m2.On("Authenticate", ctx, rc, sc).Return(nil)

	ca := CompositeAuthenticator{m2, m1}

	// WHEN
	err := ca.Authenticate(ctx, rc, sc)

	// THEN
	assert.NoError(t, err)

	m1.AssertExpectations(t)
	m2.AssertExpectations(t)
}

func TestCompositeAuthenticatorFromPrototypeIsNotAllowed(t *testing.T) {
	// GIVEN
	p := CompositeAuthenticator{}

	// WHEN
	_, err := p.WithConfig([]byte{})

	// THEN
	assert.Error(t, err)
	assert.Equal(t, "reconfiguration not allowed", err.Error())
}

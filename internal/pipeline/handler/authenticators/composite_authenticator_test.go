package authenticators

import (
	"context"
	"testing"

	"github.com/dadrus/heimdall/internal/pipeline/handler/subject"
	"github.com/dadrus/heimdall/internal/testsupport"
	"github.com/stretchr/testify/assert"
)

func TestCompositeAuthenticatorExecutionWithFallback(t *testing.T) {
	t.Parallel()

	// GIVEN
	sub := &subject.Subject{ID: "foo"}

	ctx := &testsupport.MockContext{}
	ctx.On("AppContext").Return(context.Background())

	auth1 := &testsupport.MockAuthenticator{}
	auth1.On("Authenticate", ctx).Return(nil, testsupport.ErrTestPurpose)

	auth2 := &testsupport.MockAuthenticator{}
	auth2.On("Authenticate", ctx).Return(sub, nil)

	auth := CompositeAuthenticator{auth1, auth2}

	// WHEN
	rSub, err := auth.Authenticate(ctx)

	// THEN
	assert.NoError(t, err)
	assert.Equal(t, sub, rSub)

	auth1.AssertExpectations(t)
	auth2.AssertExpectations(t)
}

func TestCompositeAuthenticatorExecutionWithoutFallback(t *testing.T) {
	t.Parallel()

	// GIVEN
	sub := &subject.Subject{ID: "foo"}

	ctx := &testsupport.MockContext{}
	ctx.On("AppContext").Return(context.Background())

	auth1 := &testsupport.MockAuthenticator{}
	auth2 := &testsupport.MockAuthenticator{}
	auth2.On("Authenticate", ctx).Return(sub, nil)

	auth := CompositeAuthenticator{auth2, auth1}

	// WHEN
	rSub, err := auth.Authenticate(ctx)

	// THEN
	assert.NoError(t, err)

	assert.Equal(t, sub, rSub)

	auth1.AssertExpectations(t)
	auth2.AssertExpectations(t)
}

func TestCompositeAuthenticatorFromPrototypeIsNotAllowed(t *testing.T) {
	t.Parallel()

	// GIVEN
	auth := CompositeAuthenticator{}

	// WHEN
	_, err := auth.WithConfig(nil)

	// THEN
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "configuration error")
}

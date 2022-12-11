package authenticators

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
)

func TestUnauthorizedAuthenticatorExecution(t *testing.T) {
	t.Parallel()
	// GIVEN
	var identifier interface{ HandlerID() string }

	ctx := &mocks.MockContext{}
	ctx.On("AppContext").Return(context.Background())

	auth := newUnauthorizedAuthenticator("unauth")

	// WHEN
	sub, err := auth.Execute(ctx)

	// THEN
	assert.ErrorIs(t, err, heimdall.ErrAuthentication)
	assert.ErrorContains(t, err, "denied by authenticator")
	assert.Nil(t, sub)

	require.True(t, errors.As(err, &identifier))
	assert.Equal(t, "unauth", identifier.HandlerID())
}

func TestCreateUnauthorizedAuthenticatorFromPrototype(t *testing.T) {
	t.Parallel()
	// GIVEN
	prototype := newUnauthorizedAuthenticator("unauth")

	// WHEN
	auth, err := prototype.WithConfig(nil)

	// THEN
	assert.NoError(t, err)

	uaa, ok := auth.(*unauthorizedAuthenticator)
	require.True(t, ok)

	// prototype and "created" authenticator are same
	assert.Equal(t, prototype, uaa)
	assert.Equal(t, "unauth", uaa.HandlerID())
}

func TestUnauthorizedAuthenticatorIsFallbackOnErrorAllowed(t *testing.T) {
	t.Parallel()

	// GIVEN
	auth := newUnauthorizedAuthenticator("unauth")

	// WHEN
	isAllowed := auth.IsFallbackOnErrorAllowed()

	// THEN
	require.False(t, isAllowed)
	require.Equal(t, "unauth", auth.HandlerID())
}

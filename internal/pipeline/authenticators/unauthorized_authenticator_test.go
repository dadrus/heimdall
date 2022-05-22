package authenticators

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
)

func TestUnauthorizedAuthenticatorExecution(t *testing.T) {
	t.Parallel()
	// GIVEN
	ctx := &mocks.MockContext{}
	ctx.On("AppContext").Return(context.Background())

	auth := newUnauthorizedAuthenticator()

	// WHEN
	sub, err := auth.Execute(ctx)

	// THEN
	assert.ErrorIs(t, err, heimdall.ErrAuthentication)
	assert.ErrorContains(t, err, "denied by authenticator")
	assert.Nil(t, sub)
}

func TestCreateUnauthorizedAuthenticatorFromPrototype(t *testing.T) {
	t.Parallel()
	// GIVEN
	prototype := newUnauthorizedAuthenticator()

	// WHEN
	auth, err := prototype.WithConfig(nil)

	// THEN
	assert.NoError(t, err)

	// prototype and "created" authenticator are same
	assert.Equal(t, prototype, auth)
}

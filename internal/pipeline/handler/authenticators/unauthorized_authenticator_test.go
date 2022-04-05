package authenticators

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dadrus/heimdall/internal/heimdall"
)

func TestUnauthorizedAuthenticatorExecution(t *testing.T) {
	t.Parallel()
	// GIVEN
	auth := NewUnauthorizedAuthenticator()

	// WHEN
	sub, err := auth.Authenticate(nil)

	// THEN
	assert.ErrorIs(t, err, heimdall.ErrAuthentication)
	assert.ErrorContains(t, err, "denied by authenticator")
	assert.Nil(t, sub)
}

func TestCreateUnauthorizedAuthenticatorFromPrototype(t *testing.T) {
	t.Parallel()
	// GIVEN
	prototype := NewUnauthorizedAuthenticator()

	// WHEN
	auth, err := prototype.WithConfig(nil)

	// THEN
	assert.NoError(t, err)

	// prototype and "created" authenticator are same
	assert.Equal(t, prototype, auth)
}

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
	err := auth.Authenticate(nil, nil, nil)

	// THEN
	assert.ErrorIs(t, err, heimdall.ErrAuthentication)
	assert.ErrorContains(t, err, "denied by authenticator")
}

func TestCreateUnauthorizedAuthenticatorFromPrototype(t *testing.T) {
	t.Parallel()
	// GIVEN
	prototype := NewUnauthorizedAuthenticator()

	// WHEN
	auth, err := prototype.WithConfig([]byte{})

	// THEN
	assert.NoError(t, err)

	// prototype and "created" authenticator are same
	assert.Equal(t, prototype, auth)
}

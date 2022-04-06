package authenticators

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNoopAuthenticatorExecution(t *testing.T) {
	t.Parallel()

	// GIVEN
	a := newNoopAuthenticator()

	// WHEN
	sub, err := a.Authenticate(nil)

	// THEN
	require.NoError(t, err)
	require.NotNil(t, sub)
	assert.Empty(t, sub)
}

func TestCreateNoopAuthenticatorFromPrototype(t *testing.T) {
	t.Parallel()

	// GIVEN
	prototype := newNoopAuthenticator()

	// WHEN
	auth, err := prototype.WithConfig(nil)

	// THEN
	require.NoError(t, err)
	require.Equal(t, prototype, auth)
}

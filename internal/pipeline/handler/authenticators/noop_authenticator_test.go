package authenticators

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
)

func TestNoopAuthenticatorExecution(t *testing.T) {
	t.Parallel()

	// GIVEN
	sc := heimdall.SubjectContext{}
	a := NewNoopAuthenticator()

	// WHEN
	err := a.Authenticate(nil, nil, &sc)

	// THEN
	require.NoError(t, err)
	require.NotNil(t, sc.Subject)
	assert.Empty(t, sc.Subject)
}

func TestCreateNoopAuthenticatorFromPrototype(t *testing.T) {
	t.Parallel()

	// GIVEN
	prototype := NewNoopAuthenticator()

	// WHEN
	auth, err := prototype.WithConfig(nil)

	// THEN
	require.NoError(t, err)
	require.Equal(t, prototype, auth)
}

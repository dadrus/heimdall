package authenticators

import (
	"testing"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNoopAuthenticatorExecution(t *testing.T) {
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
	// GIVEN
	p := NewNoopAuthenticator()

	// WHEN
	a, err := p.WithConfig(nil)

	// THEN
	require.NoError(t, err)
	require.Equal(t, p, a)
}

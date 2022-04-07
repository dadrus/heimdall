package authenticators

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/pipeline/testsupport"
)

func TestNoopAuthenticatorExecution(t *testing.T) {
	t.Parallel()

	// GIVEN
	ctx := &testsupport.MockContext{}
	ctx.On("AppContext").Return(context.Background())

	a := newNoopAuthenticator()

	// WHEN
	sub, err := a.Authenticate(ctx)

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

package authenticators

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall/mocks"
)

func TestNoopAuthenticatorExecution(t *testing.T) {
	t.Parallel()

	// GIVEN
	ctx := &mocks.MockContext{}
	ctx.On("AppContext").Return(context.Background())

	auth := newNoopAuthenticator()

	// WHEN
	sub, err := auth.Execute(ctx)

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
	auth1, err1 := prototype.WithConfig(nil)
	auth2, err2 := prototype.WithConfig(map[string]any{"foo": "bar"})

	// THEN
	assert.NoError(t, err1)
	assert.Equal(t, prototype, auth1)

	assert.NoError(t, err2)
	assert.Equal(t, prototype, auth2)
}

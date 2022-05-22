package authorizers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
)

func TestCreateDenyAuthorizerFromPrototype(t *testing.T) {
	// GIVEN
	prototype := newDenyAuthorizer()

	// WHEN
	conf1, err1 := prototype.WithConfig(nil)
	conf2, err2 := prototype.WithConfig(map[string]any{"foo": "bar"})

	// THEN
	require.NoError(t, err1)
	require.NoError(t, err2)

	assert.Equal(t, prototype, conf1)
	assert.Equal(t, prototype, conf2)
}

func TestDenyAuthorizerExecute(t *testing.T) {
	// GIVEN
	ctx := &mocks.MockContext{}
	ctx.On("AppContext").Return(context.Background())

	auth := newDenyAuthorizer()

	// WHEN
	err := auth.Execute(ctx, nil)

	// THEN
	require.Error(t, err)
	require.ErrorIs(t, err, heimdall.ErrAuthorization)
	require.Contains(t, err.Error(), "denied by authorizer")
}

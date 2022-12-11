package authorizers

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
)

func TestCreateDenyAuthorizerFromPrototype(t *testing.T) {
	// GIVEN
	prototype := newDenyAuthorizer("foo")

	// WHEN
	conf1, err1 := prototype.WithConfig(nil)
	conf2, err2 := prototype.WithConfig(map[string]any{"foo": "bar"})

	// THEN
	require.NoError(t, err1)
	require.NoError(t, err2)

	assert.Equal(t, prototype, conf1)
	assert.Equal(t, prototype, conf2)

	assert.IsType(t, &denyAuthorizer{}, conf1)
	assert.IsType(t, &denyAuthorizer{}, conf2)

	// nolint: forcetypeassert
	assert.Equal(t, "foo", conf1.(*denyAuthorizer).HandlerID())
}

func TestDenyAuthorizerExecute(t *testing.T) {
	// GIVEN
	var identifier interface{ HandlerID() string }

	ctx := &mocks.MockContext{}
	ctx.On("AppContext").Return(context.Background())

	auth := newDenyAuthorizer("bar")

	// WHEN
	err := auth.Execute(ctx, nil)

	// THEN
	require.Error(t, err)
	require.ErrorIs(t, err, heimdall.ErrAuthorization)
	require.Contains(t, err.Error(), "denied by authorizer")

	require.True(t, errors.As(err, &identifier))
	assert.Equal(t, "bar", identifier.HandlerID())
}

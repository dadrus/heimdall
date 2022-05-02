package authorizers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/pipeline/testsupport"
)

func TestCreateAllowAuthorizerFromPrototype(t *testing.T) {
	// GIVEN
	prototype := newAllowAuthorizer()

	// WHEN
	conf1, err1 := prototype.WithConfig(nil)
	conf2, err2 := prototype.WithConfig(map[any]any{"foo": "bar"})

	// THEN
	require.NoError(t, err1)
	require.NoError(t, err2)

	assert.Equal(t, prototype, conf1)
	assert.Equal(t, prototype, conf2)
}

func TestAllowAuthorizerExecute(t *testing.T) {
	// GIVEN
	ctx := &testsupport.MockContext{}
	ctx.On("AppContext").Return(context.Background())

	auth := newAllowAuthorizer()

	// WHEN
	err := auth.Execute(ctx, nil)

	// THEN
	require.NoError(t, err)
}

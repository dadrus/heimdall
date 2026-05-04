package tlsx

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	keyregistrymocks "github.com/dadrus/heimdall/internal/keyregistry/v2/mocks"
	secretsmocks "github.com/dadrus/heimdall/internal/secrets/mocks"
)

func TestWithServerAuthentication(t *testing.T) {
	t.Parallel()

	// GIVEN
	opts := newOptions()

	apply := WithServerAuthentication(true)

	// WHEN
	apply(opts)

	// THEN
	assert.True(t, opts.serverAuthRequired)
}

func TestWithClientAuthentication(t *testing.T) {
	t.Parallel()

	// GIVEN
	opts := newOptions()

	apply := WithClientAuthentication(true)

	// WHEN
	apply(opts)

	// THEN
	assert.True(t, opts.clientAuthRequired)
}

func TestWithSecretsManager(t *testing.T) {
	t.Parallel()

	// GIVEN
	opts := newOptions()
	mgr := secretsmocks.NewManagerMock(t)

	apply := WithSecretsManager(mgr)

	// WHEN
	apply(opts)

	// THEN
	require.Same(t, mgr, opts.secretsManager)
}

func TestWithKeyObserver(t *testing.T) {
	t.Parallel()

	t.Run("non nil observer", func(t *testing.T) {
		// GIVEN
		opts := newOptions()
		observer := keyregistrymocks.NewKeyObserverMock(t)

		apply := WithKeyObserver(observer)

		// WHEN
		apply(opts)

		// THEN
		require.Same(t, observer, opts.keyObserver)
	})

	t.Run("nil observer", func(t *testing.T) {
		// GIVEN
		opts := newOptions()
		original := opts.keyObserver

		apply := WithKeyObserver(nil)

		// WHEN
		apply(opts)

		// THEN
		assert.Equal(t, original, opts.keyObserver)
	})
}

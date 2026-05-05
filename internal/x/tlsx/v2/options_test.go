package tlsx

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dadrus/heimdall/internal/keyregistry/v2"
	keyregistrymocks "github.com/dadrus/heimdall/internal/keyregistry/v2/mocks"
	"github.com/dadrus/heimdall/internal/secrets"
	secretsmocks "github.com/dadrus/heimdall/internal/secrets/mocks"
)

func TestWithServerAuthentication(t *testing.T) {
	t.Parallel()

	// GIVEN
	opts := newOptions()

	// WHEN
	WithServerAuthentication(true)(opts)

	// THEN
	assert.True(t, opts.serverAuthRequired)
}

func TestWithClientAuthentication(t *testing.T) {
	t.Parallel()

	// GIVEN
	opts := newOptions()

	// WHEN
	WithClientAuthentication(true)(opts)

	// THEN
	assert.True(t, opts.clientAuthRequired)
}

func TestWithSecretsManager(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		sm     secrets.Manager
		assert func(t *testing.T, opts *options)
	}{
		"nil manager":     {},
		"non nil manager": {sm: secretsmocks.NewManagerMock(t)},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			opts := newOptions()

			// WHEN
			WithSecretsManager(tc.sm)(opts)

			// THEN
			assert.Equal(t, tc.sm, opts.secretsManager)
		})
	}
}

func TestWithKeyObserver(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		ko     keyregistry.KeyObserver
		assert func(t *testing.T, opts *options)
	}{
		"nil observer":     {},
		"non nil observer": {ko: keyregistrymocks.NewKeyObserverMock(t)},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			opts := newOptions()

			// WHEN
			WithKeyObserver(tc.ko)(opts)

			// THEN
			if tc.ko == nil {
				assert.Equal(t, noopObserver{}, opts.keyObserver)
			} else {
				assert.Equal(t, tc.ko, opts.keyObserver)
			}
		})
	}
}

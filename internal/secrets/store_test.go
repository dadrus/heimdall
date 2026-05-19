package secrets

import (
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/secrets/types"
	secretsmocks "github.com/dadrus/heimdall/internal/secrets/types/mocks"
)

func TestNewSecretStore(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		manager    Manager
		refFactory ReferenceFactory
		assert     func(t *testing.T, store Store, err error)
	}{
		"creates secret store": {
			manager:    secretsmocks.NewManagerMock(t),
			refFactory: InternalRef,
			assert: func(t *testing.T, ss Store, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, ss)

				impl, ok := ss.(*store)
				require.True(t, ok)

				assert.NotNil(t, impl.manager)
				assert.NotNil(t, impl.refFactory)
				assert.NotNil(t, impl.informers)
				assert.Empty(t, impl.informers)
			},
		},
		"returns configuration error without manager": {
			refFactory: InternalRef,
			assert: func(t *testing.T, _ Store, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "secret manager is not configured")
			},
		},
		"returns configuration error without reference factory": {
			manager: secretsmocks.NewManagerMock(t),
			assert: func(t *testing.T, _ Store, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "secret reference factory is not configured")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			ss, err := NewStore(tc.manager, tc.refFactory)

			tc.assert(t, ss, err)
		})
	}
}

func TestSecretStoreRegisterSecret(t *testing.T) {
	t.Parallel()

	ref := Reference{
		Source:   "k8s",
		Selector: "api-key",
	}

	managerRef := InternalRef("k8s", "api-key")
	secret := types.NewStringSecret("api-key", "secret-value")

	for uc, tc := range map[string]struct {
		refFactory ReferenceFactory
		setup      func(t *testing.T, mgr *secretsmocks.ManagerMock)
		assert     func(t *testing.T, store Store, err error)
	}{
		"registers secret and makes it available": {
			refFactory: InternalRef,
			setup: func(t *testing.T, mgr *secretsmocks.ManagerMock) {
				t.Helper()

				mgr.EXPECT().
					ResolveSecret(mock.Anything, managerRef).
					Return(secret, nil)
				mgr.EXPECT().
					Subscribe(managerRef, mock.Anything).
					Return(func() {}, nil)
			},
			assert: func(t *testing.T, store Store, err error) {
				t.Helper()

				require.NoError(t, err)

				value, err := store.GetSecret(ref)
				require.NoError(t, err)
				assert.Equal(t, "secret-value", value)
			},
		},
		"returns start error from informer": {
			refFactory: InternalRef,
			setup: func(t *testing.T, mgr *secretsmocks.ManagerMock) {
				t.Helper()

				mgr.EXPECT().
					ResolveSecret(mock.Anything, managerRef).
					Return(nil, assert.AnError)
			},
			assert: func(t *testing.T, _ Store, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)
			},
		},
		"returns subscribe error from informer": {
			refFactory: InternalRef,
			setup: func(t *testing.T, mgr *secretsmocks.ManagerMock) {
				t.Helper()

				mgr.EXPECT().
					ResolveSecret(mock.Anything, managerRef).
					Return(secret, nil)
				mgr.EXPECT().
					Subscribe(managerRef, mock.Anything).
					Return(nil, assert.AnError)
			},
			assert: func(t *testing.T, _ Store, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			mgr := secretsmocks.NewManagerMock(t)
			tc.setup(t, mgr)

			store, err := NewStore(mgr, tc.refFactory)
			require.NoError(t, err)

			defer store.CleanUp()

			err = store.RegisterSecret(ref)

			tc.assert(t, store, err)
		})
	}
}

func TestSecretStoreRegisterSecretIsIdempotent(t *testing.T) {
	t.Parallel()

	ref := Reference{
		Source:   "k8s",
		Selector: "api-key",
	}

	managerRef := InternalRef("k8s", "api-key")
	secret := types.NewStringSecret("api-key", "secret-value")

	var refFactoryCalls atomic.Int32

	mgr := secretsmocks.NewManagerMock(t)
	mgr.EXPECT().
		ResolveSecret(mock.Anything, managerRef).
		Return(secret, nil)
	mgr.EXPECT().
		Subscribe(managerRef, mock.Anything).
		Return(func() {}, nil)

	store, err := NewStore(
		mgr,
		func(source, selector string) Reference {
			refFactoryCalls.Add(1)

			return InternalRef(source, selector)
		},
	)
	require.NoError(t, err)

	defer store.CleanUp()

	require.NoError(t, store.RegisterSecret(ref))
	require.NoError(t, store.RegisterSecret(ref))

	assert.EqualValues(t, 1, refFactoryCalls.Load())

	value, err := store.GetSecret(ref)
	require.NoError(t, err)
	assert.Equal(t, "secret-value", value)
}

func TestSecretStoreGetSecret(t *testing.T) {
	t.Parallel()

	ref := Reference{
		Source:   "k8s",
		Selector: "api-key",
	}

	t.Run("returns not found for unknown reference", func(t *testing.T) {
		t.Parallel()

		store, err := NewStore(secretsmocks.NewManagerMock(t), InternalRef)
		require.NoError(t, err)

		defer store.CleanUp()

		value, err := store.GetSecret(ref)

		require.Error(t, err)
		require.ErrorIs(t, err, ErrSecretNotFound)
		assert.Empty(t, value)
	})

	t.Run("returns not found after stop", func(t *testing.T) {
		t.Parallel()

		managerRef := InternalRef("k8s", "api-key")
		secret := types.NewStringSecret("api-key", "secret-value")

		var unsubscribed atomic.Bool

		mgr := secretsmocks.NewManagerMock(t)
		mgr.EXPECT().
			ResolveSecret(mock.Anything, managerRef).
			Return(secret, nil)
		mgr.EXPECT().
			Subscribe(managerRef, mock.Anything).
			Return(func() {
				unsubscribed.Store(true)
			}, nil)

		store, err := NewStore(mgr, InternalRef)
		require.NoError(t, err)

		require.NoError(t, store.RegisterSecret(ref))

		store.CleanUp()

		value, err := store.GetSecret(ref)

		require.Error(t, err)
		require.ErrorIs(t, err, ErrSecretNotFound)
		assert.Empty(t, value)
		assert.True(t, unsubscribed.Load())
	})
}

func TestSecretStoreStop(t *testing.T) {
	t.Parallel()

	refA := Reference{Source: "k8s", Selector: "api-key-a"}
	refB := Reference{Source: "k8s", Selector: "api-key-b"}

	managerRefA := InternalRef("k8s", "api-key-a")
	managerRefB := InternalRef("k8s", "api-key-b")

	var unsubscribed atomic.Int32

	mgr := secretsmocks.NewManagerMock(t)
	mgr.EXPECT().
		ResolveSecret(mock.Anything, managerRefA).
		Return(types.NewStringSecret("api-key-a", "secret-a"), nil)
	mgr.EXPECT().
		Subscribe(managerRefA, mock.Anything).
		Return(func() {
			unsubscribed.Add(1)
		}, nil)

	mgr.EXPECT().
		ResolveSecret(mock.Anything, managerRefB).
		Return(types.NewStringSecret("api-key-b", "secret-b"), nil)
	mgr.EXPECT().
		Subscribe(managerRefB, mock.Anything).
		Return(func() {
			unsubscribed.Add(1)
		}, nil)

	ss, err := NewStore(mgr, InternalRef)
	require.NoError(t, err)

	require.NoError(t, ss.RegisterSecret(refA))
	require.NoError(t, ss.RegisterSecret(refB))

	ss.CleanUp()

	impl := ss.(*store)

	assert.EqualValues(t, 2, unsubscribed.Load())
	assert.Empty(t, impl.informers)

	value, err := ss.GetSecret(refA)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrSecretNotFound)
	assert.Empty(t, value)
}

func TestStringSecretValue(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		secret Secret
		assert func(t *testing.T, value string, err error)
	}{
		"returns string secret value": {
			secret: types.NewStringSecret("api-key", "secret-value"),
			assert: func(t *testing.T, value string, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "secret-value", value)
			},
		},
		"returns kind mismatch for non string secret": {
			secret: types.NewCredentials("credentials", map[string]any{
				"user":     "foo",
				"password": "bar",
			}),
			assert: func(t *testing.T, value string, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrSecretKindMismatch)
				assert.Empty(t, value)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			value, err := stringSecretValue(tc.secret)

			tc.assert(t, value, err)
		})
	}
}

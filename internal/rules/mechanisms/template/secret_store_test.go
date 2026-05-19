package template

import (
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/secrets"
	secretsmocks "github.com/dadrus/heimdall/internal/secrets/mocks"
	"github.com/dadrus/heimdall/internal/secrets/types"
)

func TestNewSecretStore(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		manager    secrets.Manager
		refFactory SecretReferenceFactory
		assert     func(t *testing.T, store SecretStore, err error)
	}{
		"creates secret store": {
			manager:    secretsmocks.NewManagerMock(t),
			refFactory: secrets.InternalRef,
			assert: func(t *testing.T, store SecretStore, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, store)

				impl, ok := store.(*secretStore)
				require.True(t, ok)

				assert.NotNil(t, impl.manager)
				assert.NotNil(t, impl.refFactory)
				assert.NotNil(t, impl.informers)
				assert.Empty(t, impl.informers)
			},
		},
		"returns configuration error without manager": {
			refFactory: secrets.InternalRef,
			assert: func(t *testing.T, _ SecretStore, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "secret manager is not configured")
			},
		},
		"returns configuration error without reference factory": {
			manager: secretsmocks.NewManagerMock(t),
			assert: func(t *testing.T, _ SecretStore, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "secret reference factory is not configured")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			store, err := NewSecretStore(tc.manager, tc.refFactory)

			tc.assert(t, store, err)
		})
	}
}

func TestSecretStoreRegisterSecret(t *testing.T) {
	t.Parallel()

	ref := SecretReference{
		Source:   "k8s",
		Selector: "api-key",
	}

	managerRef := secrets.InternalRef("k8s", "api-key")
	secret := types.NewStringSecret("api-key", "secret-value")

	for uc, tc := range map[string]struct {
		refFactory SecretReferenceFactory
		setup      func(t *testing.T, mgr *secretsmocks.ManagerMock)
		assert     func(t *testing.T, store SecretStore, err error)
	}{
		"registers secret and makes it available": {
			refFactory: secrets.InternalRef,
			setup: func(t *testing.T, mgr *secretsmocks.ManagerMock) {
				t.Helper()

				mgr.EXPECT().
					ResolveSecret(mock.Anything, managerRef).
					Return(secret, nil)
				mgr.EXPECT().
					Subscribe(managerRef, mock.Anything).
					Return(func() {}, nil)
			},
			assert: func(t *testing.T, store SecretStore, err error) {
				t.Helper()

				require.NoError(t, err)

				value, err := store.GetSecret(ref)
				require.NoError(t, err)
				assert.Equal(t, "secret-value", value)
			},
		},
		"returns start error from informer": {
			refFactory: secrets.InternalRef,
			setup: func(t *testing.T, mgr *secretsmocks.ManagerMock) {
				t.Helper()

				mgr.EXPECT().
					ResolveSecret(mock.Anything, managerRef).
					Return(nil, assert.AnError)
			},
			assert: func(t *testing.T, _ SecretStore, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)
			},
		},
		"returns subscribe error from informer": {
			refFactory: secrets.InternalRef,
			setup: func(t *testing.T, mgr *secretsmocks.ManagerMock) {
				t.Helper()

				mgr.EXPECT().
					ResolveSecret(mock.Anything, managerRef).
					Return(secret, nil)
				mgr.EXPECT().
					Subscribe(managerRef, mock.Anything).
					Return(nil, assert.AnError)
			},
			assert: func(t *testing.T, _ SecretStore, err error) {
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

			store, err := NewSecretStore(mgr, tc.refFactory)
			require.NoError(t, err)

			defer store.CleanUp()

			err = store.RegisterSecret(ref)

			tc.assert(t, store, err)
		})
	}
}

func TestSecretStoreRegisterSecretIsIdempotent(t *testing.T) {
	t.Parallel()

	ref := SecretReference{
		Source:   "k8s",
		Selector: "api-key",
	}

	managerRef := secrets.InternalRef("k8s", "api-key")
	secret := types.NewStringSecret("api-key", "secret-value")

	var refFactoryCalls atomic.Int32

	mgr := secretsmocks.NewManagerMock(t)
	mgr.EXPECT().
		ResolveSecret(mock.Anything, managerRef).
		Return(secret, nil)
	mgr.EXPECT().
		Subscribe(managerRef, mock.Anything).
		Return(func() {}, nil)

	store, err := NewSecretStore(
		mgr,
		func(source, selector string) secrets.Reference {
			refFactoryCalls.Add(1)

			return secrets.InternalRef(source, selector)
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

	ref := SecretReference{
		Source:   "k8s",
		Selector: "api-key",
	}

	t.Run("returns not found for unknown reference", func(t *testing.T) {
		t.Parallel()

		store, err := NewSecretStore(secretsmocks.NewManagerMock(t), secrets.InternalRef)
		require.NoError(t, err)

		defer store.CleanUp()

		value, err := store.GetSecret(ref)

		require.Error(t, err)
		require.ErrorIs(t, err, secrets.ErrSecretNotFound)
		assert.Empty(t, value)
	})

	t.Run("returns not found after stop", func(t *testing.T) {
		t.Parallel()

		managerRef := secrets.InternalRef("k8s", "api-key")
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

		store, err := NewSecretStore(mgr, secrets.InternalRef)
		require.NoError(t, err)

		require.NoError(t, store.RegisterSecret(ref))

		store.CleanUp()

		value, err := store.GetSecret(ref)

		require.Error(t, err)
		require.ErrorIs(t, err, secrets.ErrSecretNotFound)
		assert.Empty(t, value)
		assert.True(t, unsubscribed.Load())
	})
}

func TestSecretStoreStop(t *testing.T) {
	t.Parallel()

	refA := SecretReference{Source: "k8s", Selector: "api-key-a"}
	refB := SecretReference{Source: "k8s", Selector: "api-key-b"}

	managerRefA := secrets.InternalRef("k8s", "api-key-a")
	managerRefB := secrets.InternalRef("k8s", "api-key-b")

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

	store, err := NewSecretStore(mgr, secrets.InternalRef)
	require.NoError(t, err)

	require.NoError(t, store.RegisterSecret(refA))
	require.NoError(t, store.RegisterSecret(refB))

	store.CleanUp()

	impl := store.(*secretStore)

	assert.EqualValues(t, 2, unsubscribed.Load())
	assert.Empty(t, impl.informers)

	value, err := store.GetSecret(refA)
	require.Error(t, err)
	require.ErrorIs(t, err, secrets.ErrSecretNotFound)
	assert.Empty(t, value)
}

func TestStringSecretValue(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		secret secrets.Secret
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
				require.ErrorIs(t, err, secrets.ErrSecretKindMismatch)
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

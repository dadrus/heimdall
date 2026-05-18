package informer

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/secrets"
	secretsmocks "github.com/dadrus/heimdall/internal/secrets/mocks"
	"github.com/dadrus/heimdall/internal/secrets/types"
)

func TestSecretResolverStart(t *testing.T) {
	t.Parallel()

	ref := secrets.InternalRef("source", "selector")
	secret := types.NewStringSecret("selector", "value")

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, sm *secretsmocks.ManagerMock)
		assert func(t *testing.T, err error, resolver *SecretInformer[string])
	}{
		"starts successfully": {
			setup: func(t *testing.T, sm *secretsmocks.ManagerMock) {
				t.Helper()

				sm.EXPECT().ResolveSecret(mock.Anything, ref).Return(secret, nil)
				sm.EXPECT().Subscribe(ref, mock.Anything).Return(func() {}, nil)
			},
			assert: func(t *testing.T, err error, resolver *SecretInformer[string]) {
				t.Helper()

				require.NoError(t, err)

				value, ok := resolver.Get()
				require.True(t, ok)
				require.Equal(t, "value", value)
			},
		},
		"fails if initial secret resolution fails": {
			setup: func(t *testing.T, sm *secretsmocks.ManagerMock) {
				t.Helper()

				sm.EXPECT().ResolveSecret(mock.Anything, ref).Return(nil, secrets.ErrSecretNotFound)
			},
			assert: func(t *testing.T, err error, resolver *SecretInformer[string]) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, secrets.ErrSecretNotFound)

				value, ok := resolver.Get()
				require.False(t, ok)
				require.Empty(t, value)
			},
		},
		"fails if subscription setup fails": {
			setup: func(t *testing.T, sm *secretsmocks.ManagerMock) {
				t.Helper()

				sm.EXPECT().ResolveSecret(mock.Anything, ref).Return(secret, nil)
				sm.EXPECT().Subscribe(ref, mock.Anything).Return(nil, assert.AnError)
			},
			assert: func(t *testing.T, err error, resolver *SecretInformer[string]) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, secrets.ErrSubscribeFailed)

				value, ok := resolver.Get()
				require.True(t, ok)
				require.Equal(t, "value", value)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			sm := secretsmocks.NewManagerMock(t)
			tc.setup(t, sm)

			resolver := &SecretInformer[string]{
				Manager:   sm,
				Reference: ref,
				Converter: func(secret secrets.Secret) (string, error) {
					t.Helper()

					stringSecret, ok := secret.(secrets.StringSecret)
					require.True(t, ok)

					return stringSecret.Value(), nil
				},
			}

			err := resolver.Start(t.Context())

			tc.assert(t, err, resolver)
		})
	}
}

func TestSecretResolverReload(t *testing.T) {
	t.Parallel()

	ref := secrets.InternalRef("source", "selector")

	for uc, tc := range map[string]struct {
		setup               func(t *testing.T, sm *secretsmocks.ManagerMock) func(context.Context) error
		converter           Converter[secrets.Secret, string]
		missingSecretPolicy MissingSecretPolicy[secrets.Secret, string]
		assert              func(t *testing.T, err error, resolver *SecretInformer[string], updates []string, reported []error)
	}{
		"updates cached value on change": {
			converter: func(secret secrets.Secret) (string, error) {
				stringSecret, ok := secret.(secrets.StringSecret)
				if !ok {
					return "", errors.New("unexpected secret type")
				}

				return stringSecret.Value(), nil
			},
			setup: func(t *testing.T, sm *secretsmocks.ManagerMock) func(context.Context) error {
				t.Helper()

				current := types.NewStringSecret("selector", "initial")
				next := types.NewStringSecret("selector", "updated")

				sm.EXPECT().
					ResolveSecret(mock.Anything, ref).
					Return(current, nil).
					Once()

				var callback func(context.Context) error

				sm.EXPECT().
					Subscribe(ref, mock.Anything).
					RunAndReturn(func(_ secrets.Reference, cb func(context.Context) error) (func(), error) {
						callback = cb

						sm.EXPECT().
							ResolveSecret(mock.Anything, ref).
							Return(next, nil).
							Once()

						return func() {}, nil
					})

				return func(ctx context.Context) error {
					t.Helper()
					require.NotNil(t, callback)

					return callback(ctx)
				}
			},
			assert: func(t *testing.T, err error, resolver *SecretInformer[string], updates []string, reported []error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, []string{"initial", "updated"}, updates)
				require.Empty(t, reported)

				value, ok := resolver.Get()
				require.True(t, ok)
				require.Equal(t, "updated", value)
			},
		},
		"keeps previous value on conversion error": {
			converter: func(secret secrets.Secret) (string, error) {
				stringSecret, ok := secret.(secrets.StringSecret)
				if !ok {
					return "", errors.New("unexpected secret type")
				}

				if stringSecret.Value() == "invalid" {
					return "", errors.New("invalid value")
				}

				return stringSecret.Value(), nil
			},
			setup: func(t *testing.T, sm *secretsmocks.ManagerMock) func(context.Context) error {
				t.Helper()

				initial := types.NewStringSecret("selector", "initial")
				invalid := types.NewStringSecret("selector", "invalid")

				sm.EXPECT().
					ResolveSecret(mock.Anything, ref).
					Return(initial, nil).
					Once()

				var callback func(context.Context) error

				sm.EXPECT().
					Subscribe(ref, mock.Anything).
					RunAndReturn(func(_ secrets.Reference, cb func(context.Context) error) (func(), error) {
						callback = cb

						sm.EXPECT().
							ResolveSecret(mock.Anything, ref).
							Return(invalid, nil).
							Once()

						return func() {}, nil
					})

				return func(ctx context.Context) error {
					t.Helper()
					require.NotNil(t, callback)

					return callback(ctx)
				}
			},
			assert: func(t *testing.T, err error, resolver *SecretInformer[string], updates []string, reported []error) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, updates, 1)
				require.Equal(t, "initial", updates[0])
				require.Len(t, reported, 1)
				require.ErrorContains(t, reported[0], "invalid value")

				value, ok := resolver.Get()
				require.True(t, ok)
				require.Equal(t, "initial", value)
			},
		},
		"clears cached value if configured secret disappears": {
			converter: func(secret secrets.Secret) (string, error) {
				stringSecret, ok := secret.(secrets.StringSecret)
				if !ok {
					return "", errors.New("unexpected secret type")
				}

				return stringSecret.Value(), nil
			},
			missingSecretPolicy: ClearSecret[string]{},
			setup: func(t *testing.T, sm *secretsmocks.ManagerMock) func(context.Context) error {
				t.Helper()

				initial := types.NewStringSecret("selector", "initial")

				sm.EXPECT().
					ResolveSecret(mock.Anything, ref).
					Return(initial, nil).
					Once()

				var callback func(context.Context) error

				sm.EXPECT().
					Subscribe(ref, mock.Anything).
					RunAndReturn(func(_ secrets.Reference, cb func(context.Context) error) (func(), error) {
						callback = cb

						sm.EXPECT().
							ResolveSecret(mock.Anything, ref).
							Return(nil, secrets.ErrSecretNotFound).
							Once()

						return func() {}, nil
					})

				return func(ctx context.Context) error {
					t.Helper()
					require.NotNil(t, callback)

					return callback(ctx)
				}
			},
			assert: func(t *testing.T, err error, resolver *SecretInformer[string], updates []string, reported []error) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, updates, 1)
				require.Equal(t, "initial", updates[0])
				require.Len(t, reported, 1)
				require.ErrorIs(t, reported[0], secrets.ErrSecretNotFound)

				value, ok := resolver.Get()
				require.False(t, ok)
				require.Empty(t, value)
			},
		},
		"returns error if configured to fail on missing secret": {
			converter: func(secret secrets.Secret) (string, error) {
				stringSecret, ok := secret.(secrets.StringSecret)
				if !ok {
					return "", errors.New("unexpected secret type")
				}

				return stringSecret.Value(), nil
			},
			missingSecretPolicy: FailSecret[string]{},
			setup: func(t *testing.T, sm *secretsmocks.ManagerMock) func(context.Context) error {
				t.Helper()

				initial := types.NewStringSecret("selector", "initial")

				sm.EXPECT().
					ResolveSecret(mock.Anything, ref).
					Return(initial, nil).
					Once()

				var callback func(context.Context) error

				sm.EXPECT().
					Subscribe(ref, mock.Anything).
					RunAndReturn(func(_ secrets.Reference, cb func(context.Context) error) (func(), error) {
						callback = cb

						sm.EXPECT().
							ResolveSecret(mock.Anything, ref).
							Return(nil, secrets.ErrSecretNotFound).
							Once()

						return func() {}, nil
					})

				return func(ctx context.Context) error {
					t.Helper()
					require.NotNil(t, callback)

					return callback(ctx)
				}
			},
			assert: func(t *testing.T, err error, resolver *SecretInformer[string], updates []string, reported []error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, secrets.ErrSecretNotFound)
				require.Len(t, updates, 1)
				require.Equal(t, "initial", updates[0])
				require.Len(t, reported, 1)
				require.ErrorIs(t, reported[0], secrets.ErrSecretNotFound)

				value, ok := resolver.Get()
				require.True(t, ok)
				require.Equal(t, "initial", value)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			sm := secretsmocks.NewManagerMock(t)

			var (
				updates  []string
				reported []error
			)

			policy := tc.missingSecretPolicy
			if policy == nil {
				policy = KeepPreviousSecret[string]{}
			}

			converter := tc.converter
			if converter == nil {
				converter = func(secret secrets.Secret) (string, error) {
					t.Helper()

					stringSecret, ok := secret.(secrets.StringSecret)
					require.True(t, ok)

					return stringSecret.Value(), nil
				}
			}

			reload := tc.setup(t, sm)

			resolver := &SecretInformer[string]{
				Manager:             sm,
				Reference:           ref,
				Converter:           converter,
				MissingSecretPolicy: policy,
				OnUpdate: func(_ context.Context, _ secrets.Secret, value string) {
					updates = append(updates, value)
				},
				OnError: func(_ context.Context, err error) {
					reported = append(reported, err)
				},
			}

			err := resolver.Start(t.Context())
			require.NoError(t, err)

			err = reload(t.Context())

			tc.assert(t, err, resolver, updates, reported)
		})
	}
}

func TestSecretResolverStop(t *testing.T) {
	t.Parallel()

	ref := secrets.InternalRef("source", "selector")
	secret := types.NewStringSecret("selector", "value")
	stopped := false

	sm := secretsmocks.NewManagerMock(t)
	sm.EXPECT().ResolveSecret(mock.Anything, ref).Return(secret, nil)
	sm.EXPECT().Subscribe(ref, mock.Anything).Return(func() { stopped = true }, nil)

	resolver := &SecretInformer[string]{
		Manager:   sm,
		Reference: ref,
		Converter: func(secret secrets.Secret) (string, error) {
			t.Helper()

			stringSecret, ok := secret.(secrets.StringSecret)
			require.True(t, ok)

			return stringSecret.Value(), nil
		},
	}

	err := resolver.Start(t.Context())
	require.NoError(t, err)

	resolver.Stop()
	assert.True(t, stopped)
}

func TestResolverStartPanics(t *testing.T) {
	t.Parallel()

	ref := secrets.InternalRef("source", "selector")
	converter := func(secret secrets.Secret) (string, error) {
		stringSecret, ok := secret.(secrets.StringSecret)
		if !ok {
			return "", errors.New("unexpected secret type")
		}

		return stringSecret.Value(), nil
	}

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T) *Informer[secrets.Secret, string]
		assert func(t *testing.T, panicValue any)
	}{
		"panics if manager is nil": {
			setup: func(t *testing.T) *Informer[secrets.Secret, string] {
				t.Helper()

				return &Informer[secrets.Secret, string]{
					Reference: ref,
					Source:    SecretSource{},
					Converter: converter,
				}
			},
			assert: func(t *testing.T, panicValue any) {
				t.Helper()

				require.Equal(t, "secret cache: manager is nil", panicValue)
			},
		},
		"panics if source is nil": {
			setup: func(t *testing.T) *Informer[secrets.Secret, string] {
				t.Helper()

				return &Informer[secrets.Secret, string]{
					Manager:   secretsmocks.NewManagerMock(t),
					Reference: ref,
					Converter: converter,
				}
			},
			assert: func(t *testing.T, panicValue any) {
				t.Helper()

				require.Equal(t, "secret cache: resolver is nil", panicValue)
			},
		},
		"panics if converter is nil": {
			setup: func(t *testing.T) *Informer[secrets.Secret, string] {
				t.Helper()

				return &Informer[secrets.Secret, string]{
					Manager:   secretsmocks.NewManagerMock(t),
					Reference: ref,
					Source:    SecretSource{},
				}
			},
			assert: func(t *testing.T, panicValue any) {
				t.Helper()

				require.Equal(t, "secret cache: converter is nil", panicValue)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			resolver := tc.setup(t)

			var recovered any

			func() {
				defer func() {
					recovered = recover()
				}()

				_ = resolver.Start(t.Context())
			}()

			require.NotNil(t, recovered)
			tc.assert(t, recovered)
		})
	}
}

func TestCredentialsResolverStart(t *testing.T) {
	t.Parallel()

	ref := secrets.InternalRef("source", "redis")
	creds := types.NewCredentials("redis", map[string]any{
		"username": "foo",
		"password": "bar",
	})

	sm := secretsmocks.NewManagerMock(t)
	sm.EXPECT().ResolveCredentials(mock.Anything, ref).Return(creds, nil)
	sm.EXPECT().Subscribe(ref, mock.Anything).Return(func() {}, nil)

	resolver := &CredentialsInformer[string]{
		Manager:   sm,
		Reference: ref,
		Converter: func(credentials secrets.Credentials) (string, error) {
			t.Helper()

			type decoded struct {
				Username string `mapstructure:"username"`
				Password string `mapstructure:"password"`
			}

			var out decoded
			require.NoError(t, credentials.Decode(&out))

			return out.Username + ":" + out.Password, nil
		},
	}

	err := resolver.Start(t.Context())
	require.NoError(t, err)

	value, ok := resolver.Get()
	require.True(t, ok)
	require.Equal(t, "foo:bar", value)
}

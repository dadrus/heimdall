package source

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/secrets2/provider"
	providermocks "github.com/dadrus/heimdall/internal/secrets2/provider/mocks"
	"github.com/dadrus/heimdall/internal/secrets2/registry"
	"github.com/dadrus/heimdall/internal/secrets2/types"
)

func TestProviderObserverNotify(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		sourceName string
		event      provider.ChangeEvent
		want       Event
	}{
		"adds source name to source wide event": {
			sourceName: "vault",
			event:      provider.ChangeEvent{},
			want:       Event{Source: "vault"},
		},
		"adds source name to selector event": {
			sourceName: "k8s",
			event: provider.ChangeEvent{
				Selectors: []provider.Selector{{Value: "service-account", Namespace: "team-a"}},
			},
			want: Event{
				Source:    "k8s",
				Selectors: []provider.Selector{{Value: "service-account", Namespace: "team-a"}},
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			observer := NewObserverMock(t)
			observer.EXPECT().Notify(tc.want)

			po := &providerObserver{name: tc.sourceName, o: observer}
			po.Notify(tc.event)
		})
	}
}

func TestNewSecretSource(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		conf   config.SecretSourceConfig
		setup  func(t *testing.T, providerType string) provider.Factory
		assert func(t *testing.T, src *secretSource, err error)
	}{
		"creates source from registered provider": {
			conf: config.SecretSourceConfig{
				AllowInRules: true,
				Config:       map[string]any{"foo": "bar"},
			},
			setup: func(t *testing.T, _ string) provider.Factory {
				t.Helper()

				return provider.FactoryFunc(func(args provider.Args) (provider.Provider, error) {
					require.Equal(t, map[string]any{"foo": "bar"}, args.Config)
					require.NotNil(t, args.Logger)
					require.NotNil(t, args.Observer)
					require.NotNil(t, args.Resolver)

					prv := providermocks.NewProviderMock(t)
					prv.EXPECT().
						Dependencies().
						Return([]types.Reference{
							{Source: "pem", Selector: "server"},
						})

					return prv, nil
				})
			},
			assert: func(t *testing.T, src *secretSource, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, src)

				require.Equal(t, "vault", src.Name())
				require.True(t, src.AccessFromRulesAllowed())
				require.Equal(t, []types.Reference{
					{Source: "pem", Selector: "server"},
				}, src.Dependencies())
			},
		},
		"returns unsupported provider type error": {
			conf: config.SecretSourceConfig{
				Type: "does-not-exist",
			},
			setup: func(t *testing.T, _ string) provider.Factory {
				t.Helper()

				return nil
			},
			assert: func(t *testing.T, src *secretSource, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, types.ErrUnsupportedProviderType)
				require.Nil(t, src)
			},
		},
		"returns provider creation error": {
			setup: func(t *testing.T, _ string) provider.Factory {
				t.Helper()

				return provider.FactoryFunc(func(provider.Args) (provider.Provider, error) {
					return nil, assert.AnError
				})
			},
			assert: func(t *testing.T, src *secretSource, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)
				require.Nil(t, src)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			providerType := uniqueProviderType(t, uc)
			conf := tc.conf

			if conf.Type == "" {
				conf.Type = providerType
			}

			factory := tc.setup(t, providerType)
			if factory != nil {
				registry.Register(providerType, factory)

				t.Cleanup(func() {
					registry.Unregister(providerType)
				})
			}

			observer := NewObserverMock(t)
			resolver := providermocks.NewDependenciesResolverMock(t)

			src, err := newSecretSource(
				"vault",
				conf,
				zerolog.Nop(),
				nil,
				observer,
				resolver,
			)

			tc.assert(t, src, err)
		})
	}
}

func TestSecretSourceDelegatesToProvider(t *testing.T) {
	t.Parallel()

	secret := types.NewStringSecret("server", "value")
	secretSet := []types.Secret{secret}
	creds := types.NewCredentials("github", map[string]any{
		"client_id":     "heimdall",
		"client_secret": "secret",
	})

	for uc, tc := range map[string]struct {
		setup  func(*providermocks.ProviderMock)
		call   func(*secretSource) (any, error)
		assert func(t *testing.T, result any, err error)
	}{
		"start": {
			setup: func(prv *providermocks.ProviderMock) {
				prv.EXPECT().Start(mock.Anything).Return(nil)
			},
			call: func(src *secretSource) (any, error) {
				return nil, src.Start(context.Background())
			},
			assert: func(t *testing.T, _ any, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"stop": {
			setup: func(prv *providermocks.ProviderMock) {
				prv.EXPECT().Stop(mock.Anything).Return(nil)
			},
			call: func(src *secretSource) (any, error) {
				return nil, src.Stop(context.Background())
			},
			assert: func(t *testing.T, _ any, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"is namespace aware": {
			setup: func(prv *providermocks.ProviderMock) {
				prv.EXPECT().IsNamespaceAware().Return(true)
			},
			call: func(src *secretSource) (any, error) {
				return src.IsNamespaceAware(), nil
			},
			assert: func(t *testing.T, result any, err error) {
				t.Helper()

				require.NoError(t, err)
				require.True(t, result.(bool))
			},
		},
		"get secret": {
			setup: func(prv *providermocks.ProviderMock) {
				prv.EXPECT().
					GetSecret(mock.Anything, provider.Selector{Value: "server"}).
					Return(secret, nil)
			},
			call: func(src *secretSource) (any, error) {
				return src.GetSecret(context.Background(), provider.Selector{Value: "server"})
			},
			assert: func(t *testing.T, result any, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, secret, result)
			},
		},
		"get secret set": {
			setup: func(prv *providermocks.ProviderMock) {
				prv.EXPECT().
					GetSecretSet(mock.Anything, provider.Selector{Value: "server"}).
					Return(secretSet, nil)
			},
			call: func(src *secretSource) (any, error) {
				return src.GetSecretSet(context.Background(), provider.Selector{Value: "server"})
			},
			assert: func(t *testing.T, result any, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, secretSet, result)
			},
		},
		"get credentials": {
			setup: func(prv *providermocks.ProviderMock) {
				prv.EXPECT().
					GetCredentials(mock.Anything, provider.Selector{Value: "github"}).
					Return(creds, nil)
			},
			call: func(src *secretSource) (any, error) {
				return src.GetCredentials(context.Background(), provider.Selector{Value: "github"})
			},
			assert: func(t *testing.T, result any, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, creds, result)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			prv := providermocks.NewProviderMock(t)
			tc.setup(prv)

			src := &secretSource{
				name:         "test",
				allowInRules: true,
				sr:           &secretsResolver{},
				p:            prv,
				logger:       zerolog.Nop(),
			}

			result, err := tc.call(src)
			tc.assert(t, result, err)
		})
	}
}

func TestSecretSourceRun(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setupProvider func(*providermocks.ProviderMock)
		setupObserver func(*ObserverMock)
		wantLog       string
	}{
		"restarts provider and notifies source wide event": {
			setupProvider: func(prv *providermocks.ProviderMock) {
				prv.EXPECT().Stop(mock.Anything).Return(nil)
				prv.EXPECT().Start(mock.Anything).Return(nil)
			},
			setupObserver: func(observer *ObserverMock) {
				observer.EXPECT().Notify(Event{Source: "vault"})
			},
			wantLog: "Secret source restarted after dependency change",
		},
		"does not start or notify if stop fails": {
			setupProvider: func(prv *providermocks.ProviderMock) {
				prv.EXPECT().Stop(mock.Anything).Return(assert.AnError)
			},
			setupObserver: func(*ObserverMock) {},
			wantLog:       "Stopping secret source failed",
		},
		"does not notify if start fails": {
			setupProvider: func(prv *providermocks.ProviderMock) {
				prv.EXPECT().Stop(mock.Anything).Return(nil)
				prv.EXPECT().Start(mock.Anything).Return(assert.AnError)
			},
			setupObserver: func(*ObserverMock) {},
			wantLog:       "Starting secret source failed",
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			var logs bytes.Buffer

			logger := zerolog.New(&logs)

			prv := providermocks.NewProviderMock(t)
			tc.setupProvider(prv)

			observer := NewObserverMock(t)
			tc.setupObserver(observer)

			src := &secretSource{
				name:     "vault",
				sr:       &secretsResolver{},
				p:        prv,
				logger:   logger,
				observer: observer,
			}

			src.Run()

			require.Contains(t, logs.String(), tc.wantLog)
		})
	}
}

func TestSecretSourceUnschedule(t *testing.T) {
	t.Parallel()

	t.Run("cancels scheduled restart task", func(t *testing.T) {
		t.Parallel()

		var logs bytes.Buffer

		src := &secretSource{
			name:   "vault",
			logger: zerolog.New(&logs),
		}

		require.True(t, src.Schedule())

		src.Unschedule(assert.AnError)

		require.False(t, src.BeginRun())
		require.Contains(t, logs.String(), "Failed scheduling secret source restart task")
	})
}

func TestSecretSourceStopTask(t *testing.T) {
	t.Parallel()

	src := &secretSource{
		name:   "vault",
		logger: zerolog.Nop(),
	}

	require.True(t, src.Schedule())

	src.stopTask()

	require.False(t, src.Schedule())
	require.False(t, src.BeginRun())
}

func uniqueProviderType(t *testing.T, suffix string) string {
	t.Helper()

	replacer := strings.NewReplacer(
		"/", "-",
		" ", "-",
		"_", "-",
	)

	return "test-" + strings.ToLower(replacer.Replace(t.Name())) + "-" + suffix
}

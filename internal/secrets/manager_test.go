package secrets

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/secrets/registry"
	"github.com/dadrus/heimdall/internal/secrets/source"
	"github.com/dadrus/heimdall/internal/secrets/types"
	typemocks "github.com/dadrus/heimdall/internal/secrets/types/mocks"
)

type providerSetup struct {
	sourceName   string
	sourceType   string
	allowInRules bool
	config       map[string]any
	setup        func(t *testing.T, args types.ProviderArgs) types.Provider
}

func newManagerWithProviderMocks(t *testing.T, providers ...providerSetup) *manager {
	t.Helper()

	cfg := &config.Configuration{
		SecretManagement: make(config.SecretManagement, len(providers)),
	}

	for _, provider := range providers {
		provider := provider

		sourceType := provider.sourceType
		if sourceType == "" {
			sourceType = uniqueProviderType(t, provider.sourceName)
		}

		cfg.SecretManagement[provider.sourceName] = config.SecretSourceConfig{
			Type:         sourceType,
			AllowInRules: provider.allowInRules,
			Config:       provider.config,
		}

		registry.Register(sourceType, types.ProviderFactoryFunc(func(args types.ProviderArgs) (types.Provider, error) {
			if provider.setup == nil {
				p := typemocks.NewProviderMock(t)
				p.EXPECT().Dependencies().Return(nil)

				return p, nil
			}

			return provider.setup(t, args), nil
		}))

		t.Cleanup(func() {
			registry.Unregister(sourceType)
		})
	}

	mgr, err := NewManager(cfg, zerolog.Nop(), nil)
	require.NoError(t, err)

	return mgr
}

func uniqueProviderType(t *testing.T, sourceName string) string {
	t.Helper()

	replacer := strings.NewReplacer(
		"/", "-",
		" ", "-",
		"_", "-",
	)

	return "test-" + strings.ToLower(replacer.Replace(t.Name())) + "-" + sourceName
}

func TestManagerNew(t *testing.T) {
	t.Parallel()

	t.Run("creates manager with registered provider", func(t *testing.T) {
		t.Parallel()

		mgr := newManagerWithProviderMocks(t, providerSetup{
			sourceName: "inline",
			config:     map[string]any{"foo": "bar"},
			setup: func(t *testing.T, args types.ProviderArgs) types.Provider {
				t.Helper()

				require.Equal(t, map[string]any{"foo": "bar"}, args.Config)
				require.NotNil(t, args.Logger)
				require.NotNil(t, args.Observer)
				require.NotNil(t, args.Resolver)

				p := typemocks.NewProviderMock(t)
				p.EXPECT().Dependencies().Return(nil)

				return p
			},
		})
		defer mgr.dispatcher.stop()

		require.Contains(t, mgr.sources, "inline")
		require.Len(t, mgr.order, 1)
		require.Equal(t, "inline", mgr.order[0].s.Name())
	})

	t.Run("fails for unsupported provider type", func(t *testing.T) {
		t.Parallel()

		cfg := &config.Configuration{
			SecretManagement: config.SecretManagement{
				"bad": {Type: uniqueProviderType(t, "unsupported")},
			},
		}

		mgr, err := NewManager(cfg, zerolog.Nop(), nil)

		require.Error(t, err)
		require.ErrorIs(t, err, registry.ErrUnsupportedProviderType)
		require.Nil(t, mgr)
	})

	t.Run("fails for provider factory error", func(t *testing.T) {
		t.Parallel()

		providerType := uniqueProviderType(t, "broken")
		registry.Register(providerType, types.ProviderFactoryFunc(func(types.ProviderArgs) (types.Provider, error) {
			return nil, assert.AnError
		}))
		t.Cleanup(func() {
			registry.Unregister(providerType)
		})

		cfg := &config.Configuration{
			SecretManagement: config.SecretManagement{
				"broken": {Type: providerType},
			},
		}

		mgr, err := NewManager(cfg, zerolog.Nop(), nil)

		require.Error(t, err)
		require.ErrorIs(t, err, assert.AnError)
		require.Nil(t, mgr)
	})

	t.Run("orders dependency before dependent", func(t *testing.T) {
		t.Parallel()

		mgr := newManagerWithProviderMocks(t,
			providerSetup{
				sourceName: "pem",
				setup: func(t *testing.T, _ types.ProviderArgs) types.Provider {
					t.Helper()

					p := typemocks.NewProviderMock(t)
					p.EXPECT().Dependencies().Return(nil)

					return p
				},
			},
			providerSetup{
				sourceName: "vault",
				setup: func(t *testing.T, _ types.ProviderArgs) types.Provider {
					t.Helper()

					p := typemocks.NewProviderMock(t)
					p.EXPECT().Dependencies().Return([]types.Reference{
						{Source: "pem", Selector: "server"},
					})

					return p
				},
			},
		)
		defer mgr.dispatcher.stop()

		require.Len(t, mgr.order, 2)
		require.Equal(t, "pem", mgr.order[0].s.Name())
		require.Equal(t, "vault", mgr.order[1].s.Name())
	})

	t.Run("fails for unknown dependency", func(t *testing.T) {
		t.Parallel()

		providerType := uniqueProviderType(t, "vault")
		registry.Register(providerType, types.ProviderFactoryFunc(func(types.ProviderArgs) (types.Provider, error) {
			p := typemocks.NewProviderMock(t)
			p.EXPECT().Dependencies().Return([]types.Reference{
				{Source: "missing", Selector: "server"},
			})

			return p, nil
		}))
		t.Cleanup(func() {
			registry.Unregister(providerType)
		})

		cfg := &config.Configuration{
			SecretManagement: config.SecretManagement{
				"vault": {Type: providerType},
			},
		}

		mgr, err := NewManager(cfg, zerolog.Nop(), nil)

		require.Error(t, err)
		require.Nil(t, mgr)
	})

	t.Run("fails for cyclic dependency", func(t *testing.T) {
		t.Parallel()

		typeA := uniqueProviderType(t, "a")
		typeB := uniqueProviderType(t, "b")
		typeC := uniqueProviderType(t, "c")

		registry.Register(typeA, types.ProviderFactoryFunc(func(types.ProviderArgs) (types.Provider, error) {
			p := typemocks.NewProviderMock(t)
			p.EXPECT().Dependencies().Return([]types.Reference{
				{Source: "b", Selector: "secret"},
			})

			return p, nil
		}))
		t.Cleanup(func() {
			registry.Unregister(typeA)
		})

		registry.Register(typeB, types.ProviderFactoryFunc(func(types.ProviderArgs) (types.Provider, error) {
			p := typemocks.NewProviderMock(t)
			p.EXPECT().Dependencies().Return([]types.Reference{
				{Source: "c", Selector: "secret"},
			})

			return p, nil
		}))
		t.Cleanup(func() {
			registry.Unregister(typeB)
		})

		registry.Register(typeC, types.ProviderFactoryFunc(func(types.ProviderArgs) (types.Provider, error) {
			p := typemocks.NewProviderMock(t)
			p.EXPECT().Dependencies().Return([]types.Reference{
				{Source: "a", Selector: "secret"},
			})

			return p, nil
		}))
		t.Cleanup(func() {
			registry.Unregister(typeC)
		})

		cfg := &config.Configuration{
			SecretManagement: config.SecretManagement{
				"a": {Type: typeA},
				"b": {Type: typeB},
				"c": {Type: typeC},
			},
		}

		mgr, err := NewManager(cfg, zerolog.Nop(), nil)

		require.Error(t, err)
		require.Nil(t, mgr)
	})

	t.Run("ignores duplicate dependencies", func(t *testing.T) {
		t.Parallel()

		mgr := newManagerWithProviderMocks(t,
			providerSetup{
				sourceName: "a",
				setup: func(t *testing.T, _ types.ProviderArgs) types.Provider {
					t.Helper()

					p := typemocks.NewProviderMock(t)
					p.EXPECT().Dependencies().Return(nil)

					return p
				},
			},
			providerSetup{
				sourceName: "b",
				setup: func(t *testing.T, _ types.ProviderArgs) types.Provider {
					t.Helper()

					p := typemocks.NewProviderMock(t)
					p.EXPECT().Dependencies().Return([]types.Reference{
						{Source: "a", Selector: "secret1"},
						{Source: "a", Selector: "secret2"},
					})

					return p
				},
			},
		)
		defer mgr.dispatcher.stop()

		require.Len(t, mgr.order, 2)
		require.Equal(t, "a", mgr.order[0].s.Name())
		require.Equal(t, "b", mgr.order[1].s.Name())
	})
}

func TestManagerResolveSecret(t *testing.T) {
	t.Parallel()

	secret := types.NewStringSecret("server", "value")

	for uc, tc := range map[string]struct {
		ruleContext bool
		allowRules  bool
		setup       func(t *testing.T, args types.ProviderArgs) types.Provider
		assert      func(t *testing.T, got Secret, err error)
	}{
		"delegates internal access": {
			setup: func(t *testing.T, _ types.ProviderArgs) types.Provider {
				t.Helper()

				p := typemocks.NewProviderMock(t)
				p.EXPECT().Dependencies().Return(nil)
				p.EXPECT().
					GetSecret(mock.Anything, types.Selector{Value: "server"}).
					Return(secret, nil)

				return p
			},
			assert: func(t *testing.T, got Secret, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, secret, got)
			},
		},
		"delegates rule access when allowed": {
			ruleContext: true,
			allowRules:  true,
			setup: func(t *testing.T, _ types.ProviderArgs) types.Provider {
				t.Helper()

				p := typemocks.NewProviderMock(t)
				p.EXPECT().Dependencies().Return(nil)
				p.EXPECT().
					GetSecret(mock.Anything, types.Selector{Value: "server"}).
					Return(secret, nil)

				return p
			},
			assert: func(t *testing.T, got Secret, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, secret, got)
			},
		},
		"rejects rule access when forbidden": {
			ruleContext: true,
			allowRules:  false,
			setup: func(t *testing.T, _ types.ProviderArgs) types.Provider {
				t.Helper()

				p := typemocks.NewProviderMock(t)
				p.EXPECT().Dependencies().Return(nil)

				return p
			},
			assert: func(t *testing.T, got Secret, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrSecretSourceForbidden)
				require.Nil(t, got)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			mgr := newManagerWithProviderMocks(t, providerSetup{
				sourceName:   "tls",
				allowInRules: tc.allowRules,
				setup:        tc.setup,
			})
			defer mgr.dispatcher.stop()

			got, err := mgr.ResolveSecret(
				context.Background(),
				Reference{
					Source:      "tls",
					Selector:    "server",
					RuleContext: tc.ruleContext,
				},
			)

			tc.assert(t, got, err)
		})
	}

	t.Run("returns source not found for unknown source", func(t *testing.T) {
		t.Parallel()

		mgr := newManagerWithProviderMocks(t)
		defer mgr.dispatcher.stop()

		got, err := mgr.ResolveSecret(context.Background(), Reference{Source: "missing", Selector: "server"})

		require.Error(t, err)
		require.ErrorIs(t, err, ErrSourceNotFound)
		require.Nil(t, got)
	})
}

func TestManagerResolveSecretSet(t *testing.T) {
	t.Parallel()

	secretSet := []types.Secret{
		types.NewStringSecret("a", "value-a"),
		types.NewStringSecret("b", "value-b"),
	}

	for uc, tc := range map[string]struct {
		ruleContext bool
		allowRules  bool
		setup       func(t *testing.T, args types.ProviderArgs) types.Provider
		assert      func(t *testing.T, got []Secret, err error)
	}{
		"delegates internal access": {
			setup: func(t *testing.T, _ types.ProviderArgs) types.Provider {
				t.Helper()

				p := typemocks.NewProviderMock(t)
				p.EXPECT().Dependencies().Return(nil)
				p.EXPECT().
					GetSecretSet(mock.Anything, types.Selector{Value: "keys"}).
					Return(secretSet, nil)

				return p
			},
			assert: func(t *testing.T, got []Secret, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, secretSet, got)
			},
		},
		"delegates rule access when allowed": {
			ruleContext: true,
			allowRules:  true,
			setup: func(t *testing.T, _ types.ProviderArgs) types.Provider {
				t.Helper()

				p := typemocks.NewProviderMock(t)
				p.EXPECT().Dependencies().Return(nil)
				p.EXPECT().
					GetSecretSet(mock.Anything, types.Selector{Value: "keys"}).
					Return(secretSet, nil)

				return p
			},
			assert: func(t *testing.T, got []Secret, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, secretSet, got)
			},
		},
		"rejects rule access when forbidden": {
			ruleContext: true,
			allowRules:  false,
			setup: func(t *testing.T, _ types.ProviderArgs) types.Provider {
				t.Helper()

				p := typemocks.NewProviderMock(t)
				p.EXPECT().Dependencies().Return(nil)

				return p
			},
			assert: func(t *testing.T, got []Secret, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrSecretSourceForbidden)
				require.Nil(t, got)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			mgr := newManagerWithProviderMocks(t, providerSetup{
				sourceName:   "jwks",
				allowInRules: tc.allowRules,
				setup:        tc.setup,
			})
			defer mgr.dispatcher.stop()

			got, err := mgr.ResolveSecretSet(
				context.Background(),
				Reference{
					Source:      "jwks",
					Selector:    "keys",
					RuleContext: tc.ruleContext,
				},
			)

			tc.assert(t, got, err)
		})
	}

	t.Run("returns source not found for unknown source", func(t *testing.T) {
		t.Parallel()

		mgr := newManagerWithProviderMocks(t)
		defer mgr.dispatcher.stop()

		got, err := mgr.ResolveSecretSet(context.Background(), Reference{Source: "missing", Selector: "keys"})

		require.Error(t, err)
		require.ErrorIs(t, err, ErrSourceNotFound)
		require.Nil(t, got)
	})
}

func TestManagerResolveCredentials(t *testing.T) {
	t.Parallel()

	credentials := types.NewCredentials("github", map[string]any{
		"client_id":     "heimdall",
		"client_secret": "secret",
	})

	for uc, tc := range map[string]struct {
		ruleContext bool
		allowRules  bool
		setup       func(t *testing.T, args types.ProviderArgs) types.Provider
		assert      func(t *testing.T, got Credentials, err error)
	}{
		"delegates internal access": {
			setup: func(t *testing.T, _ types.ProviderArgs) types.Provider {
				t.Helper()

				p := typemocks.NewProviderMock(t)
				p.EXPECT().Dependencies().Return(nil)
				p.EXPECT().
					GetCredentials(mock.Anything, types.Selector{Value: "github"}).
					Return(credentials, nil)

				return p
			},
			assert: func(t *testing.T, got Credentials, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, credentials, got)
			},
		},
		"delegates rule access when allowed": {
			ruleContext: true,
			allowRules:  true,
			setup: func(t *testing.T, _ types.ProviderArgs) types.Provider {
				t.Helper()

				p := typemocks.NewProviderMock(t)
				p.EXPECT().Dependencies().Return(nil)
				p.EXPECT().
					GetCredentials(mock.Anything, types.Selector{Value: "github"}).
					Return(credentials, nil)

				return p
			},
			assert: func(t *testing.T, got Credentials, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, credentials, got)
			},
		},
		"rejects rule access when forbidden": {
			ruleContext: true,
			allowRules:  false,
			setup: func(t *testing.T, _ types.ProviderArgs) types.Provider {
				t.Helper()

				p := typemocks.NewProviderMock(t)
				p.EXPECT().Dependencies().Return(nil)

				return p
			},
			assert: func(t *testing.T, got Credentials, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrSecretSourceForbidden)
				require.Nil(t, got)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			mgr := newManagerWithProviderMocks(t, providerSetup{
				sourceName:   "inline",
				allowInRules: tc.allowRules,
				setup:        tc.setup,
			})
			defer mgr.dispatcher.stop()

			got, err := mgr.ResolveCredentials(
				context.Background(),
				Reference{
					Source:      "inline",
					Selector:    "github",
					RuleContext: tc.ruleContext,
				},
			)

			tc.assert(t, got, err)
		})
	}

	t.Run("returns source not found for unknown source", func(t *testing.T) {
		t.Parallel()

		mgr := newManagerWithProviderMocks(t)
		defer mgr.dispatcher.stop()

		got, err := mgr.ResolveCredentials(context.Background(), Reference{Source: "missing", Selector: "github"})

		require.Error(t, err)
		require.ErrorIs(t, err, ErrSourceNotFound)
		require.Nil(t, got)
	})
}

func TestManagerLifecycle(t *testing.T) {
	t.Parallel()

	t.Run("starts in dependency order and stops in reverse order", func(t *testing.T) {
		t.Parallel()

		var (
			mut   sync.Mutex
			order []string
		)

		record := func(entry string) {
			mut.Lock()
			defer mut.Unlock()

			order = append(order, entry)
		}

		mgr := newManagerWithProviderMocks(t,
			providerSetup{
				sourceName: "pem",
				setup: func(t *testing.T, _ types.ProviderArgs) types.Provider {
					t.Helper()

					p := typemocks.NewProviderMock(t)
					p.EXPECT().Dependencies().Return(nil)
					p.EXPECT().Start(mock.Anything).Run(func(context.Context) {
						record("start:pem")
					}).Return(nil)
					p.EXPECT().Stop(mock.Anything).Run(func(context.Context) {
						record("stop:pem")
					}).Return(nil)

					return p
				},
			},
			providerSetup{
				sourceName: "vault",
				setup: func(t *testing.T, _ types.ProviderArgs) types.Provider {
					t.Helper()

					p := typemocks.NewProviderMock(t)
					p.EXPECT().Dependencies().Return([]types.Reference{
						{Source: "pem", Selector: "server"},
					})
					p.EXPECT().Start(mock.Anything).Run(func(context.Context) {
						record("start:vault")
					}).Return(nil)
					p.EXPECT().Stop(mock.Anything).Run(func(context.Context) {
						record("stop:vault")
					}).Return(nil)

					return p
				},
			},
		)

		require.NoError(t, mgr.Start(context.Background()))
		require.NoError(t, mgr.Stop(context.Background()))

		require.Equal(t, []string{
			"start:pem",
			"start:vault",
			"stop:vault",
			"stop:pem",
		}, order)
	})

	t.Run("stops already started sources when start fails", func(t *testing.T) {
		t.Parallel()

		var stopped atomic.Int32

		mgr := newManagerWithProviderMocks(t,
			providerSetup{
				sourceName: "first",
				setup: func(t *testing.T, _ types.ProviderArgs) types.Provider {
					t.Helper()

					p := typemocks.NewProviderMock(t)
					p.EXPECT().Dependencies().Return(nil)
					p.EXPECT().Start(mock.Anything).Return(nil)
					p.EXPECT().Stop(mock.Anything).Run(func(context.Context) {
						stopped.Add(1)
					}).Return(nil)

					return p
				},
			},
			providerSetup{
				sourceName: "second",
				setup: func(t *testing.T, _ types.ProviderArgs) types.Provider {
					t.Helper()

					p := typemocks.NewProviderMock(t)
					p.EXPECT().Dependencies().Return([]types.Reference{
						{Source: "first", Selector: "x"},
					})
					p.EXPECT().Start(mock.Anything).Return(assert.AnError)

					return p
				},
			},
		)
		defer mgr.dispatcher.stop()

		err := mgr.Start(context.Background())

		require.Error(t, err)
		require.ErrorIs(t, err, assert.AnError)
		require.EqualValues(t, 1, stopped.Load())
	})

	t.Run("returns first stop error", func(t *testing.T) {
		t.Parallel()

		mgr := newManagerWithProviderMocks(t,
			providerSetup{
				sourceName: "first",
				setup: func(t *testing.T, _ types.ProviderArgs) types.Provider {
					t.Helper()

					p := typemocks.NewProviderMock(t)
					p.EXPECT().Dependencies().Return(nil)
					p.EXPECT().Stop(mock.Anything).Return(errors.New("second stop error"))

					return p
				},
			},
			providerSetup{
				sourceName: "second",
				setup: func(t *testing.T, _ types.ProviderArgs) types.Provider {
					t.Helper()

					p := typemocks.NewProviderMock(t)
					p.EXPECT().Dependencies().Return([]types.Reference{
						{Source: "first", Selector: "x"},
					})
					p.EXPECT().Stop(mock.Anything).Return(assert.AnError)

					return p
				},
			},
		)

		err := mgr.Stop(context.Background())

		require.Error(t, err)
		require.ErrorIs(t, err, assert.AnError)
	})

	t.Run("stops subscriber bindings before stopping sources", func(t *testing.T) {
		t.Parallel()

		mgr := newManagerWithProviderMocks(t,
			providerSetup{
				sourceName: "pem",
				setup: func(t *testing.T, _ types.ProviderArgs) types.Provider {
					t.Helper()

					p := typemocks.NewProviderMock(t)
					p.EXPECT().Dependencies().Return(nil)
					p.EXPECT().Stop(mock.Anything).Return(nil)

					return p
				},
			},
		)

		started := make(chan struct{}, 1)
		release := make(chan struct{})
		stopped := make(chan struct{})

		_, err := mgr.Subscribe(
			Reference{Source: "pem", Selector: "server"},
			func(context.Context) error {
				started <- struct{}{}
				<-release

				return nil
			},
		)
		require.NoError(t, err)

		mgr.Notify(source.Event{
			Source:    "pem",
			Selectors: []types.Selector{{Value: "server"}},
		})

		select {
		case <-started:
		case <-time.After(500 * time.Millisecond):
			t.Fatal("callback not started")
		}

		var wg sync.WaitGroup
		wg.Go(func() {
			require.NoError(t, mgr.Stop(context.Background()))
			close(stopped)
		})

		select {
		case <-stopped:
			t.Fatal("manager stopped before subscriber callback finished")
		case <-time.After(100 * time.Millisecond):
		}

		close(release)

		select {
		case <-stopped:
		case <-time.After(500 * time.Millisecond):
			t.Fatal("manager did not stop")
		}

		wg.Wait()
	})
}

func TestManagerRestart(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T) secretSource
		assert func(t *testing.T, err error)
	}{
		"returns stop error": {
			setup: func(t *testing.T) secretSource {
				t.Helper()

				src := NewSecretSourceMock(t)
				src.EXPECT().Name().Return("vault")
				src.EXPECT().Stop(mock.Anything).Return(assert.AnError)

				return src
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)
				require.ErrorContains(t, err, "failed stopping secret source")
			},
		},
		"returns start error": {
			setup: func(t *testing.T) secretSource {
				t.Helper()

				src := NewSecretSourceMock(t)
				src.EXPECT().Name().Return("vault")
				src.EXPECT().Stop(mock.Anything).Return(nil)
				src.EXPECT().Start(mock.Anything).Return(assert.AnError)

				return src
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)
				require.ErrorContains(t, err, "failed starting secret source")
			},
		},
		"notifies source-wide event after successful restart": {
			setup: func(t *testing.T) secretSource {
				t.Helper()

				src := NewSecretSourceMock(t)
				src.EXPECT().Name().Return("vault")
				src.EXPECT().Stop(mock.Anything).Return(nil)
				src.EXPECT().Start(mock.Anything).Return(nil)

				return src
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			mgr := newManagerWithProviderMocks(t, providerSetup{sourceName: "vault"})
			defer mgr.dispatcher.stop()

			called := make(chan struct{}, 1)
			unsubscribe, err := mgr.Subscribe(
				Reference{Source: "vault", Selector: "server"},
				func(context.Context) error {
					called <- struct{}{}
					return nil
				},
			)
			require.NoError(t, err)
			defer unsubscribe()

			err = mgr.restart(context.Background(), tc.setup(t))

			tc.assert(t, err)

			if err != nil {
				select {
				case <-called:
					t.Fatal("callback unexpectedly called after failed restart")
				case <-time.After(200 * time.Millisecond):
				}

				return
			}

			select {
			case <-called:
			case <-time.After(500 * time.Millisecond):
				t.Fatal("restart did not emit source-wide event")
			}
		})
	}
}

func TestManagerMatchingBindings(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		sources       []string
		subscriptions []Reference
		event         source.Event
		want          int
	}{
		"returns no binding for selector event without matching binding": {
			sources: []string{"pem"},
			subscriptions: []Reference{
				{Source: "pem", Selector: "server"},
			},
			event: source.Event{
				Source:    "pem",
				Selectors: []types.Selector{{Value: "client"}},
			},
			want: 0,
		},
		"returns matching binding and ignores missing selector": {
			sources: []string{"pem"},
			subscriptions: []Reference{
				{Source: "pem", Selector: "server"},
			},
			event: source.Event{
				Source: "pem",
				Selectors: []types.Selector{
					{Value: "server"},
					{Value: "client"},
				},
			},
			want: 1,
		},
		"source-wide event skips bindings from other sources": {
			sources: []string{"pem", "inline"},
			subscriptions: []Reference{
				{Source: "pem", Selector: "server"},
				{Source: "inline", Selector: "github"},
			},
			event: source.Event{
				Source: "pem",
			},
			want: 1,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			providers := make([]providerSetup, 0, len(tc.sources))
			for _, sourceName := range tc.sources {
				providers = append(providers, providerSetup{sourceName: sourceName})
			}

			mgr := newManagerWithProviderMocks(t, providers...)
			defer mgr.dispatcher.stop()

			for _, ref := range tc.subscriptions {
				unsubscribe, err := mgr.Subscribe(ref, func(context.Context) error { return nil })
				require.NoError(t, err)

				defer unsubscribe()
			}

			require.Len(t, mgr.matchingBindings(tc.event), tc.want)
		})
	}
}

func TestManagerSubscribeNotify(t *testing.T) {
	t.Parallel()

	t.Run("matching selector invokes callback", func(t *testing.T) {
		t.Parallel()

		mgr := newManagerWithProviderMocks(t, providerSetup{sourceName: "pem"})
		defer mgr.dispatcher.stop()

		called := make(chan struct{}, 1)

		unsubscribe, err := mgr.Subscribe(
			Reference{Source: "pem", Selector: "server"},
			func(context.Context) error {
				called <- struct{}{}
				return nil
			},
		)
		require.NoError(t, err)
		defer unsubscribe()

		mgr.Notify(source.Event{
			Source:    "pem",
			Selectors: []types.Selector{{Value: "server"}},
		})

		select {
		case <-called:
		case <-time.After(500 * time.Millisecond):
			t.Fatal("callback not called")
		}
	})

	t.Run("non-matching selector is ignored", func(t *testing.T) {
		t.Parallel()

		mgr := newManagerWithProviderMocks(t, providerSetup{sourceName: "pem"})
		defer mgr.dispatcher.stop()

		called := make(chan struct{}, 1)

		unsubscribe, err := mgr.Subscribe(
			Reference{Source: "pem", Selector: "server"},
			func(context.Context) error {
				called <- struct{}{}
				return nil
			},
		)
		require.NoError(t, err)
		defer unsubscribe()

		mgr.Notify(source.Event{
			Source:    "pem",
			Selectors: []types.Selector{{Value: "client"}},
		})

		select {
		case <-called:
			t.Fatal("callback unexpectedly called")
		case <-time.After(200 * time.Millisecond):
		}
	})

	t.Run("source-wide event fans out", func(t *testing.T) {
		t.Parallel()

		mgr := newManagerWithProviderMocks(t, providerSetup{sourceName: "pem"})
		defer mgr.dispatcher.stop()

		calledA := make(chan struct{}, 1)
		calledB := make(chan struct{}, 1)

		unsubA, err := mgr.Subscribe(
			Reference{Source: "pem", Selector: "a"},
			func(context.Context) error {
				calledA <- struct{}{}
				return nil
			},
		)
		require.NoError(t, err)
		defer unsubA()

		unsubB, err := mgr.Subscribe(
			Reference{Source: "pem", Selector: "b"},
			func(context.Context) error {
				calledB <- struct{}{}
				return nil
			},
		)
		require.NoError(t, err)
		defer unsubB()

		mgr.Notify(source.Event{Source: "pem"})

		select {
		case <-calledA:
		case <-time.After(500 * time.Millisecond):
			t.Fatal("callback A not called")
		}

		select {
		case <-calledB:
		case <-time.After(500 * time.Millisecond):
			t.Fatal("callback B not called")
		}
	})

	t.Run("namespace matching invokes only matching namespace", func(t *testing.T) {
		t.Parallel()

		mgr := newManagerWithProviderMocks(t, providerSetup{sourceName: "k8s"})
		defer mgr.dispatcher.stop()

		calledA := make(chan struct{}, 1)
		calledB := make(chan struct{}, 1)

		unsubA, err := mgr.Subscribe(
			Reference{Source: "k8s", Namespace: "team-a", Selector: "secret"},
			func(context.Context) error {
				calledA <- struct{}{}
				return nil
			},
		)
		require.NoError(t, err)
		defer unsubA()

		unsubB, err := mgr.Subscribe(
			Reference{Source: "k8s", Namespace: "team-b", Selector: "secret"},
			func(context.Context) error {
				calledB <- struct{}{}
				return nil
			},
		)
		require.NoError(t, err)
		defer unsubB()

		mgr.Notify(source.Event{
			Source: "k8s",
			Selectors: []types.Selector{
				{Value: "secret", Namespace: "team-a"},
			},
		})

		select {
		case <-calledA:
		case <-time.After(500 * time.Millisecond):
			t.Fatal("team-a callback not called")
		}

		select {
		case <-calledB:
			t.Fatal("team-b callback unexpectedly called")
		case <-time.After(200 * time.Millisecond):
		}
	})

	t.Run("unsubscribe works", func(t *testing.T) {
		t.Parallel()

		mgr := newManagerWithProviderMocks(t, providerSetup{sourceName: "pem"})
		defer mgr.dispatcher.stop()

		called := make(chan struct{}, 1)

		unsubscribe, err := mgr.Subscribe(
			Reference{Source: "pem", Selector: "server"},
			func(context.Context) error {
				called <- struct{}{}
				return nil
			},
		)
		require.NoError(t, err)

		unsubscribe()

		mgr.Notify(source.Event{
			Source:    "pem",
			Selectors: []types.Selector{{Value: "server"}},
		})

		select {
		case <-called:
			t.Fatal("callback unexpectedly called")
		case <-time.After(200 * time.Millisecond):
		}
	})

	t.Run("dependency event restarts dependent provider", func(t *testing.T) {
		t.Parallel()

		var restarts atomic.Int32

		mgr := newManagerWithProviderMocks(t,
			providerSetup{
				sourceName: "pem",
				setup: func(t *testing.T, _ types.ProviderArgs) types.Provider {
					t.Helper()

					p := typemocks.NewProviderMock(t)
					p.EXPECT().Dependencies().Return(nil)

					return p
				},
			},
			providerSetup{
				sourceName: "vault",
				setup: func(t *testing.T, _ types.ProviderArgs) types.Provider {
					t.Helper()

					p := typemocks.NewProviderMock(t)
					p.EXPECT().Dependencies().Return([]types.Reference{
						{Source: "pem", Selector: "server"},
					})
					p.EXPECT().Stop(mock.Anything).Run(func(context.Context) {
						restarts.Add(1)
					}).Return(nil)
					p.EXPECT().Start(mock.Anything).Return(nil)

					return p
				},
			},
		)
		defer mgr.dispatcher.stop()

		mgr.Notify(source.Event{
			Source:    "pem",
			Selectors: []types.Selector{{Value: "server"}},
		})

		require.Eventually(t, func() bool {
			return restarts.Load() == 1
		}, time.Second, 10*time.Millisecond)
	})

	t.Run("returns error for nil callback", func(t *testing.T) {
		t.Parallel()

		mgr := newManagerWithProviderMocks(t, providerSetup{sourceName: "pem"})
		defer mgr.dispatcher.stop()

		unsubscribe, err := mgr.Subscribe(
			Reference{Source: "pem", Selector: "server"},
			nil,
		)

		require.Nil(t, unsubscribe)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrSubscribeFailed)
	})

	t.Run("returns error for unknown source", func(t *testing.T) {
		t.Parallel()

		mgr := newManagerWithProviderMocks(t)
		defer mgr.dispatcher.stop()

		unsubscribe, err := mgr.Subscribe(
			Reference{Source: "missing", Selector: "server"},
			func(context.Context) error { return nil },
		)

		require.Nil(t, unsubscribe)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrSourceNotFound)
	})

	t.Run("unsubscribe is no-op when binding was already removed", func(t *testing.T) {
		t.Parallel()

		mgr := newManagerWithProviderMocks(t, providerSetup{sourceName: "pem"})
		defer mgr.dispatcher.stop()

		unsubscribe, err := mgr.Subscribe(
			Reference{Source: "pem", Selector: "server"},
			func(context.Context) error { return nil },
		)
		require.NoError(t, err)

		mgr.mu.Lock()
		delete(mgr.bindings, bindingKey{source: "pem", selector: "server"})
		mgr.mu.Unlock()

		require.NotPanics(t, func() {
			unsubscribe()
		})
	})

	t.Run("unsubscribe keeps binding when subscribers remain", func(t *testing.T) {
		t.Parallel()

		mgr := newManagerWithProviderMocks(t, providerSetup{sourceName: "pem"})
		defer mgr.dispatcher.stop()

		firstCalled := make(chan struct{}, 1)
		secondCalled := make(chan struct{}, 1)

		unsubFirst, err := mgr.Subscribe(
			Reference{Source: "pem", Selector: "server"},
			func(context.Context) error {
				firstCalled <- struct{}{}
				return nil
			},
		)
		require.NoError(t, err)

		unsubSecond, err := mgr.Subscribe(
			Reference{Source: "pem", Selector: "server"},
			func(context.Context) error {
				secondCalled <- struct{}{}
				return nil
			},
		)
		require.NoError(t, err)
		defer unsubSecond()

		unsubFirst()

		mgr.Notify(source.Event{
			Source:    "pem",
			Selectors: []types.Selector{{Value: "server"}},
		})

		select {
		case <-firstCalled:
			t.Fatal("first callback unexpectedly called")
		case <-time.After(200 * time.Millisecond):
		}

		select {
		case <-secondCalled:
		case <-time.After(500 * time.Millisecond):
			t.Fatal("second callback not called")
		}
	})
}

package source

import (
	"context"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/secrets/registry"
	"github.com/dadrus/heimdall/internal/secrets/types"
	typemocks "github.com/dadrus/heimdall/internal/secrets/types/mocks"
)

func TestProviderObserverNotify(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		sourceName string
		event      types.ChangeEvent
		want       Event
	}{
		"adds source name to source wide event": {
			sourceName: "vault",
			event:      types.ChangeEvent{},
			want:       Event{Source: "vault"},
		},
		"adds source name to selector event": {
			sourceName: "k8s",
			event: types.ChangeEvent{
				Selectors: []types.Selector{{Value: "service-account", Namespace: "team-a"}},
			},
			want: Event{
				Source:    "k8s",
				Selectors: []types.Selector{{Value: "service-account", Namespace: "team-a"}},
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

func TestSecretsResolverResolveSecret(t *testing.T) {
	t.Parallel()

	declaredRef := types.SecretRef{Source: "pem", Selector: "server"}
	secret := types.NewStringSecret("server", "value")

	for uc, tc := range map[string]struct {
		dependencies []types.SecretRef
		ref          types.SecretRef
		setup        func(*DependencyResolverMock)
		wantSecret   types.Secret
		wantErr      error
	}{
		"delegates declared dependency": {
			dependencies: []types.SecretRef{declaredRef},
			ref:          declaredRef,
			setup: func(resolver *DependencyResolverMock) {
				resolver.EXPECT().
					ResolveSecret(mock.Anything, declaredRef).
					Return(secret, nil)
			},
			wantSecret: secret,
		},
		"returns dependency error for unknown selector": {
			dependencies: []types.SecretRef{declaredRef},
			ref:          types.SecretRef{Source: "pem", Selector: "client"},
			setup:        func(*DependencyResolverMock) {},
			wantErr:      ErrProviderDependencyNotDeclared,
		},
		"propagates resolver error": {
			dependencies: []types.SecretRef{declaredRef},
			ref:          declaredRef,
			setup: func(resolver *DependencyResolverMock) {
				resolver.EXPECT().
					ResolveSecret(mock.Anything, declaredRef).
					Return(nil, assert.AnError)
			},
			wantErr: assert.AnError,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			resolverMock := NewDependencyResolverMock(t)
			if tc.setup != nil {
				tc.setup(resolverMock)
			}

			resolver := &secretsResolver{
				name: "vault",
				deps: tc.dependencies,
				r:    resolverMock,
			}

			got, err := resolver.ResolveSecret(context.Background(), tc.ref)

			if tc.wantErr != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.wantErr)
				require.Nil(t, got)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.wantSecret, got)
		})
	}
}

func TestSecretsResolverResolveCredentials(t *testing.T) {
	t.Parallel()

	declaredRef := types.SecretRef{Source: "inline", Selector: "github"}
	creds := types.NewCredentials("github", map[string]any{
		"client_id":     "heimdall",
		"client_secret": "secret",
	})

	for uc, tc := range map[string]struct {
		dependencies []types.SecretRef
		ref          types.SecretRef
		setup        func(*DependencyResolverMock)
		wantCreds    types.Credentials
		wantErr      error
	}{
		"delegates declared dependency": {
			dependencies: []types.SecretRef{declaredRef},
			ref:          declaredRef,
			setup: func(resolver *DependencyResolverMock) {
				resolver.EXPECT().
					ResolveCredentials(mock.Anything, declaredRef).
					Return(creds, nil)
			},
			wantCreds: creds,
		},
		"returns dependency error for undeclared reference": {
			dependencies: []types.SecretRef{declaredRef},
			ref:          types.SecretRef{Source: "inline", Selector: "other"},
			setup:        func(*DependencyResolverMock) {},
			wantErr:      ErrProviderDependencyNotDeclared,
		},
		"propagates resolver error": {
			dependencies: []types.SecretRef{declaredRef},
			ref:          declaredRef,
			setup: func(resolver *DependencyResolverMock) {
				resolver.EXPECT().
					ResolveCredentials(mock.Anything, declaredRef).
					Return(nil, assert.AnError)
			},
			wantErr: assert.AnError,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			resolverMock := NewDependencyResolverMock(t)
			if tc.setup != nil {
				tc.setup(resolverMock)
			}

			resolver := &secretsResolver{
				name: "vault",
				deps: tc.dependencies,
				r:    resolverMock,
			}

			got, err := resolver.ResolveCredentials(context.Background(), tc.ref)

			if tc.wantErr != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.wantErr)
				require.Nil(t, got)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.wantCreds, got)
		})
	}
}

func TestSecretsResolverDependsOn(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		dependencies []types.SecretRef
		event        Event
		want         bool
	}{
		"returns false without dependencies": {
			dependencies: nil,
			event:        Event{Source: "pem"},
			want:         false,
		},
		"returns false for different source": {
			dependencies: []types.SecretRef{
				{Source: "pem", Selector: "server"},
			},
			event: Event{
				Source: "inline",
			},
			want: false,
		},
		"returns true for source wide event": {
			dependencies: []types.SecretRef{
				{Source: "pem", Selector: "server"},
			},
			event: Event{
				Source: "pem",
			},
			want: true,
		},
		"returns true for matching selector": {
			dependencies: []types.SecretRef{
				{Source: "pem", Selector: "server"},
			},
			event: Event{
				Source: "pem",
				Selectors: []types.Selector{
					{Value: "server"},
				},
			},
			want: true,
		},
		"returns true for one matching selector": {
			dependencies: []types.SecretRef{
				{Source: "pem", Selector: "server"},
			},
			event: Event{
				Source: "pem",
				Selectors: []types.Selector{
					{Value: "client"},
					{Value: "server"},
				},
			},
			want: true,
		},
		"returns false for non matching selector": {
			dependencies: []types.SecretRef{
				{Source: "pem", Selector: "server"},
			},
			event: Event{
				Source: "pem",
				Selectors: []types.Selector{
					{Value: "client"},
				},
			},
			want: false,
		},
		"ignores selector namespace": {
			dependencies: []types.SecretRef{
				{Source: "k8s", Selector: "service-account"},
			},
			event: Event{
				Source: "k8s",
				Selectors: []types.Selector{
					{Value: "service-account", Namespace: "team-a"},
				},
			},
			want: true,
		},
		"returns true for one matching dependency": {
			dependencies: []types.SecretRef{
				{Source: "pem", Selector: "server"},
				{Source: "inline", Selector: "github"},
			},
			event: Event{
				Source: "inline",
				Selectors: []types.Selector{
					{Value: "github"},
				},
			},
			want: true,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			resolver := &secretsResolver{
				name: "vault",
				deps: tc.dependencies,
			}

			require.Equal(t, tc.want, resolver.dependsOn(tc.event))
		})
	}
}

func TestNewSource(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		conf   config.SecretSourceConfig
		setup  func(t *testing.T, providerType string) types.ProviderFactory
		assert func(t *testing.T, src *Source, err error)
	}{
		"creates source from registered provider": {
			conf: config.SecretSourceConfig{
				AllowInRules: true,
				Config:       map[string]any{"foo": "bar"},
			},
			setup: func(t *testing.T, providerType string) types.ProviderFactory {
				t.Helper()

				return types.ProviderFactoryFunc(func(args types.ProviderArgs) (types.Provider, error) {
					require.Equal(t, map[string]any{"foo": "bar"}, args.Config)
					require.NotNil(t, args.Logger)
					require.NotNil(t, args.Observer)
					require.NotNil(t, args.Resolver)

					provider := typemocks.NewProviderMock(t)
					provider.EXPECT().
						Dependencies().
						Return([]types.SecretRef{
							{Source: "pem", Selector: "server"},
						})

					return provider, nil
				})
			},
			assert: func(t *testing.T, src *Source, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, src)

				require.Equal(t, "vault", src.Name())
				require.True(t, src.AccessFromRulesAllowed())
				require.Equal(t, []types.SecretRef{
					{Source: "pem", Selector: "server"},
				}, src.Dependencies())
			},
		},
		"returns unsupported provider type error": {
			conf: config.SecretSourceConfig{
				Type: "does-not-exist",
			},
			setup: func(t *testing.T, providerType string) types.ProviderFactory {
				t.Helper()

				return nil
			},
			assert: func(t *testing.T, src *Source, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, registry.ErrUnsupportedProviderType)
				require.Nil(t, src)
			},
		},
		"returns provider creation error": {
			setup: func(t *testing.T, providerType string) types.ProviderFactory {
				t.Helper()

				return types.ProviderFactoryFunc(func(types.ProviderArgs) (types.Provider, error) {
					return nil, assert.AnError
				})
			},
			assert: func(t *testing.T, src *Source, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)
				require.Nil(t, src)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			providerType := uniqueProviderType(t)
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
			resolver := NewDependencyResolverMock(t)

			src, err := New(
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

func TestSourceDelegatesToProvider(t *testing.T) {
	t.Parallel()

	secret := types.NewStringSecret("server", "value")
	secretSet := []types.Secret{secret}
	creds := types.NewCredentials("github", map[string]any{
		"client_id":     "heimdall",
		"client_secret": "secret",
	})

	for uc, tc := range map[string]struct {
		setup  func(*typemocks.ProviderMock)
		call   func(*Source) (any, error)
		assert func(t *testing.T, result any, err error)
	}{
		"start": {
			setup: func(provider *typemocks.ProviderMock) {
				provider.EXPECT().Start(mock.Anything).Return(nil)
			},
			call: func(src *Source) (any, error) {
				return nil, src.Start(context.Background())
			},
			assert: func(t *testing.T, _ any, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"stop": {
			setup: func(provider *typemocks.ProviderMock) {
				provider.EXPECT().Stop(mock.Anything).Return(nil)
			},
			call: func(src *Source) (any, error) {
				return nil, src.Stop(context.Background())
			},
			assert: func(t *testing.T, _ any, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"get secret": {
			setup: func(provider *typemocks.ProviderMock) {
				provider.EXPECT().
					GetSecret(mock.Anything, types.Selector{Value: "server"}).
					Return(secret, nil)
			},
			call: func(src *Source) (any, error) {
				return src.GetSecret(context.Background(), types.Selector{Value: "server"})
			},
			assert: func(t *testing.T, result any, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, secret, result)
			},
		},
		"get secret set": {
			setup: func(provider *typemocks.ProviderMock) {
				provider.EXPECT().
					GetSecretSet(mock.Anything, types.Selector{Value: "server"}).
					Return(secretSet, nil)
			},
			call: func(src *Source) (any, error) {
				return src.GetSecretSet(context.Background(), types.Selector{Value: "server"})
			},
			assert: func(t *testing.T, result any, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, secretSet, result)
			},
		},
		"get credentials": {
			setup: func(provider *typemocks.ProviderMock) {
				provider.EXPECT().
					GetCredentials(mock.Anything, types.Selector{Value: "github"}).
					Return(creds, nil)
			},
			call: func(src *Source) (any, error) {
				return src.GetCredentials(context.Background(), types.Selector{Value: "github"})
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

			provider := typemocks.NewProviderMock(t)
			tc.setup(provider)

			src := &Source{
				name:         "test",
				allowInRules: true,
				sr:           &secretsResolver{},
				p:            provider,
			}

			result, err := tc.call(src)
			tc.assert(t, result, err)
		})
	}
}

func uniqueProviderType(t *testing.T) string {
	t.Helper()

	replacer := strings.NewReplacer(
		"/", "-",
		" ", "-",
		"_", "-",
	)

	return "test-" + strings.ToLower(replacer.Replace(t.Name()))
}

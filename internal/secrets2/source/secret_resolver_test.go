package source

import (
	"context"
	"testing"

	"github.com/dadrus/heimdall/internal/secrets2/provider/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/secrets2/provider"
	"github.com/dadrus/heimdall/internal/secrets2/types"
)

func TestSecretsResolverResolveSecret(t *testing.T) {
	t.Parallel()

	declaredRef := types.Reference{Source: "pem", Selector: "server"}
	secret := types.NewStringSecret("server", "value")

	for uc, tc := range map[string]struct {
		dependencies []types.Reference
		ref          types.Reference
		setup        func(t *testing.T, drm *mocks.DependenciesResolverMock)
		wantSecret   types.Secret
		wantErr      error
	}{
		"delegates declared dependency": {
			dependencies: []types.Reference{declaredRef},
			ref:          declaredRef,
			setup: func(t *testing.T, drm *mocks.DependenciesResolverMock) {
				t.Helper()

				drm.EXPECT().
					ResolveSecret(mock.Anything, declaredRef).
					Return(secret, nil)
			},
			wantSecret: secret,
		},
		"returns dependency error for unknown selector": {
			dependencies: []types.Reference{declaredRef},
			ref:          types.Reference{Source: "pem", Selector: "client"},
			setup: func(t *testing.T, _ *mocks.DependenciesResolverMock) {
				t.Helper()
			},
			wantErr: types.ErrDependencyNotDeclared,
		},
		"returns dependency error for unknown source": {
			dependencies: []types.Reference{declaredRef},
			ref:          types.Reference{Source: "inline", Selector: "server"},
			setup: func(t *testing.T, _ *mocks.DependenciesResolverMock) {
				t.Helper()
			},
			wantErr: types.ErrDependencyNotDeclared,
		},
		"propagates resolver error": {
			dependencies: []types.Reference{declaredRef},
			ref:          declaredRef,
			setup: func(t *testing.T, drm *mocks.DependenciesResolverMock) {
				t.Helper()

				drm.EXPECT().
					ResolveSecret(mock.Anything, declaredRef).
					Return(nil, assert.AnError)
			},
			wantErr: assert.AnError,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			resolverMock := mocks.NewDependenciesResolverMock(t)
			tc.setup(t, resolverMock)

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

	declaredRef := types.Reference{Source: "inline", Selector: "github"}
	creds := types.NewCredentials("github", map[string]any{
		"client_id":     "heimdall",
		"client_secret": "secret",
	})

	for uc, tc := range map[string]struct {
		dependencies []types.Reference
		ref          types.Reference
		setup        func(t *testing.T, drm *mocks.DependenciesResolverMock)
		wantCreds    types.Credentials
		wantErr      error
	}{
		"delegates declared dependency": {
			dependencies: []types.Reference{declaredRef},
			ref:          declaredRef,
			setup: func(t *testing.T, drm *mocks.DependenciesResolverMock) {
				t.Helper()

				drm.EXPECT().
					ResolveCredentials(mock.Anything, declaredRef).
					Return(creds, nil)
			},
			wantCreds: creds,
		},
		"returns dependency error for unknown selector": {
			dependencies: []types.Reference{declaredRef},
			ref:          types.Reference{Source: "inline", Selector: "other"},
			setup: func(t *testing.T, _ *mocks.DependenciesResolverMock) {
				t.Helper()
			},
			wantErr: types.ErrDependencyNotDeclared,
		},
		"returns dependency error for unknown source": {
			dependencies: []types.Reference{declaredRef},
			ref:          types.Reference{Source: "pem", Selector: "github"},
			setup: func(t *testing.T, _ *mocks.DependenciesResolverMock) {
				t.Helper()
			},
			wantErr: types.ErrDependencyNotDeclared,
		},
		"propagates resolver error": {
			dependencies: []types.Reference{declaredRef},
			ref:          declaredRef,
			setup: func(t *testing.T, drm *mocks.DependenciesResolverMock) {
				t.Helper()

				drm.EXPECT().
					ResolveCredentials(mock.Anything, declaredRef).
					Return(nil, assert.AnError)
			},
			wantErr: assert.AnError,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			resolverMock := mocks.NewDependenciesResolverMock(t)
			tc.setup(t, resolverMock)

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

func TestSecretsResolverCheckReference(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		dependencies []types.Reference
		ref          types.Reference
		wantErr      error
	}{
		"accepts declared reference": {
			dependencies: []types.Reference{
				{Source: "pem", Selector: "server"},
			},
			ref: types.Reference{Source: "pem", Selector: "server"},
		},
		"rejects unknown selector": {
			dependencies: []types.Reference{
				{Source: "pem", Selector: "server"},
			},
			ref:     types.Reference{Source: "pem", Selector: "client"},
			wantErr: types.ErrDependencyNotDeclared,
		},
		"rejects unknown source": {
			dependencies: []types.Reference{
				{Source: "pem", Selector: "server"},
			},
			ref:     types.Reference{Source: "inline", Selector: "server"},
			wantErr: types.ErrDependencyNotDeclared,
		},
		"rejects when no dependencies are declared": {
			ref:     types.Reference{Source: "pem", Selector: "server"},
			wantErr: types.ErrDependencyNotDeclared,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			resolver := &secretsResolver{
				name: "vault",
				deps: tc.dependencies,
			}

			err := resolver.checkReference(tc.ref)

			if tc.wantErr != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.wantErr)

				return
			}

			require.NoError(t, err)
		})
	}
}

func TestSecretsResolverDependsOn(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		dependencies []types.Reference
		event        Event
		want         bool
	}{
		"returns false without dependencies": {
			dependencies: nil,
			event:        Event{Source: "pem"},
			want:         false,
		},
		"returns false for different source": {
			dependencies: []types.Reference{
				{Source: "pem", Selector: "server"},
			},
			event: Event{Source: "inline"},
			want:  false,
		},
		"returns true for source wide event": {
			dependencies: []types.Reference{
				{Source: "pem", Selector: "server"},
			},
			event: Event{Source: "pem"},
			want:  true,
		},
		"returns true for matching selector": {
			dependencies: []types.Reference{
				{Source: "pem", Selector: "server"},
			},
			event: Event{
				Source: "pem",
				Selectors: []provider.Selector{
					{Value: "server"},
				},
			},
			want: true,
		},
		"returns true for one matching selector": {
			dependencies: []types.Reference{
				{Source: "pem", Selector: "server"},
			},
			event: Event{
				Source: "pem",
				Selectors: []provider.Selector{
					{Value: "client"},
					{Value: "server"},
				},
			},
			want: true,
		},
		"returns false for non matching selector": {
			dependencies: []types.Reference{
				{Source: "pem", Selector: "server"},
			},
			event: Event{
				Source: "pem",
				Selectors: []provider.Selector{
					{Value: "client"},
				},
			},
			want: false,
		},
		"ignores selector namespace": {
			dependencies: []types.Reference{
				{Source: "k8s", Selector: "service-account"},
			},
			event: Event{
				Source: "k8s",
				Selectors: []provider.Selector{
					{Value: "service-account", Namespace: "team-a"},
				},
			},
			want: true,
		},
		"returns true for one matching dependency": {
			dependencies: []types.Reference{
				{Source: "pem", Selector: "server"},
				{Source: "inline", Selector: "github"},
			},
			event: Event{
				Source: "inline",
				Selectors: []provider.Selector{
					{Value: "github"},
				},
			},
			want: true,
		},
		"returns false for empty source event with unmatched source": {
			dependencies: []types.Reference{
				{Source: "pem", Selector: "server"},
			},
			event: Event{},
			want:  false,
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
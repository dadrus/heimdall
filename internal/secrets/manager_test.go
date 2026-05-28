// Copyright 2026 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"context"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	noopmetric "go.opentelemetry.io/otel/metric/noop"

	metricsmocks "github.com/dadrus/heimdall/internal/secrets/metrics/mocks"
	"github.com/dadrus/heimdall/internal/secrets/source"
	sourcemocks "github.com/dadrus/heimdall/internal/secrets/source/mocks"
	"github.com/dadrus/heimdall/internal/secrets/types"
)

func TestManagerResolver(t *testing.T) {
	t.Parallel()

	repository := sourcemocks.NewRepositoryMock(t)
	repository.EXPECT().
		AddObserver(mock.Anything).
		Maybe()

	mgr := newTestManager(t, repository)

	resolver := mgr.Resolver()

	require.NotNil(t, resolver)
	require.Same(t, mgr.resolver.appScope, resolver)
}

func TestManagerScopedResolverFactory(t *testing.T) {
	t.Parallel()

	repository := sourcemocks.NewRepositoryMock(t)
	repository.EXPECT().
		AddObserver(mock.Anything).
		Maybe()

	mgr := newTestManager(t, repository)

	factory := mgr.ScopedResolverFactory()
	require.NotNil(t, factory)

	scoped := factory.Create("ruleset-a", WithNamespace("team-a"))
	require.NotNil(t, scoped)

	scope := scoped.(*scope) //nolint:forcetypeassert
	require.Equal(t, "ruleset-a", scope.id)
	require.Equal(t, "team-a", scope.namespace)

	scoped.Release()
}

func TestManagerStart(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup    func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock)
		before   func(t *testing.T, mgr *manager)
		startCtx func(t *testing.T) context.Context
		assert   func(t *testing.T, mgr *manager, err error)
	}{
		"starts repository and resolver": {
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, _ *sourcemocks.SourceMock) {
				t.Helper()

				repository.EXPECT().
					Start(mock.Anything).
					Return(nil)
			},
			assert: func(t *testing.T, mgr *manager, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, resolverStateStarted, mgr.resolver.state)
			},
		},
		"returns repository start error": {
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, _ *sourcemocks.SourceMock) {
				t.Helper()

				repository.EXPECT().
					Start(mock.Anything).
					Return(assert.AnError)
			},
			assert: func(t *testing.T, mgr *manager, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)
				require.Equal(t, resolverStateInitial, mgr.resolver.state)
			},
		},
		"stops repository and resolver if readiness fails": {
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock) {
				t.Helper()

				repository.EXPECT().Lookup("src").Return(src, nil).Twice()
				repository.EXPECT().Start(mock.Anything).Return(nil)
				repository.EXPECT().Stop(mock.Anything).Return(nil)

				src.EXPECT().IsNamespaceAware().Return(false).Twice()
				src.EXPECT().GetSecret(mock.Anything, source.Selector{Value: "selector"}).
					Return(nil, assert.AnError)
			},
			before: func(t *testing.T, mgr *manager) {
				t.Helper()

				handle, err := mgr.Resolver().Secret(
					Reference{Source: "src", Selector: "selector"},
				)
				require.NoError(t, err)
				require.NotNil(t, handle)
			},
			startCtx: func(t *testing.T) context.Context {
				t.Helper()

				ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
				t.Cleanup(cancel)

				return ctx
			},
			assert: func(t *testing.T, mgr *manager, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)
				require.Equal(t, resolverStateStopped, mgr.resolver.state)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			repository := sourcemocks.NewRepositoryMock(t)
			repository.EXPECT().
				AddObserver(mock.Anything).
				Maybe()

			src := sourcemocks.NewSourceMock(t)

			tc.setup(t, repository, src)

			mgr := newTestManager(t, repository)

			if tc.before != nil {
				tc.before(t, mgr)
			}

			ctx := t.Context()
			if tc.startCtx != nil {
				ctx = tc.startCtx(t)
			}

			err := mgr.Start(ctx)

			tc.assert(t, mgr, err)
		})
	}
}

func TestManagerStop(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, repository *sourcemocks.RepositoryMock)
		assert func(t *testing.T, mgr *manager, err error)
	}{
		"stops repository and resolver": {
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock) {
				t.Helper()

				repository.EXPECT().
					Stop(mock.Anything).
					Return(nil)
			},
			assert: func(t *testing.T, mgr *manager, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, resolverStateStopped, mgr.resolver.state)
			},
		},
		"returns repository stop error": {
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock) {
				t.Helper()

				repository.EXPECT().
					Stop(mock.Anything).
					Return(assert.AnError)
			},
			assert: func(t *testing.T, mgr *manager, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)
				require.Equal(t, resolverStateStopped, mgr.resolver.state)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			repository := sourcemocks.NewRepositoryMock(t)
			repository.EXPECT().
				AddObserver(mock.Anything).
				Maybe()

			tc.setup(t, repository)

			mgr := newTestManager(t, repository)

			err := mgr.Stop(t.Context())

			tc.assert(t, mgr, err)
		})
	}
}

func TestDependencyResolverProxy(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		call  func(ctx context.Context, proxy *dependencyResolverProxy) (any, error)
		setup func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock)
		want  any
	}{
		"resolves secret": {
			call: func(ctx context.Context, proxy *dependencyResolverProxy) (any, error) {
				return proxy.ResolveSecret(ctx, Reference{Source: "src", Selector: "secret"})
			},
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock) {
				t.Helper()

				secret := types.NewStringSecret("secret", "value")

				repository.EXPECT().
					Lookup("src").
					Return(src, nil)

				src.EXPECT().
					IsNamespaceAware().
					Return(false)

				src.EXPECT().
					GetSecret(mock.Anything, source.Selector{Value: "secret"}).
					Return(secret, nil)
			},
			want: types.NewStringSecret("secret", "value"),
		},
		"resolves credentials": {
			call: func(ctx context.Context, proxy *dependencyResolverProxy) (any, error) {
				return proxy.ResolveCredentials(ctx, Reference{Source: "src", Selector: "credentials"})
			},
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock) {
				t.Helper()

				credentials := types.NewCredentials("credentials", map[string]any{"client_id": "heimdall"})

				repository.EXPECT().
					Lookup("src").
					Return(src, nil)

				src.EXPECT().
					IsNamespaceAware().
					Return(false)

				src.EXPECT().
					GetCredentials(mock.Anything, source.Selector{Value: "credentials"}).
					Return(credentials, nil)
			},
			want: types.NewCredentials("credentials", map[string]any{"client_id": "heimdall"}),
		},
		"resolves certificate bundle": {
			call: func(ctx context.Context, proxy *dependencyResolverProxy) (any, error) {
				return proxy.ResolveCertificateBundle(ctx, Reference{Source: "src", Selector: "bundle"})
			},
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock) {
				t.Helper()

				bundle := types.NewCertificateBundle("bundle", nil)

				repository.EXPECT().
					Lookup("src").
					Return(src, nil)

				src.EXPECT().
					IsNamespaceAware().
					Return(false)

				src.EXPECT().
					GetCertificateBundle(mock.Anything, source.Selector{Value: "bundle"}).
					Return(bundle, nil)
			},
			want: types.NewCertificateBundle("bundle", nil),
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			repository := sourcemocks.NewRepositoryMock(t)
			repository.EXPECT().
				AddObserver(mock.Anything).
				Maybe()

			src := sourcemocks.NewSourceMock(t)
			tc.setup(t, repository, src)

			res := newTestResolver(t, repository)

			proxy := &dependencyResolverProxy{resolver: res}

			got, err := tc.call(t.Context(), proxy)

			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestManagerStartTracksSecretUsageDuringReadiness(t *testing.T) {
	t.Parallel()

	secret := types.NewStringSecret("selector", "value")

	repository := sourcemocks.NewRepositoryMock(t)
	repository.EXPECT().
		AddObserver(mock.Anything).
		Maybe()

	src := sourcemocks.NewSourceMock(t)

	repository.EXPECT().
		Lookup("src").
		Return(src, nil).
		Twice()

	src.EXPECT().
		IsNamespaceAware().
		Return(false).
		Twice()

	repository.EXPECT().
		Start(mock.Anything).
		Return(nil)

	src.EXPECT().
		GetSecret(mock.Anything, source.Selector{Value: "selector"}).
		Return(secret, nil)

	usage := metricsmocks.NewSecretUsageMock(t)
	usage.EXPECT().Track(secret)
	usage.EXPECT().Untrack(secret)

	resolver, err := newResolver(zerolog.Nop(), repository, noopmetric.Meter{})
	require.NoError(t, err)

	resolver.su = usage

	mgr := &manager{
		repository: repository,
		resolver:   resolver,
	}

	t.Cleanup(func() {
		if resolver.state != resolverStateStopped {
			resolver.Stop()
		}
	})

	handle, err := mgr.Resolver().Secret(
		Reference{Source: "src", Selector: "selector"},
	)
	require.NoError(t, err)
	require.NotNil(t, handle)

	err = mgr.Start(t.Context())

	require.NoError(t, err)

	require.Eventually(t, func() bool {
		got, ok := handle.Get()

		return ok && got == secret
	}, time.Second, 10*time.Millisecond)
}

func newTestManager(
	t *testing.T,
	repository source.Repository,
) *manager {
	t.Helper()

	resolver, err := newResolver(zerolog.Nop(), repository, noopmetric.Meter{})
	require.NoError(t, err)

	t.Cleanup(func() {
		if resolver.state != resolverStateStopped {
			resolver.Stop()
		}
	})

	return &manager{
		repository: repository,
		resolver:   resolver,
	}
}

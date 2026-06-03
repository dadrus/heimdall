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
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	noopmetric "go.opentelemetry.io/otel/metric/noop"

	"github.com/dadrus/heimdall/internal/secrets/metrics/mocks"
	"github.com/dadrus/heimdall/internal/secrets/source"
	sourcemocks "github.com/dadrus/heimdall/internal/secrets/source/mocks"
	"github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/x/task"
)

func TestSourceObserverFuncNotify(t *testing.T) {
	t.Parallel()

	event := source.Event{
		Source: "src",
		Selectors: []source.Selector{
			{Value: "selector", Namespace: "team-a"},
		},
	}

	called := false

	observer := sourceObserverFunc(func(got source.Event) {
		called = true

		require.Equal(t, event, got)
	})

	observer.Notify(event)

	require.True(t, called)
}

func TestNewResolver(t *testing.T) {
	t.Parallel()

	repository := sourcemocks.NewRepositoryMock(t)
	repository.EXPECT().
		AddObserver(mock.MatchedBy(func(observer source.Observer) bool {
			return observer != nil
		})).
		Once()

	res, err := newResolver(zerolog.Nop(), repository, noopmetric.Meter{})

	require.NoError(t, err)
	require.NotNil(t, res)
	t.Cleanup(res.Stop)

	require.Same(t, repository, res.sources)
	require.NotNil(t, res.executor)
	require.NotNil(t, res.appScope)
	require.NotNil(t, res.secretBindings)
	require.NotNil(t, res.secretSetBindings)
	require.NotNil(t, res.credentialsBindings)
	require.NotNil(t, res.certificateBundleBindings)
	require.Equal(t, resolverStateInitial, res.state)
	require.Empty(t, res.pendingTasks)
}

func TestResolverStart(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, res *resolver, calls *atomic.Int32)
		assert func(t *testing.T, res *resolver, calls *atomic.Int32)
	}{
		"starts resolver and schedules pending tasks": {
			setup: func(t *testing.T, res *resolver, calls *atomic.Int32) {
				t.Helper()

				bdg1 := newBinding(
					bindingKey{
						kind:      bindingKindSecret,
						source:    "source",
						selector:  "selector",
						namespace: "namespace",
						scope:     referenceScopeInternal,
					},
					zerolog.Nop(),
					mocks.NewSecretUsageMock(t),
					func(context.Context) (string, error) {
						calls.Add(1)

						return "a", nil
					},
				)

				bdg2 := newBinding(
					bindingKey{
						kind:      bindingKindSecret,
						source:    "source",
						selector:  "selector",
						namespace: "namespace",
						scope:     referenceScopeInternal,
					},
					zerolog.Nop(),
					mocks.NewSecretUsageMock(t),
					func(context.Context) (string, error) {
						calls.Add(1)

						return "b", nil
					},
				)

				res.pendingTasks = append(
					res.pendingTasks,
					bdg1,
					bdg2,
				)
			},
			assert: func(t *testing.T, res *resolver, calls *atomic.Int32) {
				t.Helper()

				require.Equal(t, resolverStateStarted, res.state)
				require.Empty(t, res.pendingTasks)

				require.Eventually(t, func() bool {
					return calls.Load() == 2
				}, time.Second, 10*time.Millisecond)
			},
		},
		"does nothing when stopped": {
			setup: func(t *testing.T, res *resolver, calls *atomic.Int32) {
				t.Helper()

				bdg := newBinding(
					bindingKey{
						kind:      bindingKindSecret,
						source:    "source",
						selector:  "selector",
						namespace: "namespace",
						scope:     referenceScopeInternal,
					},
					zerolog.Nop(),
					mocks.NewSecretUsageMock(t),
					func(context.Context) (string, error) {
						calls.Add(1)

						return "ignored", nil
					},
				)

				res.state = resolverStateStopped
				res.pendingTasks = append(res.pendingTasks, bdg)
			},
			assert: func(t *testing.T, res *resolver, calls *atomic.Int32) {
				t.Helper()

				require.Equal(t, resolverStateStopped, res.state)
				require.Len(t, res.pendingTasks, 1)
				require.Zero(t, calls.Load())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			var calls atomic.Int32

			res := newEmptyTestResolver(t)
			tc.setup(t, res, &calls)

			res.Start()

			tc.assert(t, res, &calls)
		})
	}
}

func TestResolverScheduleResolve(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		state  resolverState
		assert func(t *testing.T, res *resolver, calls *atomic.Int32)
	}{
		"queues task while initial": {
			state: resolverStateInitial,
			assert: func(t *testing.T, res *resolver, calls *atomic.Int32) {
				t.Helper()

				require.Len(t, res.pendingTasks, 1)
				require.Zero(t, calls.Load())
			},
		},
		"schedules task while started": {
			state: resolverStateStarted,
			assert: func(t *testing.T, res *resolver, calls *atomic.Int32) {
				t.Helper()

				require.Empty(t, res.pendingTasks)
				require.Eventually(t, func() bool {
					return calls.Load() == 1
				}, time.Second, 10*time.Millisecond)
			},
		},
		"ignores task while stopped": {
			state: resolverStateStopped,
			assert: func(t *testing.T, res *resolver, calls *atomic.Int32) {
				t.Helper()

				require.Empty(t, res.pendingTasks)
				require.Zero(t, calls.Load())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			var calls atomic.Int32

			res := newEmptyTestResolver(t)
			res.state = tc.state

			bdg := newBinding(
				bindingKey{
					kind:      bindingKindSecret,
					source:    "source",
					selector:  "selector",
					namespace: "namespace",
					scope:     referenceScopeInternal,
				},
				zerolog.Nop(),
				mocks.NewSecretUsageMock(t),
				func(context.Context) (string, error) {
					calls.Add(1)

					return "resolved", nil
				},
			)

			res.scheduleResolve(bdg)

			tc.assert(t, res, &calls)
		})
	}
}

func TestResolverGlobalResolver(t *testing.T) {
	t.Parallel()

	res := newEmptyTestResolver(t)

	global := res.globalResolver()

	require.NotNil(t, global)
	require.Same(t, res.appScope, global)
}

func TestResolverScopedResolver(t *testing.T) {
	t.Parallel()

	res := newEmptyTestResolver(t)

	scopedA := res.scopedResolver(WithID("ruleset-a"), WithNamespace("team-a"))
	scopedAAgain := res.scopedResolver(WithID("ruleset-a"), WithNamespace("team-a"))
	scopedB := res.scopedResolver(WithID("ruleset-b"))

	require.NotNil(t, scopedA)
	require.NotNil(t, scopedAAgain)
	require.NotNil(t, scopedB)
	require.NotSame(t, scopedA, scopedAAgain)
	require.NotSame(t, scopedA, scopedB)

	scopeA := scopedA.(*scope)
	scopeAAgain := scopedAAgain.(*scope)
	scopeB := scopedB.(*scope)

	require.Equal(t, "ruleset-a", scopeA.id)
	require.Equal(t, "team-a", scopeA.namespace)

	require.Equal(t, "ruleset-a", scopeAAgain.id)
	require.Equal(t, "team-a", scopeAAgain.namespace)

	require.Equal(t, "ruleset-b", scopeB.id)
	require.Empty(t, scopeB.namespace)

	ref := scopeA.refFactory(Reference{Source: "src", Selector: "selector"})
	require.Equal(t, "src", ref.Source)
	require.Equal(t, "selector", ref.Selector)
	require.Equal(t, "team-a", ref.namespace)
	require.Equal(t, referenceScopeRule, ref.scope)
}

func TestResolverAwaitReady(t *testing.T) {
	t.Parallel()

	res := newEmptyTestResolver(t)

	err := res.AwaitReady(t.Context())

	require.NoError(t, err)
}

func TestResolverResolveSecret(t *testing.T) {
	t.Parallel()

	secret := types.NewStringSecret("selector", "value")

	repository := sourcemocks.NewRepositoryMock(t)
	repository.EXPECT().AddObserver(mock.Anything).Maybe()

	src := sourcemocks.NewSourceMock(t)

	repository.EXPECT().
		Lookup("src").
		Return(src, nil)

	src.EXPECT().
		IsNamespaceAware().
		Return(true)

	src.EXPECT().
		GetSecret(mock.Anything, source.Selector{Value: "selector"}).
		Return(secret, nil)

	res := newTestResolver(t, repository)

	got, err := res.ResolveSecret(
		t.Context(),
		Reference{Source: "src", Selector: "selector"},
	)

	require.NoError(t, err)
	require.Equal(t, secret, got)
}

func TestResolverResolveCredentials(t *testing.T) {
	t.Parallel()

	credentials := types.NewCredentials("selector", map[string]any{"client_id": "heimdall"})

	repository := sourcemocks.NewRepositoryMock(t)
	repository.EXPECT().AddObserver(mock.Anything).Maybe()

	src := sourcemocks.NewSourceMock(t)

	repository.EXPECT().
		Lookup("src").
		Return(src, nil)

	src.EXPECT().
		IsNamespaceAware().
		Return(true)

	src.EXPECT().
		GetCredentials(mock.Anything, source.Selector{Value: "selector"}).
		Return(credentials, nil)

	res := newTestResolver(t, repository)

	got, err := res.ResolveCredentials(
		t.Context(),
		Reference{Source: "src", Selector: "selector"},
	)

	require.NoError(t, err)
	require.Equal(t, credentials, got)
}

func TestResolverResolveCertificateBundle(t *testing.T) {
	t.Parallel()

	bundle := types.NewCertificateBundle("selector", nil)

	repository := sourcemocks.NewRepositoryMock(t)
	repository.EXPECT().AddObserver(mock.Anything).Maybe()

	src := sourcemocks.NewSourceMock(t)

	repository.EXPECT().
		Lookup("src").
		Return(src, nil)

	src.EXPECT().
		IsNamespaceAware().
		Return(true)

	src.EXPECT().
		GetCertificateBundle(mock.Anything, source.Selector{Value: "selector"}).
		Return(bundle, nil)

	res := newTestResolver(t, repository)

	got, err := res.ResolveCertificateBundle(
		t.Context(),
		Reference{Source: "src", Selector: "selector"},
	)

	require.NoError(t, err)
	require.Equal(t, bundle, got)
}

func TestResolverResolveSecretScoped(t *testing.T) {
	t.Parallel()

	secret := types.NewStringSecret("selector", "value")

	for uc, tc := range map[string]struct {
		reference scopedReference
		setup     func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock)
		assert    func(t *testing.T, got Secret, err error)
	}{
		"resolves secret from non namespace aware source": {
			reference: internalRef(Reference{Source: "src", Selector: "selector"}),
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock) {
				t.Helper()

				repository.EXPECT().
					Lookup("src").
					Return(src, nil)

				src.EXPECT().
					IsNamespaceAware().
					Return(false)

				src.EXPECT().
					GetSecret(mock.Anything, source.Selector{Value: "selector"}).
					Return(secret, nil)
			},
			assert: func(t *testing.T, got Secret, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, secret, got)
			},
		},
		"resolves secret from namespace aware source with namespace": {
			reference: namespacedRuleRef("team-a")(Reference{Source: "src", Selector: "selector"}),
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock) {
				t.Helper()

				repository.EXPECT().
					Lookup("src").
					Return(src, nil)

				src.EXPECT().
					AccessFromRulesAllowed().
					Return(true)

				src.EXPECT().
					IsNamespaceAware().
					Return(true)

				src.EXPECT().
					GetSecret(mock.Anything, source.Selector{
						Value:     "selector",
						Namespace: "team-a",
					}).
					Return(secret, nil)
			},
			assert: func(t *testing.T, got Secret, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, secret, got)
			},
		},
		"returns lookup error": {
			reference: internalRef(Reference{Source: "src", Selector: "selector"}),
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, _ *sourcemocks.SourceMock) {
				t.Helper()

				repository.EXPECT().
					Lookup("src").
					Return(nil, assert.AnError)
			},
			assert: func(t *testing.T, got Secret, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)
				require.Nil(t, got)
			},
		},
		"returns source error": {
			reference: internalRef(Reference{Source: "src", Selector: "selector"}),
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock) {
				t.Helper()

				repository.EXPECT().
					Lookup("src").
					Return(src, nil)

				src.EXPECT().
					IsNamespaceAware().
					Return(false)

				src.EXPECT().
					GetSecret(mock.Anything, source.Selector{Value: "selector"}).
					Return(nil, assert.AnError)
			},
			assert: func(t *testing.T, got Secret, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)
				require.Nil(t, got)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			repository := sourcemocks.NewRepositoryMock(t)
			repository.EXPECT().AddObserver(mock.Anything).Maybe()

			src := sourcemocks.NewSourceMock(t)
			tc.setup(t, repository, src)

			res := newTestResolver(t, repository)

			got, err := res.resolveSecret(t.Context(), tc.reference)

			tc.assert(t, got, err)
		})
	}
}

func TestResolverResolveSecretSet(t *testing.T) {
	t.Parallel()

	secrets := []Secret{
		types.NewStringSecret("selector/a", "a"),
		types.NewStringSecret("selector/b", "b"),
	}

	for uc, tc := range map[string]struct {
		reference scopedReference
		setup     func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock)
		assert    func(t *testing.T, got []Secret, err error)
	}{
		"resolves secret set from non namespace aware source": {
			reference: internalRef(Reference{Source: "src", Selector: "selector"}),
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock) {
				t.Helper()

				repository.EXPECT().
					Lookup("src").
					Return(src, nil)

				src.EXPECT().
					IsNamespaceAware().
					Return(false)

				src.EXPECT().
					GetSecretSet(mock.Anything, source.Selector{Value: "selector"}).
					Return(secrets, nil)
			},
			assert: func(t *testing.T, got []Secret, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, secrets, got)
			},
		},
		"resolves secret set from namespace aware source with namespace": {
			reference: namespacedRuleRef("team-a")(Reference{Source: "src", Selector: "selector"}),
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock) {
				t.Helper()

				repository.EXPECT().
					Lookup("src").
					Return(src, nil)

				src.EXPECT().
					AccessFromRulesAllowed().
					Return(true)

				src.EXPECT().
					IsNamespaceAware().
					Return(true)

				src.EXPECT().
					GetSecretSet(mock.Anything, source.Selector{
						Value:     "selector",
						Namespace: "team-a",
					}).
					Return(secrets, nil)
			},
			assert: func(t *testing.T, got []Secret, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, secrets, got)
			},
		},
		"returns lookup error": {
			reference: internalRef(Reference{Source: "src", Selector: "selector"}),
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, _ *sourcemocks.SourceMock) {
				t.Helper()

				repository.EXPECT().
					Lookup("src").
					Return(nil, assert.AnError)
			},
			assert: func(t *testing.T, got []Secret, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)
				require.Nil(t, got)
			},
		},
		"returns source error": {
			reference: internalRef(Reference{Source: "src", Selector: "selector"}),
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock) {
				t.Helper()

				repository.EXPECT().
					Lookup("src").
					Return(src, nil)

				src.EXPECT().
					IsNamespaceAware().
					Return(false)

				src.EXPECT().
					GetSecretSet(mock.Anything, source.Selector{Value: "selector"}).
					Return(nil, assert.AnError)
			},
			assert: func(t *testing.T, got []Secret, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)
				require.Nil(t, got)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			repository := sourcemocks.NewRepositoryMock(t)
			repository.EXPECT().AddObserver(mock.Anything).Maybe()

			src := sourcemocks.NewSourceMock(t)
			tc.setup(t, repository, src)

			res := newTestResolver(t, repository)

			got, err := res.resolveSecretSet(t.Context(), tc.reference)

			tc.assert(t, got, err)
		})
	}
}

func TestResolverResolveCredentialsScoped(t *testing.T) {
	t.Parallel()

	credentials := types.NewCredentials("selector", map[string]any{"client_id": "heimdall"})

	for uc, tc := range map[string]struct {
		reference scopedReference
		setup     func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock)
		assert    func(t *testing.T, got Credentials, err error)
	}{
		"resolves credentials from non namespace aware source": {
			reference: internalRef(Reference{Source: "src", Selector: "selector"}),
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock) {
				t.Helper()

				repository.EXPECT().
					Lookup("src").
					Return(src, nil)

				src.EXPECT().
					IsNamespaceAware().
					Return(false)

				src.EXPECT().
					GetCredentials(mock.Anything, source.Selector{Value: "selector"}).
					Return(credentials, nil)
			},
			assert: func(t *testing.T, got Credentials, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, credentials, got)
			},
		},
		"resolves credentials from namespace aware source with namespace": {
			reference: namespacedRuleRef("team-a")(Reference{Source: "src", Selector: "selector"}),
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock) {
				t.Helper()

				repository.EXPECT().
					Lookup("src").
					Return(src, nil)

				src.EXPECT().
					AccessFromRulesAllowed().
					Return(true)

				src.EXPECT().
					IsNamespaceAware().
					Return(true)

				src.EXPECT().
					GetCredentials(mock.Anything, source.Selector{
						Value:     "selector",
						Namespace: "team-a",
					}).
					Return(credentials, nil)
			},
			assert: func(t *testing.T, got Credentials, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, credentials, got)
			},
		},
		"returns lookup error": {
			reference: internalRef(Reference{Source: "src", Selector: "selector"}),
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, _ *sourcemocks.SourceMock) {
				t.Helper()

				repository.EXPECT().
					Lookup("src").
					Return(nil, assert.AnError)
			},
			assert: func(t *testing.T, got Credentials, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)
				require.Nil(t, got)
			},
		},
		"returns source error": {
			reference: internalRef(Reference{Source: "src", Selector: "selector"}),
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock) {
				t.Helper()

				repository.EXPECT().
					Lookup("src").
					Return(src, nil)

				src.EXPECT().
					IsNamespaceAware().
					Return(false)

				src.EXPECT().
					GetCredentials(mock.Anything, source.Selector{Value: "selector"}).
					Return(nil, assert.AnError)
			},
			assert: func(t *testing.T, got Credentials, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)
				require.Nil(t, got)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			repository := sourcemocks.NewRepositoryMock(t)
			repository.EXPECT().AddObserver(mock.Anything).Maybe()

			src := sourcemocks.NewSourceMock(t)
			tc.setup(t, repository, src)

			res := newTestResolver(t, repository)

			got, err := res.resolveCredentials(t.Context(), tc.reference)

			tc.assert(t, got, err)
		})
	}
}

func TestResolverResolveCertificateBundleScoped(t *testing.T) {
	t.Parallel()

	bundle := types.NewCertificateBundle("selector", nil)

	for uc, tc := range map[string]struct {
		reference scopedReference
		setup     func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock)
		assert    func(t *testing.T, got CertificateBundle, err error)
	}{
		"resolves certificate bundle from non namespace aware source": {
			reference: internalRef(Reference{Source: "src", Selector: "selector"}),
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock) {
				t.Helper()

				repository.EXPECT().
					Lookup("src").
					Return(src, nil)

				src.EXPECT().
					IsNamespaceAware().
					Return(false)

				src.EXPECT().
					GetCertificateBundle(mock.Anything, source.Selector{Value: "selector"}).
					Return(bundle, nil)
			},
			assert: func(t *testing.T, got CertificateBundle, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, bundle, got)
			},
		},
		"resolves certificate bundle from namespace aware source with namespace": {
			reference: namespacedRuleRef("team-a")(Reference{Source: "src", Selector: "selector"}),
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock) {
				t.Helper()

				repository.EXPECT().
					Lookup("src").
					Return(src, nil)

				src.EXPECT().
					AccessFromRulesAllowed().
					Return(true)

				src.EXPECT().
					IsNamespaceAware().
					Return(true)

				src.EXPECT().
					GetCertificateBundle(mock.Anything, source.Selector{
						Value:     "selector",
						Namespace: "team-a",
					}).
					Return(bundle, nil)
			},
			assert: func(t *testing.T, got CertificateBundle, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, bundle, got)
			},
		},
		"returns lookup error": {
			reference: internalRef(Reference{Source: "src", Selector: "selector"}),
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, _ *sourcemocks.SourceMock) {
				t.Helper()

				repository.EXPECT().
					Lookup("src").
					Return(nil, assert.AnError)
			},
			assert: func(t *testing.T, got CertificateBundle, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)
				require.Nil(t, got)
			},
		},
		"returns source error": {
			reference: internalRef(Reference{Source: "src", Selector: "selector"}),
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock) {
				t.Helper()

				repository.EXPECT().
					Lookup("src").
					Return(src, nil)

				src.EXPECT().
					IsNamespaceAware().
					Return(false)

				src.EXPECT().
					GetCertificateBundle(mock.Anything, source.Selector{Value: "selector"}).
					Return(nil, assert.AnError)
			},
			assert: func(t *testing.T, got CertificateBundle, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)
				require.Nil(t, got)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			repository := sourcemocks.NewRepositoryMock(t)
			repository.EXPECT().AddObserver(mock.Anything).Maybe()

			src := sourcemocks.NewSourceMock(t)
			tc.setup(t, repository, src)

			res := newTestResolver(t, repository)

			got, err := res.resolveCertificateBundle(t.Context(), tc.reference)

			tc.assert(t, got, err)
		})
	}
}

func TestResolverLookupSource(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		reference scopedReference
		setup     func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock)
		wantErr   error
	}{
		"returns source for internal reference": {
			reference: internalRef(Reference{Source: "src", Selector: "selector"}),
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock) {
				t.Helper()

				repository.EXPECT().
					Lookup("src").
					Return(src, nil)
			},
		},
		"allows rule reference if source is allowed in rules": {
			reference: namespacedRuleRef("team-a")(Reference{Source: "src", Selector: "selector"}),
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock) {
				t.Helper()

				repository.EXPECT().
					Lookup("src").
					Return(src, nil)

				src.EXPECT().
					AccessFromRulesAllowed().
					Return(true)
			},
		},
		"forbids rule reference if source is not allowed in rules": {
			reference: namespacedRuleRef("team-a")(Reference{Source: "src", Selector: "selector"}),
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock) {
				t.Helper()

				repository.EXPECT().
					Lookup("src").
					Return(src, nil)

				src.EXPECT().
					AccessFromRulesAllowed().
					Return(false)
			},
			wantErr: ErrSourceForbidden,
		},
		"returns lookup error": {
			reference: internalRef(Reference{Source: "src", Selector: "selector"}),
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, _ *sourcemocks.SourceMock) {
				t.Helper()

				repository.EXPECT().
					Lookup("src").
					Return(nil, assert.AnError)
			},
			wantErr: assert.AnError,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			repository := sourcemocks.NewRepositoryMock(t)
			repository.EXPECT().AddObserver(mock.Anything).Maybe()

			src := sourcemocks.NewSourceMock(t)
			tc.setup(t, repository, src)

			res := newTestResolver(t, repository)

			got, err := res.lookupSource(tc.reference)

			if tc.wantErr != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.wantErr)
				require.Nil(t, got)

				return
			}

			require.NoError(t, err)
			require.Equal(t, src, got)
		})
	}
}

func TestResolverBindingKey(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		namespaceAware bool
		reference      scopedReference
		want           bindingKey
	}{
		"uses namespace for namespace aware source": {
			namespaceAware: true,
			reference:      namespacedRuleRef("team-a")(Reference{Source: "src", Selector: "selector"}),
			want: bindingKey{
				kind:      bindingKindSecret,
				source:    "src",
				selector:  "selector",
				namespace: "team-a",
				scope:     referenceScopeRule,
			},
		},
		"ignores namespace for non namespace aware source": {
			namespaceAware: false,
			reference:      namespacedRuleRef("team-a")(Reference{Source: "src", Selector: "selector"}),
			want: bindingKey{
				kind:      bindingKindSecret,
				source:    "src",
				selector:  "selector",
				namespace: "",
				scope:     referenceScopeRule,
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			repository := sourcemocks.NewRepositoryMock(t)
			repository.EXPECT().AddObserver(mock.Anything).Maybe()

			src := sourcemocks.NewSourceMock(t)

			repository.EXPECT().
				Lookup("src").
				Return(src, nil)

			src.EXPECT().
				AccessFromRulesAllowed().
				Return(true)

			src.EXPECT().
				IsNamespaceAware().
				Return(tc.namespaceAware)

			res := newTestResolver(t, repository)

			got, err := res.bindingKey(tc.reference, bindingKindSecret)

			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestResolverBindingReturnsBindingKeyError(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		call func(res *resolver, ref scopedReference) (any, bindingKey, error)
	}{
		"secret binding": {
			call: func(res *resolver, ref scopedReference) (any, bindingKey, error) {
				return res.secretBinding(ref)
			},
		},
		"secret set binding": {
			call: func(res *resolver, ref scopedReference) (any, bindingKey, error) {
				return res.secretSetBinding(ref)
			},
		},
		"credentials binding": {
			call: func(res *resolver, ref scopedReference) (any, bindingKey, error) {
				return res.credentialsBinding(ref)
			},
		},
		"certificate bundle binding": {
			call: func(res *resolver, ref scopedReference) (any, bindingKey, error) {
				return res.certificateBundleBinding(ref)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			repository := sourcemocks.NewRepositoryMock(t)
			repository.EXPECT().AddObserver(mock.Anything).Maybe()

			repository.EXPECT().
				Lookup("src").
				Return(nil, assert.AnError)

			res := newTestResolver(t, repository)

			got, key, err := tc.call(
				res,
				internalRef(Reference{Source: "src", Selector: "selector"}),
			)

			require.Error(t, err)
			require.ErrorIs(t, err, assert.AnError)
			require.Nil(t, got)
			require.Equal(t, bindingKey{}, key)
		})
	}
}

func TestResolverSecretBinding(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		start  bool
		setup  func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock, calls *atomic.Int32)
		assert func(t *testing.T, res *resolver, bdg *binding[Secret], key bindingKey, calls *atomic.Int32, err error)
	}{
		"creates binding and queues initial resolve before start": {
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock, _ *atomic.Int32) {
				t.Helper()

				repository.EXPECT().Lookup("src").Return(src, nil)
				src.EXPECT().IsNamespaceAware().Return(false)
			},
			assert: func(t *testing.T, res *resolver, bdg *binding[Secret], key bindingKey, calls *atomic.Int32, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, bdg)
				require.Equal(t, bindingKindSecret, key.kind)
				require.Len(t, res.secretBindings, 1)
				require.Equal(t, 1, res.secretBindings[key].leases)
				require.Len(t, res.pendingTasks, 1)
				require.Zero(t, calls.Load())
			},
		},
		"creates binding and schedules initial resolve after start": {
			start: true,
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock, calls *atomic.Int32) {
				t.Helper()

				repository.EXPECT().Lookup("src").Return(src, nil).Twice()
				src.EXPECT().IsNamespaceAware().Return(false).Twice()
				src.EXPECT().
					GetSecret(mock.Anything, source.Selector{Value: "selector"}).
					Run(func(context.Context, source.Selector) {
						calls.Add(1)
					}).
					Return(types.NewStringSecret("selector", "value"), nil)
			},
			assert: func(t *testing.T, res *resolver, bdg *binding[Secret], key bindingKey, calls *atomic.Int32, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, bdg)
				require.Empty(t, res.pendingTasks)
				require.Len(t, res.secretBindings, 1)
				require.Equal(t, 1, res.secretBindings[key].leases)

				require.Eventually(t, func() bool {
					return calls.Load() == 1
				}, time.Second, 10*time.Millisecond)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			var calls atomic.Int32

			repository := sourcemocks.NewRepositoryMock(t)
			repository.EXPECT().AddObserver(mock.Anything).Maybe()

			src := sourcemocks.NewSourceMock(t)
			tc.setup(t, repository, src, &calls)

			res := newTestResolver(t, repository)
			if tc.start {
				res.Start()
			}

			bdg, key, err := res.secretBinding(
				internalRef(Reference{Source: "src", Selector: "selector"}),
			)

			tc.assert(t, res, bdg, key, &calls, err)
		})
	}
}

func TestResolverSecretSetBinding(t *testing.T) {
	t.Parallel()

	secrets := []Secret{
		types.NewStringSecret("selector/a", "a"),
		types.NewStringSecret("selector/b", "b"),
	}

	for uc, tc := range map[string]struct {
		start  bool
		setup  func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock, calls *atomic.Int32)
		assert func(t *testing.T, res *resolver, bdg *binding[[]Secret], key bindingKey, calls *atomic.Int32, err error)
	}{
		"creates binding and queues initial resolve before start": {
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock, _ *atomic.Int32) {
				t.Helper()

				repository.EXPECT().Lookup("src").Return(src, nil)
				src.EXPECT().IsNamespaceAware().Return(false)
			},
			assert: func(t *testing.T, res *resolver, bdg *binding[[]Secret], key bindingKey, calls *atomic.Int32, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, bdg)
				require.Equal(t, bindingKindSecretSet, key.kind)
				require.Len(t, res.secretSetBindings, 1)
				require.Equal(t, 1, res.secretSetBindings[key].leases)
				require.Len(t, res.pendingTasks, 1)
				require.Zero(t, calls.Load())
			},
		},
		"creates binding and schedules initial resolve after start": {
			start: true,
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock, calls *atomic.Int32) {
				t.Helper()

				repository.EXPECT().Lookup("src").Return(src, nil).Twice()
				src.EXPECT().IsNamespaceAware().Return(false).Twice()
				src.EXPECT().
					GetSecretSet(mock.Anything, source.Selector{Value: "selector"}).
					Run(func(context.Context, source.Selector) {
						calls.Add(1)
					}).
					Return(secrets, nil)
			},
			assert: func(t *testing.T, res *resolver, bdg *binding[[]Secret], key bindingKey, calls *atomic.Int32, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, bdg)
				require.Empty(t, res.pendingTasks)
				require.Len(t, res.secretSetBindings, 1)
				require.Equal(t, 1, res.secretSetBindings[key].leases)

				require.Eventually(t, func() bool {
					return calls.Load() == 1
				}, time.Second, 10*time.Millisecond)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			var calls atomic.Int32

			repository := sourcemocks.NewRepositoryMock(t)
			repository.EXPECT().AddObserver(mock.Anything).Maybe()

			src := sourcemocks.NewSourceMock(t)
			tc.setup(t, repository, src, &calls)

			res := newTestResolver(t, repository)
			if tc.start {
				res.Start()
			}

			bdg, key, err := res.secretSetBinding(
				internalRef(Reference{Source: "src", Selector: "selector"}),
			)

			tc.assert(t, res, bdg, key, &calls, err)
		})
	}
}

func TestResolverCredentialsBinding(t *testing.T) {
	t.Parallel()

	credentials := types.NewCredentials("selector", map[string]any{"client_id": "heimdall"})

	for uc, tc := range map[string]struct {
		start  bool
		setup  func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock, calls *atomic.Int32)
		assert func(t *testing.T, res *resolver, bdg *binding[Credentials], key bindingKey, calls *atomic.Int32, err error)
	}{
		"creates binding and queues initial resolve before start": {
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock, _ *atomic.Int32) {
				t.Helper()

				repository.EXPECT().Lookup("src").Return(src, nil)
				src.EXPECT().IsNamespaceAware().Return(false)
			},
			assert: func(t *testing.T, res *resolver, bdg *binding[Credentials], key bindingKey, calls *atomic.Int32, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, bdg)
				require.Equal(t, bindingKindCredentials, key.kind)
				require.Len(t, res.credentialsBindings, 1)
				require.Equal(t, 1, res.credentialsBindings[key].leases)
				require.Len(t, res.pendingTasks, 1)
				require.Zero(t, calls.Load())
			},
		},
		"creates binding and schedules initial resolve after start": {
			start: true,
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock, calls *atomic.Int32) {
				t.Helper()

				repository.EXPECT().Lookup("src").Return(src, nil).Twice()
				src.EXPECT().IsNamespaceAware().Return(false).Twice()
				src.EXPECT().
					GetCredentials(mock.Anything, source.Selector{Value: "selector"}).
					Run(func(context.Context, source.Selector) {
						calls.Add(1)
					}).
					Return(credentials, nil)
			},
			assert: func(t *testing.T, res *resolver, bdg *binding[Credentials], key bindingKey, calls *atomic.Int32, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, bdg)
				require.Empty(t, res.pendingTasks)
				require.Len(t, res.credentialsBindings, 1)
				require.Equal(t, 1, res.credentialsBindings[key].leases)

				require.Eventually(t, func() bool {
					return calls.Load() == 1
				}, time.Second, 10*time.Millisecond)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			var calls atomic.Int32

			repository := sourcemocks.NewRepositoryMock(t)
			repository.EXPECT().AddObserver(mock.Anything).Maybe()

			src := sourcemocks.NewSourceMock(t)
			tc.setup(t, repository, src, &calls)

			res := newTestResolver(t, repository)
			if tc.start {
				res.Start()
			}

			bdg, key, err := res.credentialsBinding(
				internalRef(Reference{Source: "src", Selector: "selector"}),
			)

			tc.assert(t, res, bdg, key, &calls, err)
		})
	}
}

func TestResolverCertificateBundleBinding(t *testing.T) {
	t.Parallel()

	bundle := types.NewCertificateBundle("selector", nil)

	for uc, tc := range map[string]struct {
		start  bool
		setup  func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock, calls *atomic.Int32)
		assert func(t *testing.T, res *resolver, bdg *binding[CertificateBundle], key bindingKey, calls *atomic.Int32, err error)
	}{
		"creates binding and queues initial resolve before start": {
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock, _ *atomic.Int32) {
				t.Helper()

				repository.EXPECT().Lookup("src").Return(src, nil)
				src.EXPECT().IsNamespaceAware().Return(false)
			},
			assert: func(t *testing.T, res *resolver, bdg *binding[CertificateBundle], key bindingKey, calls *atomic.Int32, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, bdg)
				require.Equal(t, bindingKindCertificateBundle, key.kind)
				require.Len(t, res.certificateBundleBindings, 1)
				require.Equal(t, 1, res.certificateBundleBindings[key].leases)
				require.Len(t, res.pendingTasks, 1)
				require.Zero(t, calls.Load())
			},
		},
		"creates binding and schedules initial resolve after start": {
			start: true,
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock, calls *atomic.Int32) {
				t.Helper()

				repository.EXPECT().Lookup("src").Return(src, nil).Twice()
				src.EXPECT().IsNamespaceAware().Return(false).Twice()
				src.EXPECT().
					GetCertificateBundle(mock.Anything, source.Selector{Value: "selector"}).
					Run(func(context.Context, source.Selector) {
						calls.Add(1)
					}).
					Return(bundle, nil)
			},
			assert: func(t *testing.T, res *resolver, bdg *binding[CertificateBundle], key bindingKey, calls *atomic.Int32, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, bdg)
				require.Empty(t, res.pendingTasks)
				require.Len(t, res.certificateBundleBindings, 1)
				require.Equal(t, 1, res.certificateBundleBindings[key].leases)

				require.Eventually(t, func() bool {
					return calls.Load() == 1
				}, time.Second, 10*time.Millisecond)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			var calls atomic.Int32

			repository := sourcemocks.NewRepositoryMock(t)
			repository.EXPECT().AddObserver(mock.Anything).Maybe()

			src := sourcemocks.NewSourceMock(t)
			tc.setup(t, repository, src, &calls)

			res := newTestResolver(t, repository)
			if tc.start {
				res.Start()
			}

			bdg, key, err := res.certificateBundleBinding(
				internalRef(Reference{Source: "src", Selector: "selector"}),
			)

			tc.assert(t, res, bdg, key, &calls, err)
		})
	}
}

func TestResolverSecretBindingReusesExistingBinding(t *testing.T) {
	t.Parallel()

	repository := sourcemocks.NewRepositoryMock(t)
	repository.EXPECT().AddObserver(mock.Anything).Maybe()

	src := sourcemocks.NewSourceMock(t)

	repository.EXPECT().Lookup("src").Return(src, nil).Twice()
	src.EXPECT().IsNamespaceAware().Return(false).Twice()

	res := newTestResolver(t, repository)

	first, key, err := res.secretBinding(
		internalRef(Reference{Source: "src", Selector: "selector"}),
	)
	require.NoError(t, err)

	second, secondKey, err := res.secretBinding(
		internalRef(Reference{Source: "src", Selector: "selector"}),
	)
	require.NoError(t, err)

	require.Same(t, first, second)
	require.Equal(t, key, secondKey)
	require.Equal(t, 2, res.secretBindings[key].leases)
	require.Len(t, res.pendingTasks, 1)
}

func TestResolverReleaseBinding(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		initialLeases int
		releaseCount  int
		wantPresent   bool
		wantLeases    int
	}{
		"decrements lease count": {
			initialLeases: 2,
			releaseCount:  1,
			wantPresent:   true,
			wantLeases:    1,
		},
		"removes and stops binding when last lease is released": {
			initialLeases: 1,
			releaseCount:  1,
			wantPresent:   false,
		},
		"removes and stops binding when release count exceeds leases": {
			initialLeases: 1,
			releaseCount:  2,
			wantPresent:   false,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			res := newEmptyTestResolver(t)

			key := bindingKey{
				kind:     bindingKindSecret,
				source:   "src",
				selector: "selector",
				scope:    referenceScopeInternal,
			}

			bdg := newBinding[Secret](
				bindingKey{
					kind:      bindingKindSecret,
					source:    "source",
					selector:  "selector",
					namespace: "namespace",
					scope:     referenceScopeInternal,
				},
				zerolog.Nop(),
				mocks.NewSecretUsageMock(t),
				nil,
			)

			res.secretBindings[key] = &leasedBinding[Secret]{
				binding: bdg,
				leases:  tc.initialLeases,
			}

			res.releaseBinding(key, tc.releaseCount)

			entry, ok := res.secretBindings[key]
			require.Equal(t, tc.wantPresent, ok)

			if tc.wantPresent {
				require.Equal(t, tc.wantLeases, entry.leases)
				require.True(t, bdg.Schedule())

				return
			}

			require.False(t, bdg.Schedule())
		})
	}
}

func TestResolverReleaseBindingForAllKinds(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		kind   bindingKind
		setup  func(t *testing.T, res *resolver, key bindingKey) *bindingMarker
		assert func(t *testing.T, res *resolver, marker *bindingMarker)
	}{
		"secret": {
			kind: bindingKindSecret,
			setup: func(t *testing.T, res *resolver, key bindingKey) *bindingMarker {
				t.Helper()

				bdg := newBinding[Secret](
					bindingKey{
						kind:      bindingKindSecret,
						source:    "source",
						selector:  "selector",
						namespace: "namespace",
						scope:     referenceScopeInternal,
					},
					zerolog.Nop(),
					mocks.NewSecretUsageMock(t),
					nil,
				)

				res.secretBindings[key] = &leasedBinding[Secret]{binding: bdg, leases: 1}

				return &bindingMarker{schedule: bdg.Schedule}
			},
			assert: func(t *testing.T, res *resolver, marker *bindingMarker) {
				t.Helper()

				require.Empty(t, res.secretBindings)
				require.False(t, marker.schedule())
			},
		},
		"secret set": {
			kind: bindingKindSecretSet,
			setup: func(t *testing.T, res *resolver, key bindingKey) *bindingMarker {
				t.Helper()

				bdg := newBinding[[]Secret](
					bindingKey{
						kind:      bindingKindSecret,
						source:    "source",
						selector:  "selector",
						namespace: "namespace",
						scope:     referenceScopeInternal,
					},
					zerolog.Nop(),
					mocks.NewSecretUsageMock(t),
					nil,
				)

				res.secretSetBindings[key] = &leasedBinding[[]Secret]{binding: bdg, leases: 1}

				return &bindingMarker{schedule: bdg.Schedule}
			},
			assert: func(t *testing.T, res *resolver, marker *bindingMarker) {
				t.Helper()

				require.Empty(t, res.secretSetBindings)
				require.False(t, marker.schedule())
			},
		},
		"credentials": {
			kind: bindingKindCredentials,
			setup: func(t *testing.T, res *resolver, key bindingKey) *bindingMarker {
				t.Helper()

				bdg := newBinding[Credentials](
					bindingKey{
						kind:      bindingKindSecret,
						source:    "source",
						selector:  "selector",
						namespace: "namespace",
						scope:     referenceScopeInternal,
					},
					zerolog.Nop(),
					mocks.NewSecretUsageMock(t),
					nil,
				)
				res.credentialsBindings[key] = &leasedBinding[Credentials]{binding: bdg, leases: 1}

				return &bindingMarker{schedule: bdg.Schedule}
			},
			assert: func(t *testing.T, res *resolver, marker *bindingMarker) {
				t.Helper()

				require.Empty(t, res.credentialsBindings)
				require.False(t, marker.schedule())
			},
		},
		"certificate bundle": {
			kind: bindingKindCertificateBundle,
			setup: func(t *testing.T, res *resolver, key bindingKey) *bindingMarker {
				t.Helper()

				bdg := newBinding[CertificateBundle](
					bindingKey{
						kind:      bindingKindSecret,
						source:    "source",
						selector:  "selector",
						namespace: "namespace",
						scope:     referenceScopeInternal,
					},
					zerolog.Nop(),
					mocks.NewSecretUsageMock(t),
					nil,
				)
				res.certificateBundleBindings[key] = &leasedBinding[CertificateBundle]{binding: bdg, leases: 1}

				return &bindingMarker{schedule: bdg.Schedule}
			},
			assert: func(t *testing.T, res *resolver, marker *bindingMarker) {
				t.Helper()

				require.Empty(t, res.certificateBundleBindings)
				require.False(t, marker.schedule())
			},
		},
		"unknown kind": {
			kind: bindingKind("unknown"),
			setup: func(t *testing.T, _ *resolver, _ bindingKey) *bindingMarker {
				t.Helper()

				return &bindingMarker{schedule: func() bool { return true }}
			},
			assert: func(t *testing.T, _ *resolver, marker *bindingMarker) {
				t.Helper()

				require.True(t, marker.schedule())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			res := newEmptyTestResolver(t)
			key := bindingKey{
				kind:     tc.kind,
				source:   "src",
				selector: "selector",
				scope:    referenceScopeInternal,
			}

			marker := tc.setup(t, res, key)

			res.releaseBinding(key, 1)

			tc.assert(t, res, marker)
		})
	}
}

func TestResolverMatch(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		namespaceAware bool
		event          source.Event
		keys           []bindingKey
		wantMatches    int
	}{
		"matches source wide event": {
			event: source.Event{Source: "src"},
			keys: []bindingKey{
				{
					kind:     bindingKindSecret,
					source:   "src",
					selector: "selector",
					scope:    referenceScopeInternal,
				},
				{
					kind:     bindingKindSecret,
					source:   "other",
					selector: "selector",
					scope:    referenceScopeInternal,
				},
			},
			wantMatches: 1,
		},
		"matches selector event": {
			event: source.Event{
				Source: "src",
				Selectors: []source.Selector{
					{Value: "selector"},
				},
			},
			keys: []bindingKey{
				{
					kind:     bindingKindSecret,
					source:   "src",
					selector: "selector",
					scope:    referenceScopeInternal,
				},
				{
					kind:     bindingKindSecret,
					source:   "src",
					selector: "other",
					scope:    referenceScopeInternal,
				},
			},
			wantMatches: 1,
		},
		"uses selector namespace for namespace aware source": {
			namespaceAware: true,
			event: source.Event{
				Source: "src",
				Selectors: []source.Selector{
					{Value: "selector", Namespace: "team-a"},
				},
			},
			keys: []bindingKey{
				{
					kind:      bindingKindSecret,
					source:    "src",
					selector:  "selector",
					namespace: "team-a",
					scope:     referenceScopeRule,
				},
				{
					kind:      bindingKindSecret,
					source:    "src",
					selector:  "selector",
					namespace: "team-b",
					scope:     referenceScopeRule,
				},
			},
			wantMatches: 1,
		},
		"matches across binding kinds": {
			event: source.Event{Source: "src"},
			keys: []bindingKey{
				{
					kind:     bindingKindSecret,
					source:   "src",
					selector: "selector",
					scope:    referenceScopeInternal,
				},
				{
					kind:     bindingKindSecretSet,
					source:   "src",
					selector: "selector",
					scope:    referenceScopeInternal,
				},
				{
					kind:     bindingKindCredentials,
					source:   "src",
					selector: "selector",
					scope:    referenceScopeInternal,
				},
				{
					kind:     bindingKindCertificateBundle,
					source:   "src",
					selector: "selector",
					scope:    referenceScopeInternal,
				},
			},
			wantMatches: 4,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			repository := sourcemocks.NewRepositoryMock(t)
			repository.EXPECT().AddObserver(mock.Anything).Maybe()

			src := sourcemocks.NewSourceMock(t)

			repository.EXPECT().
				Lookup(tc.event.Source).
				Return(src, nil)

			src.EXPECT().
				IsNamespaceAware().Maybe().
				Return(tc.namespaceAware)

			res := newTestResolver(t, repository)

			for _, key := range tc.keys {
				switch key.kind {
				case bindingKindSecret:
					bdg := newBinding[Secret](
						bindingKey{
							kind:      bindingKindSecret,
							source:    "source",
							selector:  "selector",
							namespace: "namespace",
							scope:     referenceScopeInternal,
						},
						zerolog.Nop(),
						mocks.NewSecretUsageMock(t),
						nil,
					)
					bdg.bindingKey = key
					res.secretBindings[key] = &leasedBinding[Secret]{binding: bdg, leases: 1}
				case bindingKindSecretSet:
					bdg := newBinding[[]Secret](
						bindingKey{
							kind:      bindingKindSecret,
							source:    "source",
							selector:  "selector",
							namespace: "namespace",
							scope:     referenceScopeInternal,
						},
						zerolog.Nop(),
						mocks.NewSecretUsageMock(t),
						nil,
					)
					bdg.bindingKey = key
					res.secretSetBindings[key] = &leasedBinding[[]Secret]{binding: bdg, leases: 1}
				case bindingKindCredentials:
					bdg := newBinding[Credentials](
						bindingKey{
							kind:      bindingKindSecret,
							source:    "source",
							selector:  "selector",
							namespace: "namespace",
							scope:     referenceScopeInternal,
						},
						zerolog.Nop(),
						mocks.NewSecretUsageMock(t),
						nil,
					)
					bdg.bindingKey = key
					res.credentialsBindings[key] = &leasedBinding[Credentials]{binding: bdg, leases: 1}
				case bindingKindCertificateBundle:
					bdg := newBinding[CertificateBundle](
						bindingKey{
							kind:      bindingKindSecret,
							source:    "source",
							selector:  "selector",
							namespace: "namespace",
							scope:     referenceScopeInternal,
						},
						zerolog.Nop(),
						mocks.NewSecretUsageMock(t),
						nil,
					)
					bdg.bindingKey = key
					res.certificateBundleBindings[key] = &leasedBinding[CertificateBundle]{binding: bdg, leases: 1}
				}
			}

			got := res.match(tc.event)

			require.Len(t, got, tc.wantMatches)
		})
	}
}

func TestResolverHandleSourceEvent(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32

	repository := sourcemocks.NewRepositoryMock(t)
	repository.EXPECT().AddObserver(mock.Anything).Maybe()

	src := sourcemocks.NewSourceMock(t)

	repository.EXPECT().
		Lookup("src").
		Return(src, nil).
		Twice()

	src.EXPECT().
		IsNamespaceAware().
		Return(false)

	src.EXPECT().
		GetSecret(mock.Anything, source.Selector{Value: "selector"}).
		Run(func(context.Context, source.Selector) {
			calls.Add(1)
		}).
		Return(types.NewStringSecret("selector", "value"), nil)

	res := newTestResolver(t, repository)
	res.Start()

	key := bindingKey{
		kind:     bindingKindSecret,
		source:   "src",
		selector: "selector",
		scope:    referenceScopeInternal,
	}

	sum := mocks.NewSecretUsageMock(t)
	sum.EXPECT().Track(mock.Anything)
	sum.EXPECT().Untrack(mock.Anything).Maybe()

	bdg := newBinding(
		bindingKey{
			kind:      bindingKindSecret,
			source:    "source",
			selector:  "selector",
			namespace: "namespace",
			scope:     referenceScopeInternal,
		},
		zerolog.Nop(),
		sum,
		func(ctx context.Context) (Secret, error) {
			return res.resolveSecret(ctx, internalRef(Reference{Source: "src", Selector: "selector"}))
		},
	)
	bdg.bindingKey = key

	res.secretBindings[key] = &leasedBinding[Secret]{
		binding: bdg,
		leases:  1,
	}

	res.handleSourceEvent(source.Event{Source: "src"})

	require.Eventually(t, func() bool {
		return calls.Load() == 1
	}, time.Second, 10*time.Millisecond)
}

func TestResolverHandleSourceEventQueuesTaskBeforeStart(t *testing.T) {
	t.Parallel()

	repository := sourcemocks.NewRepositoryMock(t)
	repository.EXPECT().AddObserver(mock.Anything).Maybe()

	src := sourcemocks.NewSourceMock(t)

	repository.EXPECT().
		Lookup("src").
		Return(src, nil)

	res := newTestResolver(t, repository)

	key := bindingKey{
		kind:     bindingKindSecret,
		source:   "src",
		selector: "selector",
		scope:    referenceScopeInternal,
	}
	bdg := newBinding[Secret](
		bindingKey{
			kind:      bindingKindSecret,
			source:    "source",
			selector:  "selector",
			namespace: "namespace",
			scope:     referenceScopeInternal,
		},
		zerolog.Nop(),
		mocks.NewSecretUsageMock(t),
		nil,
	)
	bdg.bindingKey = key

	res.secretBindings[key] = &leasedBinding[Secret]{
		binding: bdg,
		leases:  1,
	}

	res.handleSourceEvent(source.Event{Source: "src"})

	require.Len(t, res.pendingTasks, 1)
}

func TestResolverStop(t *testing.T) {
	t.Parallel()

	res := newEmptyTestResolver(t)

	appKey := bindingKey{
		kind:     bindingKindCredentials,
		source:   "src",
		selector: "credentials",
		scope:    referenceScopeInternal,
	}
	res.appScope.leases[appKey] = 1

	secretKey := bindingKey{
		kind:     bindingKindSecret,
		source:   "src",
		selector: "selector",
		scope:    referenceScopeInternal,
	}
	certKey := bindingKey{
		kind:     bindingKindCertificateBundle,
		source:   "src",
		selector: "bundle",
		scope:    referenceScopeInternal,
	}

	secretBinding := newBinding[Secret](
		bindingKey{
			kind:      bindingKindSecret,
			source:    "source",
			selector:  "selector",
			namespace: "namespace",
			scope:     referenceScopeInternal,
		},
		zerolog.Nop(),
		mocks.NewSecretUsageMock(t),
		nil,
	)
	credentialsBinding := newBinding[Credentials](
		bindingKey{
			kind:      bindingKindSecret,
			source:    "source",
			selector:  "selector",
			namespace: "namespace",
			scope:     referenceScopeInternal,
		},
		zerolog.Nop(),
		mocks.NewSecretUsageMock(t),
		nil,
	)
	certificateBundleBinding := newBinding[CertificateBundle](
		bindingKey{
			kind:      bindingKindSecret,
			source:    "source",
			selector:  "selector",
			namespace: "namespace",
			scope:     referenceScopeInternal,
		},
		zerolog.Nop(),
		mocks.NewSecretUsageMock(t),
		nil,
	)

	res.secretBindings[secretKey] = &leasedBinding[Secret]{
		binding: secretBinding,
		leases:  1,
	}
	res.credentialsBindings[appKey] = &leasedBinding[Credentials]{
		binding: credentialsBinding,
		leases:  1,
	}
	res.certificateBundleBindings[certKey] = &leasedBinding[CertificateBundle]{
		binding: certificateBundleBinding,
		leases:  1,
	}

	res.pendingTasks = append(
		res.pendingTasks,
		newBinding(
			bindingKey{
				kind:      bindingKindSecret,
				source:    "source",
				selector:  "selector",
				namespace: "namespace",
				scope:     referenceScopeInternal,
			},
			zerolog.Nop(),
			mocks.NewSecretUsageMock(t),
			func(context.Context) (string, error) {
				return "ignored", nil
			},
		),
	)

	res.Stop()

	require.Equal(t, resolverStateStopped, res.state)
	require.Empty(t, res.pendingTasks)
	require.Empty(t, res.secretBindings)
	require.Empty(t, res.credentialsBindings)
	require.Empty(t, res.certificateBundleBindings)
	require.False(t, secretBinding.Schedule())
	require.False(t, credentialsBinding.Schedule())
	require.False(t, certificateBundleBinding.Schedule())
}

func TestSelectorFor(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		namespaceAware bool
		want           source.Selector
	}{
		"sets namespace for namespace aware source": {
			namespaceAware: true,
			want: source.Selector{
				Value:     "selector",
				Namespace: "team-a",
			},
		},
		"omits namespace for non namespace aware source": {
			namespaceAware: false,
			want: source.Selector{
				Value: "selector",
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			src := sourcemocks.NewSourceMock(t)
			src.EXPECT().
				IsNamespaceAware().
				Return(tc.namespaceAware)

			got := selectorFor(
				src,
				scopedReference{
					Reference: Reference{Source: "src", Selector: "selector"},
					namespace: "team-a",
					scope:     referenceScopeRule,
				},
			)

			require.Equal(t, tc.want, got)
		})
	}
}

func newTestResolver(
	t *testing.T,
	repository source.Repository,
) *resolver {
	t.Helper()

	res, err := newResolver(zerolog.Nop(), repository, noopmetric.Meter{})
	require.NoError(t, err)

	t.Cleanup(func() {
		if res.state != resolverStateStopped {
			res.Stop()
		}
	})

	return res
}

func newEmptyTestResolver(t *testing.T) *resolver {
	t.Helper()

	executor, err := task.NewExecutor(bindingRefreshTaskWorkers)
	require.NoError(t, err)

	res := &resolver{
		logger:                    zerolog.Nop(),
		executor:                  executor,
		secretBindings:            make(map[bindingKey]*leasedBinding[Secret]),
		secretSetBindings:         make(map[bindingKey]*leasedBinding[[]Secret]),
		credentialsBindings:       make(map[bindingKey]*leasedBinding[Credentials]),
		certificateBundleBindings: make(map[bindingKey]*leasedBinding[CertificateBundle]),
	}
	res.appScope = newScope(res)

	t.Cleanup(func() {
		if res.state != resolverStateStopped {
			res.Stop()
		}
	})

	return res
}

type bindingMarker struct {
	schedule func() bool
}

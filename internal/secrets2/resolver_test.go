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

package secrets2

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/secrets2/source"
	sourcemocks "github.com/dadrus/heimdall/internal/secrets2/source/mocks"
	"github.com/dadrus/heimdall/internal/secrets2/types"
	"github.com/dadrus/heimdall/internal/x/task"
)

func TestApplyResolveOptions(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		opts []ResolveOption
		want ResolveMode
	}{
		"defaults to eager": {
			want: ResolveEager,
		},
		"applies lazy": {
			opts: []ResolveOption{Lazy()},
			want: ResolveLazy,
		},
		"applies eager last": {
			opts: []ResolveOption{Lazy(), Eager()},
			want: ResolveEager,
		},
		"ignores nil options": {
			opts: []ResolveOption{nil, Lazy()},
			want: ResolveLazy,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			got := applyResolveOptions(tc.opts...)

			require.Equal(t, tc.want, got.mode)
		})
	}
}

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

	res, err := newResolver(zerolog.Nop(), repository)

	require.NoError(t, err)
	require.NotNil(t, res)
	t.Cleanup(res.Stop)

	require.Same(t, repository, res.sources)
	require.NotNil(t, res.executor)
	require.NotNil(t, res.appScope)
	require.NotNil(t, res.ruleScopes)
	require.NotNil(t, res.secretBindings)
	require.NotNil(t, res.secretSetBindings)
	require.NotNil(t, res.credentialsBindings)
	require.NotNil(t, res.certificateBundleBindings)
}

func TestResolverScopes(t *testing.T) {
	t.Parallel()

	repository := sourcemocks.NewRepositoryMock(t)
	repository.EXPECT().AddObserver(mock.Anything).Once()

	res, err := newResolver(zerolog.Nop(), repository)
	require.NoError(t, err)
	t.Cleanup(res.Stop)

	appScope := res.Resolver()
	require.NotNil(t, appScope)
	require.Same(t, res.appScope, appScope)

	ruleScopeA := res.ScopedResolver("team-a", WithNamespace("a"))
	ruleScopeAAgain := res.ScopedResolver("team-a", WithNamespace("b"))
	ruleScopeB := res.ScopedResolver("team-b")

	require.Same(t, ruleScopeA, ruleScopeAAgain)
	require.NotSame(t, ruleScopeA, ruleScopeB)

	ruleScopeA.Release()

	ruleScopeANew := res.ScopedResolver("team-a", WithNamespace("a"))
	require.NotSame(t, ruleScopeA, ruleScopeANew)
}

func TestResolverResolveSecret(t *testing.T) {
	t.Parallel()

	secret := types.NewStringSecret("selector", "value")

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock)
		assert func(t *testing.T, got Secret, err error)
	}{
		"resolves secret from non namespace aware source": {
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
		"resolves secret from namespace aware source with empty namespace": {
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock) {
				t.Helper()

				repository.EXPECT().
					Lookup("src").
					Return(src, nil)

				src.EXPECT().
					IsNamespaceAware().
					Return(true)

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
		"returns lookup error": {
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

			got, err := res.ResolveSecret(
				context.Background(),
				Reference{Source: "src", Selector: "selector"},
			)

			tc.assert(t, got, err)
		})
	}
}

func TestResolverResolveCredentials(t *testing.T) {
	t.Parallel()

	credentials := types.NewCredentials("selector", map[string]any{"client_id": "heimdall"})

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock)
		assert func(t *testing.T, got Credentials, err error)
	}{
		"resolves credentials from non namespace aware source": {
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
		"resolves credentials from namespace aware source with empty namespace": {
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock) {
				t.Helper()

				repository.EXPECT().
					Lookup("src").
					Return(src, nil)

				src.EXPECT().
					IsNamespaceAware().
					Return(true)

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
		"returns lookup error": {
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

			got, err := res.ResolveCredentials(
				context.Background(),
				Reference{Source: "src", Selector: "selector"},
			)

			tc.assert(t, got, err)
		})
	}
}

func TestResolverResolveCertificateBundle(t *testing.T) {
	t.Parallel()

	bundle := types.NewCertificateBundle("selector", nil)

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock)
		assert func(t *testing.T, got CertificateBundle, err error)
	}{
		"resolves certificate bundle from non namespace aware source": {
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
		"resolves certificate bundle from namespace aware source with empty namespace": {
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock) {
				t.Helper()

				repository.EXPECT().
					Lookup("src").
					Return(src, nil)

				src.EXPECT().
					IsNamespaceAware().
					Return(true)

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
		"returns lookup error": {
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

			got, err := res.ResolveCertificateBundle(
				context.Background(),
				Reference{Source: "src", Selector: "selector"},
			)

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

			got, err := res.resolveSecretSet(context.Background(), tc.reference)

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

			got, err := res.resolveCredentials(context.Background(), tc.reference)

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

			got, err := res.resolveCertificateBundle(context.Background(), tc.reference)

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
		call func(ctx context.Context, res *resolver, ref scopedReference) (any, bindingKey, error)
	}{
		"secret binding": {
			call: func(ctx context.Context, res *resolver, ref scopedReference) (any, bindingKey, error) {
				return res.secretBinding(ctx, ref)
			},
		},
		"secret set binding": {
			call: func(ctx context.Context, res *resolver, ref scopedReference) (any, bindingKey, error) {
				return res.secretSetBinding(ctx, ref)
			},
		},
		"credentials binding": {
			call: func(ctx context.Context, res *resolver, ref scopedReference) (any, bindingKey, error) {
				return res.credentialsBinding(ctx, ref)
			},
		},
		"certificate bundle binding": {
			call: func(ctx context.Context, res *resolver, ref scopedReference) (any, bindingKey, error) {
				return res.certificateBundleBinding(ctx, ref)
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
				context.Background(),
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
		mode   ResolveMode
		setup  func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock, calls *atomic.Int32)
		assert func(t *testing.T, res *resolver, bdg *binding[Secret], key bindingKey, calls *atomic.Int32, err error)
	}{
		"creates eager binding and resolves immediately": {
			mode: ResolveEager,
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock, calls *atomic.Int32) {
				t.Helper()

				repository.EXPECT().Lookup("src").Return(src, nil)
				src.EXPECT().IsNamespaceAware().Return(false)

				repository.EXPECT().Lookup("src").Return(src, nil)
				src.EXPECT().IsNamespaceAware().Return(false)
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
				require.Equal(t, bindingKindSecret, key.kind)
				require.EqualValues(t, 1, calls.Load())
				require.Len(t, res.secretBindings, 1)
				require.Equal(t, 1, res.secretBindings[key].leases)
			},
		},
		"creates lazy binding and resolves asynchronously": {
			mode: ResolveLazy,
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock, calls *atomic.Int32) {
				t.Helper()

				repository.EXPECT().Lookup("src").Return(src, nil)
				src.EXPECT().IsNamespaceAware().Return(false)

				repository.EXPECT().Lookup("src").Return(src, nil)
				src.EXPECT().IsNamespaceAware().Return(false)
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
				require.Len(t, res.secretBindings, 1)
				require.Equal(t, 1, res.secretBindings[key].leases)

				require.Eventually(t, func() bool {
					return calls.Load() == 1
				}, time.Second, 10*time.Millisecond)
			},
		},
		"returns eager resolve error and releases binding": {
			mode: ResolveEager,
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock, calls *atomic.Int32) {
				t.Helper()

				repository.EXPECT().Lookup("src").Return(src, nil)
				src.EXPECT().IsNamespaceAware().Return(false)

				repository.EXPECT().Lookup("src").Return(src, nil)
				src.EXPECT().IsNamespaceAware().Return(false)
				src.EXPECT().
					GetSecret(mock.Anything, source.Selector{Value: "selector"}).
					Run(func(context.Context, source.Selector) {
						calls.Add(1)
					}).
					Return(nil, assert.AnError)
			},
			assert: func(t *testing.T, res *resolver, bdg *binding[Secret], _ bindingKey, calls *atomic.Int32, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)
				require.Nil(t, bdg)
				require.EqualValues(t, 1, calls.Load())
				require.Empty(t, res.secretBindings)
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

			bdg, key, err := res.secretBinding(
				context.Background(),
				internalRef(Reference{Source: "src", Selector: "selector"}),
				func(opts *resolveOptions) {
					opts.mode = tc.mode
				},
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
		mode   ResolveMode
		setup  func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock, calls *atomic.Int32)
		assert func(t *testing.T, res *resolver, bdg *binding[[]Secret], key bindingKey, calls *atomic.Int32, err error)
	}{
		"creates eager binding and resolves immediately": {
			mode: ResolveEager,
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock, calls *atomic.Int32) {
				t.Helper()

				repository.EXPECT().Lookup("src").Return(src, nil)
				src.EXPECT().IsNamespaceAware().Return(false)

				repository.EXPECT().Lookup("src").Return(src, nil)
				src.EXPECT().IsNamespaceAware().Return(false)
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
				require.Equal(t, bindingKindSecretSet, key.kind)
				require.EqualValues(t, 1, calls.Load())
				require.Len(t, res.secretSetBindings, 1)
				require.Equal(t, 1, res.secretSetBindings[key].leases)
			},
		},
		"creates lazy binding and resolves asynchronously": {
			mode: ResolveLazy,
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock, calls *atomic.Int32) {
				t.Helper()

				repository.EXPECT().Lookup("src").Return(src, nil)
				src.EXPECT().IsNamespaceAware().Return(false)

				repository.EXPECT().Lookup("src").Return(src, nil)
				src.EXPECT().IsNamespaceAware().Return(false)
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
				require.Len(t, res.secretSetBindings, 1)
				require.Equal(t, 1, res.secretSetBindings[key].leases)

				require.Eventually(t, func() bool {
					return calls.Load() == 1
				}, time.Second, 10*time.Millisecond)
			},
		},
		"returns eager resolve error and releases binding": {
			mode: ResolveEager,
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock, calls *atomic.Int32) {
				t.Helper()

				repository.EXPECT().Lookup("src").Return(src, nil)
				src.EXPECT().IsNamespaceAware().Return(false)

				repository.EXPECT().Lookup("src").Return(src, nil)
				src.EXPECT().IsNamespaceAware().Return(false)
				src.EXPECT().
					GetSecretSet(mock.Anything, source.Selector{Value: "selector"}).
					Run(func(context.Context, source.Selector) {
						calls.Add(1)
					}).
					Return(nil, assert.AnError)
			},
			assert: func(t *testing.T, res *resolver, bdg *binding[[]Secret], _ bindingKey, calls *atomic.Int32, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)
				require.Nil(t, bdg)
				require.EqualValues(t, 1, calls.Load())
				require.Empty(t, res.secretSetBindings)
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

			bdg, key, err := res.secretSetBinding(
				context.Background(),
				internalRef(Reference{Source: "src", Selector: "selector"}),
				func(opts *resolveOptions) {
					opts.mode = tc.mode
				},
			)

			tc.assert(t, res, bdg, key, &calls, err)
		})
	}
}

func TestResolverCredentialsBinding(t *testing.T) {
	t.Parallel()

	credentials := types.NewCredentials("selector", map[string]any{"client_id": "heimdall"})

	for uc, tc := range map[string]struct {
		mode   ResolveMode
		setup  func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock, calls *atomic.Int32)
		assert func(t *testing.T, res *resolver, bdg *binding[Credentials], key bindingKey, calls *atomic.Int32, err error)
	}{
		"creates eager binding and resolves immediately": {
			mode: ResolveEager,
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock, calls *atomic.Int32) {
				t.Helper()

				repository.EXPECT().Lookup("src").Return(src, nil)
				src.EXPECT().IsNamespaceAware().Return(false)

				repository.EXPECT().Lookup("src").Return(src, nil)
				src.EXPECT().IsNamespaceAware().Return(false)
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
				require.Equal(t, bindingKindCredentials, key.kind)
				require.EqualValues(t, 1, calls.Load())
				require.Len(t, res.credentialsBindings, 1)
				require.Equal(t, 1, res.credentialsBindings[key].leases)
			},
		},
		"creates lazy binding and resolves asynchronously": {
			mode: ResolveLazy,
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock, calls *atomic.Int32) {
				t.Helper()

				repository.EXPECT().Lookup("src").Return(src, nil)
				src.EXPECT().IsNamespaceAware().Return(false)

				repository.EXPECT().Lookup("src").Return(src, nil)
				src.EXPECT().IsNamespaceAware().Return(false)
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
				require.Len(t, res.credentialsBindings, 1)
				require.Equal(t, 1, res.credentialsBindings[key].leases)

				require.Eventually(t, func() bool {
					return calls.Load() == 1
				}, time.Second, 10*time.Millisecond)
			},
		},
		"returns eager resolve error and releases binding": {
			mode: ResolveEager,
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock, calls *atomic.Int32) {
				t.Helper()

				repository.EXPECT().Lookup("src").Return(src, nil)
				src.EXPECT().IsNamespaceAware().Return(false)

				repository.EXPECT().Lookup("src").Return(src, nil)
				src.EXPECT().IsNamespaceAware().Return(false)
				src.EXPECT().
					GetCredentials(mock.Anything, source.Selector{Value: "selector"}).
					Run(func(context.Context, source.Selector) {
						calls.Add(1)
					}).
					Return(nil, assert.AnError)
			},
			assert: func(t *testing.T, res *resolver, bdg *binding[Credentials], _ bindingKey, calls *atomic.Int32, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)
				require.Nil(t, bdg)
				require.EqualValues(t, 1, calls.Load())
				require.Empty(t, res.credentialsBindings)
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

			bdg, key, err := res.credentialsBinding(
				context.Background(),
				internalRef(Reference{Source: "src", Selector: "selector"}),
				func(opts *resolveOptions) {
					opts.mode = tc.mode
				},
			)

			tc.assert(t, res, bdg, key, &calls, err)
		})
	}
}

func TestResolverCertificateBundleBinding(t *testing.T) {
	t.Parallel()

	bundle := types.NewCertificateBundle("selector", nil)

	for uc, tc := range map[string]struct {
		mode   ResolveMode
		setup  func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock, calls *atomic.Int32)
		assert func(t *testing.T, res *resolver, bdg *binding[CertificateBundle], key bindingKey, calls *atomic.Int32, err error)
	}{
		"creates eager binding and resolves immediately": {
			mode: ResolveEager,
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock, calls *atomic.Int32) {
				t.Helper()

				repository.EXPECT().Lookup("src").Return(src, nil)
				src.EXPECT().IsNamespaceAware().Return(false)

				repository.EXPECT().Lookup("src").Return(src, nil)
				src.EXPECT().IsNamespaceAware().Return(false)
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
				require.Equal(t, bindingKindCertificateBundle, key.kind)
				require.EqualValues(t, 1, calls.Load())
				require.Len(t, res.certificateBundleBindings, 1)
				require.Equal(t, 1, res.certificateBundleBindings[key].leases)
			},
		},
		"creates lazy binding and resolves asynchronously": {
			mode: ResolveLazy,
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock, calls *atomic.Int32) {
				t.Helper()

				repository.EXPECT().Lookup("src").Return(src, nil)
				src.EXPECT().IsNamespaceAware().Return(false)

				repository.EXPECT().Lookup("src").Return(src, nil)
				src.EXPECT().IsNamespaceAware().Return(false)
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
				require.Len(t, res.certificateBundleBindings, 1)
				require.Equal(t, 1, res.certificateBundleBindings[key].leases)

				require.Eventually(t, func() bool {
					return calls.Load() == 1
				}, time.Second, 10*time.Millisecond)
			},
		},
		"returns eager resolve error and releases binding": {
			mode: ResolveEager,
			setup: func(t *testing.T, repository *sourcemocks.RepositoryMock, src *sourcemocks.SourceMock, calls *atomic.Int32) {
				t.Helper()

				repository.EXPECT().Lookup("src").Return(src, nil)
				src.EXPECT().IsNamespaceAware().Return(false)

				repository.EXPECT().Lookup("src").Return(src, nil)
				src.EXPECT().IsNamespaceAware().Return(false)
				src.EXPECT().
					GetCertificateBundle(mock.Anything, source.Selector{Value: "selector"}).
					Run(func(context.Context, source.Selector) {
						calls.Add(1)
					}).
					Return(nil, assert.AnError)
			},
			assert: func(t *testing.T, res *resolver, bdg *binding[CertificateBundle], _ bindingKey, calls *atomic.Int32, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)
				require.Nil(t, bdg)
				require.EqualValues(t, 1, calls.Load())
				require.Empty(t, res.certificateBundleBindings)
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

			bdg, key, err := res.certificateBundleBinding(
				context.Background(),
				internalRef(Reference{Source: "src", Selector: "selector"}),
				func(opts *resolveOptions) {
					opts.mode = tc.mode
				},
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

	repository.EXPECT().Lookup("src").Return(src, nil)
	src.EXPECT().IsNamespaceAware().Return(false)

	repository.EXPECT().Lookup("src").Return(src, nil)
	src.EXPECT().IsNamespaceAware().Return(false)
	src.EXPECT().
		GetSecret(mock.Anything, source.Selector{Value: "selector"}).
		Return(types.NewStringSecret("selector", "value"), nil)

	repository.EXPECT().Lookup("src").Return(src, nil)
	src.EXPECT().IsNamespaceAware().Return(false)

	res := newTestResolver(t, repository)

	first, key, err := res.secretBinding(
		context.Background(),
		internalRef(Reference{Source: "src", Selector: "selector"}),
		Eager(),
	)
	require.NoError(t, err)

	second, secondKey, err := res.secretBinding(
		context.Background(),
		internalRef(Reference{Source: "src", Selector: "selector"}),
		Lazy(),
	)
	require.NoError(t, err)

	require.Same(t, first, second)
	require.Equal(t, key, secondKey)
	require.Equal(t, 2, res.secretBindings[key].leases)
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

			key := testResolverBindingKey(bindingKindSecret)
			bdg := newTestBinding[Secret](t, nil)

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

				bdg := newTestBinding[Secret](t, nil)
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

				bdg := newTestBinding[[]Secret](t, nil)
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

				bdg := newTestBinding[Credentials](t, nil)
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

				bdg := newTestBinding[CertificateBundle](t, nil)
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
			key := testResolverBindingKey(tc.kind)

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
				testResolverBindingKey(bindingKindSecret),
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
				testResolverBindingKey(bindingKindSecret),
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
				testResolverBindingKey(bindingKindSecret),
				testResolverBindingKey(bindingKindSecretSet),
				testResolverBindingKey(bindingKindCredentials),
				testResolverBindingKey(bindingKindCertificateBundle),
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
				IsNamespaceAware().
				Return(tc.namespaceAware)

			res := newTestResolver(t, repository)

			for _, key := range tc.keys {
				switch key.kind {
				case bindingKindSecret:
					bdg := newTestBinding[Secret](t, nil)
					bdg.bindingKey = key
					res.secretBindings[key] = &leasedBinding[Secret]{binding: bdg, leases: 1}
				case bindingKindSecretSet:
					bdg := newTestBinding[[]Secret](t, nil)
					bdg.bindingKey = key
					res.secretSetBindings[key] = &leasedBinding[[]Secret]{binding: bdg, leases: 1}
				case bindingKindCredentials:
					bdg := newTestBinding[Credentials](t, nil)
					bdg.bindingKey = key
					res.credentialsBindings[key] = &leasedBinding[Credentials]{binding: bdg, leases: 1}
				case bindingKindCertificateBundle:
					bdg := newTestBinding[CertificateBundle](t, nil)
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
		Return(src, nil)

	src.EXPECT().
		IsNamespaceAware().
		Return(false)

	res := newTestResolver(t, repository)

	key := testResolverBindingKey(bindingKindSecret)
	bdg := newTestBinding[Secret](t, func(context.Context) (Secret, error) {
		calls.Add(1)

		return types.NewStringSecret("selector", "value"), nil
	})
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

func TestResolverReleaseScope(t *testing.T) {
	t.Parallel()

	res := newEmptyTestResolver(t)

	scopeA := newScope(res,
		withID("a"),
		withReleaser(res),
		withNamespace("team-a"),
	)
	scopeB := newScope(res,
		withID("b"),
		withReleaser(res),
		withNamespace("team-b"),
	)

	res.ruleScopes["a"] = scopeA
	res.ruleScopes["b"] = scopeB

	res.releaseScope("a", scopeB)

	require.Same(t, scopeA, res.ruleScopes["a"])
	require.Same(t, scopeB, res.ruleScopes["b"])

	res.releaseScope("a", scopeA)

	require.NotContains(t, res.ruleScopes, "a")
	require.Same(t, scopeB, res.ruleScopes["b"])
}

func TestResolverStop(t *testing.T) {
	t.Parallel()

	res := newEmptyTestResolver(t)

	ruleScope := newScope(res,
		withID("a"),
		withReleaser(res),
		withNamespace("team-a"),
	)
	ruleKey := testResolverBindingKey(bindingKindSecret)
	ruleScope.leases[ruleKey] = 1
	res.ruleScopes["a"] = ruleScope

	appKey := bindingKey{
		kind:     bindingKindCredentials,
		source:   "src",
		selector: "credentials",
		scope:    referenceScopeInternal,
	}
	res.appScope.leases[appKey] = 1

	certKey := bindingKey{
		kind:     bindingKindCertificateBundle,
		source:   "src",
		selector: "bundle",
		scope:    referenceScopeInternal,
	}

	secretBinding := newTestBinding[Secret](t, nil)
	credentialsBinding := newTestBinding[Credentials](t, nil)
	certificateBundleBinding := newTestBinding[CertificateBundle](t, nil)

	res.secretBindings[ruleKey] = &leasedBinding[Secret]{
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

	res.Stop()

	require.Empty(t, res.ruleScopes)
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

	res, err := newResolver(zerolog.Nop(), repository)
	require.NoError(t, err)

	t.Cleanup(res.Stop)

	return res
}

func newEmptyTestResolver(t *testing.T) *resolver {
	t.Helper()

	executor, err := task.NewExecutor(bindingRefreshTaskWorkers)
	require.NoError(t, err)

	res := &resolver{
		logger:                    zerolog.Nop(),
		executor:                  executor,
		ruleScopes:                make(map[string]*scope),
		secretBindings:            make(map[bindingKey]*leasedBinding[Secret]),
		secretSetBindings:         make(map[bindingKey]*leasedBinding[[]Secret]),
		credentialsBindings:       make(map[bindingKey]*leasedBinding[Credentials]),
		certificateBundleBindings: make(map[bindingKey]*leasedBinding[CertificateBundle]),
	}
	res.appScope = newScope(res)

	t.Cleanup(res.Stop)

	return res
}

func testResolverBindingKey(kind bindingKind) bindingKey {
	return bindingKey{
		kind:     kind,
		source:   "src",
		selector: "selector",
		scope:    referenceScopeInternal,
	}
}

type bindingMarker struct {
	schedule func() bool
}

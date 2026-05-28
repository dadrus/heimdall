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
	"sync"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/secrets/metrics/mocks"
	"github.com/dadrus/heimdall/internal/secrets/types"
)

func TestNewScope(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, bindings *BindingProviderMock) *scope
		assert func(t *testing.T, scp *scope)
	}{
		"creates internal scope by default": {
			setup: func(t *testing.T, bindings *BindingProviderMock) *scope {
				t.Helper()

				return newScope(bindings)
			},
			assert: func(t *testing.T, scp *scope) {
				t.Helper()

				ref := scp.refFactory(Reference{Source: "src", Selector: "selector"})

				require.Equal(t, "src", ref.Source)
				require.Equal(t, "selector", ref.Selector)
				require.Empty(t, ref.namespace)
				require.Equal(t, referenceScopeInternal, ref.scope)
				require.Empty(t, scp.id)
				require.Empty(t, scp.namespace)
				require.NotNil(t, scp.leases)
			},
		},
		"creates scoped resolver with id and namespace": {
			setup: func(t *testing.T, bindings *BindingProviderMock) *scope {
				t.Helper()

				return newScope(
					bindings,
					withID("foo"),
					withNamespace("team-a"),
				)
			},
			assert: func(t *testing.T, scp *scope) {
				t.Helper()

				ref := scp.refFactory(Reference{Source: "src", Selector: "selector"})

				require.Equal(t, "src", ref.Source)
				require.Equal(t, "selector", ref.Selector)
				require.Equal(t, "team-a", ref.namespace)
				require.Equal(t, referenceScopeRule, ref.scope)
				require.Equal(t, "foo", scp.id)
				require.Equal(t, "team-a", scp.namespace)
				require.NotNil(t, scp.leases)
			},
		},
		"ignores nil options": {
			setup: func(t *testing.T, bindings *BindingProviderMock) *scope {
				t.Helper()

				return newScope(bindings, nil)
			},
			assert: func(t *testing.T, scp *scope) {
				t.Helper()

				ref := scp.refFactory(Reference{Source: "src", Selector: "selector"})

				require.Equal(t, referenceScopeInternal, ref.scope)
				require.Empty(t, scp.id)
				require.Empty(t, scp.namespace)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			bindings := NewBindingProviderMock(t)

			scp := tc.setup(t, bindings)

			tc.assert(t, scp)
		})
	}
}

func TestScopeSecret(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, bindings *BindingProviderMock) *scope
		assert func(t *testing.T, handle SecretHandle, scp *scope, err error)
	}{
		"returns secret handle and tracks lease": {
			setup: func(t *testing.T, bindings *BindingProviderMock) *scope {
				t.Helper()

				key := testScopeBindingKey(bindingKindSecret)
				secret := types.NewStringSecret("selector", "value")

				sum := mocks.NewSecretUsageMock(t)
				sum.EXPECT().Track(secret)

				bdg := newBinding(
					key,
					zerolog.Nop(),
					sum,
					func(context.Context) (Secret, error) { return secret, nil },
				)
				bdg.publish(t.Context(), secret)

				bindings.EXPECT().
					secretBinding(
						scopedReference{
							Reference: Reference{Source: "src", Selector: "selector"},
							scope:     referenceScopeInternal,
						},
					).
					Return(bdg, key, nil)

				return newScope(bindings)
			},
			assert: func(t *testing.T, handle SecretHandle, scp *scope, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, handle)

				secret, ok := handle.Get()
				require.True(t, ok)
				require.Equal(t, "selector", secret.Selector())

				require.Equal(t, map[bindingKey]int{
					testScopeBindingKey(bindingKindSecret): 1,
				}, scp.leases)
				require.Len(t, scp.readiness, 1)
			},
		},
		"returns binding error": {
			setup: func(t *testing.T, bindings *BindingProviderMock) *scope {
				t.Helper()

				bindings.EXPECT().
					secretBinding(
						scopedReference{
							Reference: Reference{Source: "src", Selector: "selector"},
							scope:     referenceScopeInternal,
						},
					).
					Return(nil, bindingKey{}, assert.AnError)

				return newScope(bindings)
			},
			assert: func(t *testing.T, handle SecretHandle, scp *scope, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)
				require.Nil(t, handle)
				require.Empty(t, scp.leases)
				require.Empty(t, scp.readiness)
			},
		},
		"releases binding if scope is already closed": {
			setup: func(t *testing.T, bindings *BindingProviderMock) *scope {
				t.Helper()

				key := testScopeBindingKey(bindingKindSecret)
				secret := types.NewStringSecret("selector", "value")

				sum := mocks.NewSecretUsageMock(t)
				sum.EXPECT().Track(secret)

				bdg := newBinding(
					key,
					zerolog.Nop(),
					sum,
					func(context.Context) (Secret, error) { return secret, nil },
				)
				bdg.publish(t.Context(), secret)

				bindings.EXPECT().
					secretBinding(
						scopedReference{
							Reference: Reference{Source: "src", Selector: "selector"},
							scope:     referenceScopeInternal,
						},
					).
					Return(bdg, key, nil)

				bindings.EXPECT().
					releaseBinding(key, 1)

				scp := newScope(bindings)
				scp.closed = true

				return scp
			},
			assert: func(t *testing.T, handle SecretHandle, _ *scope, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrResolverScopeClosed)
				require.Nil(t, handle)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			bindings := NewBindingProviderMock(t)
			scp := tc.setup(t, bindings)

			handle, err := scp.Secret(
				Reference{Source: "src", Selector: "selector"},
			)

			tc.assert(t, handle, scp, err)
		})
	}
}

func TestScopeSecretSet(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, bindings *BindingProviderMock) *scope
		assert func(t *testing.T, handle SecretSetHandle, scp *scope, err error)
	}{
		"returns secret set handle and tracks lease": {
			setup: func(t *testing.T, bindings *BindingProviderMock) *scope {
				t.Helper()

				key := testScopeBindingKey(bindingKindSecretSet)
				secrets := []Secret{
					types.NewStringSecret("selector/a", "a"),
					types.NewStringSecret("selector/b", "b"),
				}

				bdg := newBinding(
					key,
					zerolog.Nop(),
					mocks.NewSecretUsageMock(t),
					func(context.Context) ([]Secret, error) { return secrets, nil },
				)
				bdg.publish(t.Context(), secrets)

				bindings.EXPECT().
					secretSetBinding(
						scopedReference{
							Reference: Reference{Source: "src", Selector: "selector"},
							scope:     referenceScopeInternal,
						},
					).
					Return(bdg, key, nil)

				return newScope(bindings)
			},
			assert: func(t *testing.T, handle SecretSetHandle, scp *scope, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, handle)

				secrets, ok := handle.Get()
				require.True(t, ok)
				require.Len(t, secrets, 2)

				require.Equal(t, map[bindingKey]int{
					testScopeBindingKey(bindingKindSecretSet): 1,
				}, scp.leases)
				require.Len(t, scp.readiness, 1)
			},
		},
		"returns binding error": {
			setup: func(t *testing.T, bindings *BindingProviderMock) *scope {
				t.Helper()

				bindings.EXPECT().
					secretSetBinding(
						scopedReference{
							Reference: Reference{Source: "src", Selector: "selector"},
							scope:     referenceScopeInternal,
						},
					).
					Return(nil, bindingKey{}, assert.AnError)

				return newScope(bindings)
			},
			assert: func(t *testing.T, handle SecretSetHandle, scp *scope, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)
				require.Nil(t, handle)
				require.Empty(t, scp.leases)
				require.Empty(t, scp.readiness)
			},
		},
		"releases binding if scope is already closed": {
			setup: func(t *testing.T, bindings *BindingProviderMock) *scope {
				t.Helper()

				key := testScopeBindingKey(bindingKindSecretSet)
				secrets := []Secret{types.NewStringSecret("selector/a", "a")}

				bdg := newBinding(
					key,
					zerolog.Nop(),
					mocks.NewSecretUsageMock(t),
					func(context.Context) ([]Secret, error) { return secrets, nil },
				)
				bdg.publish(t.Context(), secrets)

				bindings.EXPECT().
					secretSetBinding(
						scopedReference{
							Reference: Reference{Source: "src", Selector: "selector"},
							scope:     referenceScopeInternal,
						},
					).
					Return(bdg, key, nil)

				bindings.EXPECT().
					releaseBinding(key, 1)

				scp := newScope(bindings)
				scp.closed = true

				return scp
			},
			assert: func(t *testing.T, handle SecretSetHandle, _ *scope, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrResolverScopeClosed)
				require.Nil(t, handle)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			bindings := NewBindingProviderMock(t)
			scp := tc.setup(t, bindings)

			handle, err := scp.SecretSet(
				Reference{Source: "src", Selector: "selector"},
			)

			tc.assert(t, handle, scp, err)
		})
	}
}

func TestScopeCredentials(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, bindings *BindingProviderMock) *scope
		assert func(t *testing.T, handle CredentialsHandle, scp *scope, err error)
	}{
		"returns credentials handle and tracks lease": {
			setup: func(t *testing.T, bindings *BindingProviderMock) *scope {
				t.Helper()

				key := testScopeBindingKey(bindingKindCredentials)
				creds := types.NewCredentials("selector", map[string]any{"client_id": "heimdall"})

				sum := mocks.NewSecretUsageMock(t)
				sum.EXPECT().Track(creds)

				bdg := newBinding(
					key,
					zerolog.Nop(),
					sum,
					func(context.Context) (Credentials, error) { return creds, nil },
				)
				bdg.publish(t.Context(), creds)

				bindings.EXPECT().
					credentialsBinding(
						scopedReference{
							Reference: Reference{Source: "src", Selector: "selector"},
							scope:     referenceScopeInternal,
						},
					).
					Return(bdg, key, nil)

				return newScope(bindings)
			},
			assert: func(t *testing.T, handle CredentialsHandle, scp *scope, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, handle)

				creds, ok := handle.Get()
				require.True(t, ok)
				require.Equal(t, "selector", creds.Selector())

				require.Equal(t, map[bindingKey]int{
					testScopeBindingKey(bindingKindCredentials): 1,
				}, scp.leases)
				require.Len(t, scp.readiness, 1)
			},
		},
		"returns binding error": {
			setup: func(t *testing.T, bindings *BindingProviderMock) *scope {
				t.Helper()

				bindings.EXPECT().
					credentialsBinding(
						scopedReference{
							Reference: Reference{Source: "src", Selector: "selector"},
							scope:     referenceScopeInternal,
						},
					).
					Return(nil, bindingKey{}, assert.AnError)

				return newScope(bindings)
			},
			assert: func(t *testing.T, handle CredentialsHandle, scp *scope, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)
				require.Nil(t, handle)
				require.Empty(t, scp.leases)
				require.Empty(t, scp.readiness)
			},
		},
		"releases binding if scope is already closed": {
			setup: func(t *testing.T, bindings *BindingProviderMock) *scope {
				t.Helper()

				key := testScopeBindingKey(bindingKindCredentials)
				creds := types.NewCredentials("selector", map[string]any{"client_id": "heimdall"})

				sum := mocks.NewSecretUsageMock(t)
				sum.EXPECT().Track(creds)

				bdg := newBinding(
					key,
					zerolog.Nop(),
					sum,
					func(context.Context) (Credentials, error) { return creds, nil },
				)
				bdg.publish(t.Context(), creds)

				bindings.EXPECT().
					credentialsBinding(
						scopedReference{
							Reference: Reference{Source: "src", Selector: "selector"},
							scope:     referenceScopeInternal,
						},
					).
					Return(bdg, key, nil)

				bindings.EXPECT().
					releaseBinding(key, 1)

				scp := newScope(bindings)
				scp.closed = true

				return scp
			},
			assert: func(t *testing.T, handle CredentialsHandle, _ *scope, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrResolverScopeClosed)
				require.Nil(t, handle)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			bindings := NewBindingProviderMock(t)
			scp := tc.setup(t, bindings)

			handle, err := scp.Credentials(
				Reference{Source: "src", Selector: "selector"},
			)

			tc.assert(t, handle, scp, err)
		})
	}
}

func TestScopeCertificateBundle(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, bindings *BindingProviderMock) *scope
		assert func(t *testing.T, handle CertificateBundleHandle, scp *scope, err error)
	}{
		"returns certificate bundle handle and tracks lease": {
			setup: func(t *testing.T, bindings *BindingProviderMock) *scope {
				t.Helper()

				key := testScopeBindingKey(bindingKindCertificateBundle)
				bundle := types.NewCertificateBundle("selector", nil)

				sum := mocks.NewSecretUsageMock(t)
				sum.EXPECT().Track(bundle)

				bdg := newBinding(
					key,
					zerolog.Nop(),
					sum,
					func(context.Context) (CertificateBundle, error) { return bundle, nil },
				)
				bdg.publish(t.Context(), bundle)

				bindings.EXPECT().
					certificateBundleBinding(
						scopedReference{
							Reference: Reference{Source: "src", Selector: "selector"},
							scope:     referenceScopeInternal,
						},
					).
					Return(bdg, key, nil)

				return newScope(bindings)
			},
			assert: func(t *testing.T, handle CertificateBundleHandle, scp *scope, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, handle)

				bundle, ok := handle.Get()
				require.True(t, ok)
				require.Equal(t, "selector", bundle.Selector())

				require.Equal(t, map[bindingKey]int{
					testScopeBindingKey(bindingKindCertificateBundle): 1,
				}, scp.leases)
				require.Len(t, scp.readiness, 1)
			},
		},
		"returns binding error": {
			setup: func(t *testing.T, bindings *BindingProviderMock) *scope {
				t.Helper()

				bindings.EXPECT().
					certificateBundleBinding(
						scopedReference{
							Reference: Reference{Source: "src", Selector: "selector"},
							scope:     referenceScopeInternal,
						},
					).
					Return(nil, bindingKey{}, assert.AnError)

				return newScope(bindings)
			},
			assert: func(t *testing.T, handle CertificateBundleHandle, scp *scope, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)
				require.Nil(t, handle)
				require.Empty(t, scp.leases)
				require.Empty(t, scp.readiness)
			},
		},
		"releases binding if scope is already closed": {
			setup: func(t *testing.T, bindings *BindingProviderMock) *scope {
				t.Helper()

				key := testScopeBindingKey(bindingKindCertificateBundle)
				bundle := types.NewCertificateBundle("selector", nil)

				sum := mocks.NewSecretUsageMock(t)
				sum.EXPECT().Track(bundle)

				bdg := newBinding(
					key,
					zerolog.Nop(),
					sum,
					func(context.Context) (CertificateBundle, error) { return bundle, nil },
				)
				bdg.publish(t.Context(), bundle)

				bindings.EXPECT().
					certificateBundleBinding(
						scopedReference{
							Reference: Reference{Source: "src", Selector: "selector"},
							scope:     referenceScopeInternal,
						},
					).
					Return(bdg, key, nil)

				bindings.EXPECT().
					releaseBinding(key, 1)

				scp := newScope(bindings)
				scp.closed = true

				return scp
			},
			assert: func(t *testing.T, handle CertificateBundleHandle, _ *scope, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrResolverScopeClosed)
				require.Nil(t, handle)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			bindings := NewBindingProviderMock(t)
			scp := tc.setup(t, bindings)

			handle, err := scp.CertificateBundle(
				Reference{Source: "src", Selector: "selector"},
			)

			tc.assert(t, handle, scp, err)
		})
	}
}

func TestScopeUsesScopedReferences(t *testing.T) {
	t.Parallel()

	bindings := NewBindingProviderMock(t)

	key := bindingKey{
		kind:      bindingKindSecret,
		source:    "src",
		selector:  "selector",
		namespace: "team-a",
		scope:     referenceScopeRule,
	}
	secret := types.NewStringSecret("selector", "value")

	sum := mocks.NewSecretUsageMock(t)
	sum.EXPECT().Track(secret)

	bdg := newBinding(
		key,
		zerolog.Nop(),
		sum,
		func(context.Context) (Secret, error) { return secret, nil },
	)
	bdg.publish(t.Context(), secret)

	bindings.EXPECT().
		secretBinding(
			scopedReference{
				Reference: Reference{Source: "src", Selector: "selector"},
				namespace: "team-a",
				scope:     referenceScopeRule,
			},
		).
		Return(bdg, key, nil)

	scp := newScope(
		bindings,
		withID("foo"),
		withNamespace("team-a"),
	)

	handle, err := scp.Secret(
		Reference{Source: "src", Selector: "selector"},
	)

	require.NoError(t, err)
	require.NotNil(t, handle)
	require.Equal(t, "foo", scp.id)
	require.Equal(t, "team-a", scp.namespace)
	require.Equal(t, map[bindingKey]int{key: 1}, scp.leases)
	require.Len(t, scp.readiness, 1)
}

func TestScopeRelease(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, bindings *BindingProviderMock, calls *guardedScopeCalls) *scope
		assert func(t *testing.T, scp *scope, calls *guardedScopeCalls)
	}{
		"runs cleanups and releases bindings": {
			setup: func(
				t *testing.T,
				bindings *BindingProviderMock,
				calls *guardedScopeCalls,
			) *scope {
				t.Helper()

				keyA := testScopeBindingKey(bindingKindSecret)
				keyB := testScopeBindingKey(bindingKindCredentials)

				bindings.EXPECT().
					releaseBinding(keyA, 2).
					Run(func(_ bindingKey, _ int) {
						calls.Add("release:a")
					})
				bindings.EXPECT().
					releaseBinding(keyB, 1).
					Run(func(_ bindingKey, _ int) {
						calls.Add("release:b")
					})

				scp := newScope(
					bindings,
					withID("foo"),
					withNamespace("team-a"),
				)
				scp.leases[keyA] = 2
				scp.leases[keyB] = 1
				scp.cleanups = append(
					scp.cleanups,
					func() { calls.Add("cleanup:a") },
					func() { calls.Add("cleanup:b") },
				)
				scp.readiness = append(
					scp.readiness,
					func(context.Context) error { return nil },
					func(context.Context) error { return nil },
				)

				return scp
			},
			assert: func(t *testing.T, scp *scope, calls *guardedScopeCalls) {
				t.Helper()

				require.True(t, scp.closed)
				require.Empty(t, scp.leases)
				require.Empty(t, scp.cleanups)
				require.Nil(t, scp.readiness)

				require.ElementsMatch(t, []string{
					"cleanup:a",
					"cleanup:b",
					"release:a",
					"release:b",
				}, calls.All())
			},
		},
		"does nothing when already closed": {
			setup: func(
				t *testing.T,
				_ *BindingProviderMock,
				_ *guardedScopeCalls,
			) *scope {
				t.Helper()

				scp := newScope(NewBindingProviderMock(t))
				scp.closed = true

				return scp
			},
			assert: func(t *testing.T, scp *scope, calls *guardedScopeCalls) {
				t.Helper()

				require.True(t, scp.closed)
				require.Empty(t, calls.All())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			bindings := NewBindingProviderMock(t)

			var calls guardedScopeCalls

			scp := tc.setup(t, bindings, &calls)

			scp.Release()

			tc.assert(t, scp, &calls)
		})
	}
}

func TestScopeReleaseIsIdempotent(t *testing.T) {
	t.Parallel()

	bindings := NewBindingProviderMock(t)

	key := testScopeBindingKey(bindingKindSecret)

	bindings.EXPECT().
		releaseBinding(key, 1).
		Once()

	scp := newScope(
		bindings,
		withID("foo"),
		withNamespace("team-a"),
	)
	scp.leases[key] = 1

	scp.Release()
	scp.Release()
}

func TestScopeAwaitReady(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, calls *guardedScopeCalls) *scope
		assert func(t *testing.T, calls *guardedScopeCalls, err error)
	}{
		"waits for registered readiness callbacks": {
			setup: func(t *testing.T, calls *guardedScopeCalls) *scope {
				t.Helper()

				scp := newScope(NewBindingProviderMock(t))
				scp.registerReadiness(func(context.Context) error {
					calls.Add("a")

					return nil
				})
				scp.registerReadiness(func(context.Context) error {
					calls.Add("b")

					return nil
				})

				return scp
			},
			assert: func(t *testing.T, calls *guardedScopeCalls, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, []string{"a", "b"}, calls.All())
			},
		},
		"returns first readiness error": {
			setup: func(t *testing.T, calls *guardedScopeCalls) *scope {
				t.Helper()

				scp := newScope(NewBindingProviderMock(t))
				scp.registerReadiness(func(context.Context) error {
					calls.Add("a")

					return nil
				})
				scp.registerReadiness(func(context.Context) error {
					calls.Add("b")

					return assert.AnError
				})
				scp.registerReadiness(func(context.Context) error {
					calls.Add("c")

					return nil
				})

				return scp
			},
			assert: func(t *testing.T, calls *guardedScopeCalls, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)
				require.Equal(t, []string{"a", "b"}, calls.All())
			},
		},
		"returns closed error": {
			setup: func(t *testing.T, _ *guardedScopeCalls) *scope {
				t.Helper()

				scp := newScope(NewBindingProviderMock(t))
				scp.closed = true

				return scp
			},
			assert: func(t *testing.T, calls *guardedScopeCalls, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrResolverScopeClosed)
				require.Empty(t, calls.All())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			var calls guardedScopeCalls

			scp := tc.setup(t, &calls)

			err := scp.AwaitReady(t.Context())

			tc.assert(t, &calls, err)
		})
	}
}

func TestScopeTrackLease(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		closed bool
		want   bool
		assert func(t *testing.T, scp *scope)
	}{
		"tracks lease on open scope": {
			want: true,
			assert: func(t *testing.T, scp *scope) {
				t.Helper()

				require.Equal(t, map[bindingKey]int{
					testScopeBindingKey(bindingKindSecret): 1,
				}, scp.leases)
			},
		},
		"does not track lease on closed scope": {
			closed: true,
			want:   false,
			assert: func(t *testing.T, scp *scope) {
				t.Helper()

				require.Empty(t, scp.leases)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			scp := newScope(NewBindingProviderMock(t))
			scp.closed = tc.closed

			got := scp.trackLease(testScopeBindingKey(bindingKindSecret))

			require.Equal(t, tc.want, got)
			tc.assert(t, scp)
		})
	}
}

func TestScopeRegisterCleanup(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		closed bool
		assert func(t *testing.T, scp *scope, calls *guardedScopeCalls)
	}{
		"tracks cleanup on open scope": {
			assert: func(t *testing.T, scp *scope, calls *guardedScopeCalls) {
				t.Helper()

				require.Empty(t, calls.All())
				require.Len(t, scp.cleanups, 1)

				scp.Release()
				require.Equal(t, []string{"cleanup"}, calls.All())
			},
		},
		"runs cleanup immediately on closed scope": {
			closed: true,
			assert: func(t *testing.T, scp *scope, calls *guardedScopeCalls) {
				t.Helper()

				require.Equal(t, []string{"cleanup"}, calls.All())
				require.Empty(t, scp.cleanups)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			var calls guardedScopeCalls

			scp := newScope(NewBindingProviderMock(t))
			scp.closed = tc.closed

			scp.registerCleanup(func() {
				calls.Add("cleanup")
			})

			tc.assert(t, scp, &calls)
		})
	}
}

func TestScopeRegisterReadiness(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		closed bool
		await  func(context.Context) error
		assert func(t *testing.T, scp *scope)
	}{
		"tracks readiness on open scope": {
			await: func(context.Context) error { return nil },
			assert: func(t *testing.T, scp *scope) {
				t.Helper()

				require.Len(t, scp.readiness, 1)
			},
		},
		"ignores nil readiness": {
			assert: func(t *testing.T, scp *scope) {
				t.Helper()

				require.Empty(t, scp.readiness)
			},
		},
		"ignores readiness on closed scope": {
			closed: true,
			await:  func(context.Context) error { return nil },
			assert: func(t *testing.T, scp *scope) {
				t.Helper()

				require.Empty(t, scp.readiness)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			scp := newScope(NewBindingProviderMock(t))
			scp.closed = tc.closed

			scp.registerReadiness(tc.await)

			tc.assert(t, scp)
		})
	}
}

func testScopeBindingKey(kind bindingKind) bindingKey {
	return bindingKey{
		kind:      kind,
		source:    "src",
		selector:  "selector",
		namespace: "",
		scope:     referenceScopeInternal,
	}
}

type guardedScopeCalls struct {
	mu    sync.Mutex
	calls []string
}

func (c *guardedScopeCalls) Add(call string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.calls = append(c.calls, call)
}

func (c *guardedScopeCalls) All() []string {
	c.mu.Lock()
	defer c.mu.Unlock()

	return append([]string{}, c.calls...)
}

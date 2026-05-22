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

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestHandleGet(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup     func(t *testing.T, binding *HandleBindingMock[string])
		wantValue string
		wantOK    bool
	}{
		"returns available value": {
			setup: func(t *testing.T, binding *HandleBindingMock[string]) {
				t.Helper()

				binding.EXPECT().
					get(mock.Anything).
					Return("secret", true)
			},
			wantValue: "secret",
			wantOK:    true,
		},
		"returns unavailable value": {
			setup: func(t *testing.T, binding *HandleBindingMock[string]) {
				t.Helper()

				binding.EXPECT().
					get(mock.Anything).
					Return("", false)
			},
			wantOK: false,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			binding := NewHandleBindingMock[string](t)
			cleanups := NewCleanupRegistryMock(t)

			tc.setup(t, binding)

			handle := newHandle[string](binding, cleanups)

			got, ok := handle.Get(context.Background())

			require.Equal(t, tc.wantOK, ok)
			require.Equal(t, tc.wantValue, got)
		})
	}
}

func TestHandleOnUpdate(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		callback UpdateFunc[string]
		setup    func(t *testing.T, binding *HandleBindingMock[string], cleanups *CleanupRegistryMock)
	}{
		"registers callback and cleanup": {
			callback: func(context.Context, string) error {
				return nil
			},
			setup: func(t *testing.T, binding *HandleBindingMock[string], cleanups *CleanupRegistryMock) {
				t.Helper()

				cleanup := func() {}

				binding.EXPECT().
					subscribe(mock.MatchedBy(func(cb UpdateFunc[string]) bool {
						return cb != nil
					})).
					Return(cleanup)

				cleanups.EXPECT().
					registerCleanup(mock.MatchedBy(func(got func()) bool {
						return got != nil
					})).
					Run(func(got func()) {
						require.NotNil(t, got)
					})
			},
		},
		"ignores nil callback": {
			callback: nil,
			setup: func(t *testing.T, _ *HandleBindingMock[string], _ *CleanupRegistryMock) {
				t.Helper()
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			binding := NewHandleBindingMock[string](t)
			cleanups := NewCleanupRegistryMock(t)

			tc.setup(t, binding, cleanups)

			handle := newHandle[string](binding, cleanups)

			handle.OnUpdate(tc.callback)
		})
	}
}

func TestNoopCleanupRegistry(t *testing.T) {
	t.Parallel()

	called := false

	noopCleanupRegistry{}.registerCleanup(func() {
		called = true
	})

	require.False(t, called)
}

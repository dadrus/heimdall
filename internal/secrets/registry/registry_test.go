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

package registry

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/secrets/types/mocks"
)

func withCleanRegistry(t *testing.T) {
	t.Helper()

	factoriesMu.Lock()
	original := factories
	factories = make(map[string]Factory)
	factoriesMu.Unlock()

	t.Cleanup(func() {
		factoriesMu.Lock()
		factories = original
		factoriesMu.Unlock()
	})
}

func TestRegister(t *testing.T) {
	withCleanRegistry(t)

	t.Run("panics if factory is nil", func(t *testing.T) {
		require.PanicsWithValue(t, "secret provider factory is nil", func() {
			Register("foo", nil)
		})
	})

	t.Run("registers factory", func(t *testing.T) {
		factory := FactoryFunc(func(_ app.Context, sourceName string, _ map[string]any) (types.Provider, error) {
			return mocks.NewProviderMock(t), nil
		})

		Register("foo", factory)

		factoriesMu.RLock()

		registered, found := factories["foo"]

		factoriesMu.RUnlock()

		require.True(t, found)
		require.NotNil(t, registered)
	})
}

func TestCreate(t *testing.T) {
	for uc, tc := range map[string]struct {
		typ     string
		factory Factory
		assert  func(t *testing.T, provider types.Provider, err error)
	}{
		"returns error for unsupported provider type": {
			typ: "foo",
			assert: func(t *testing.T, provider types.Provider, err error) {
				t.Helper()

				require.Nil(t, provider)
				require.Error(t, err)
				require.ErrorIs(t, err, ErrUnsupportedProviderType)
			},
		},
		"returns factory creation error": {
			typ: "foo",
			factory: FactoryFunc(func(_ app.Context, _ string, _ map[string]any) (types.Provider, error) {
				return nil, errors.New("test error")
			}),
			assert: func(t *testing.T, provider types.Provider, err error) {
				t.Helper()

				require.Nil(t, provider)
				require.Error(t, err)
				require.ErrorContains(t, err, "test error")
			},
		},
		"creates provider with source name": {
			typ: "foo",
			factory: FactoryFunc(func(_ app.Context, sourceName string, _ map[string]any) (types.Provider, error) {
				provider := mocks.NewProviderMock(t)
				provider.EXPECT().Name().Return(sourceName)
				provider.EXPECT().Type().Return("foo")

				return provider, nil
			}),
			assert: func(t *testing.T, provider types.Provider, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, provider)
				require.Equal(t, "source-a", provider.Name())
				require.Equal(t, "foo", provider.Type())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			withCleanRegistry(t)

			if tc.factory != nil {
				Register(tc.typ, tc.factory)
			}

			appCtx := app.NewContextMock(t)

			provider, err := Create(appCtx, tc.typ, "source-a", map[string]any{"x": "y"})

			tc.assert(t, provider, err)
		})
	}
}

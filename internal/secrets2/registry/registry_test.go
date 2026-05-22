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
	"testing"

	"github.com/dadrus/heimdall/internal/secrets2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/secrets2/provider"
	"github.com/dadrus/heimdall/internal/secrets2/provider/mocks"
)

func withCleanRegistry(t *testing.T) {
	t.Helper()

	factoriesMu.Lock()
	original := factories
	factories = make(map[string]provider.Factory)
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
		factory := provider.FactoryFunc(func(_ provider.Args) (provider.Provider, error) {
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
		factory provider.Factory
		assert  func(t *testing.T, prv provider.Provider, err error)
	}{
		"returns error for unsupported provider type": {
			typ: "foo",
			assert: func(t *testing.T, _ provider.Provider, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, types.ErrUnsupportedProviderType)
			},
		},
		"returns factory creation error": {
			typ: "foo",
			factory: provider.FactoryFunc(func(_ provider.Args) (provider.Provider, error) {
				return nil, assert.AnError
			}),
			assert: func(t *testing.T, _ provider.Provider, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, assert.AnError.Error())
			},
		},
		"creates provider with source name": {
			typ: "foo",
			factory: provider.FactoryFunc(func(args provider.Args) (provider.Provider, error) {
				prv := mocks.NewProviderMock(t)
				prv.EXPECT().Type().Return("foo")

				return prv, nil
			}),
			assert: func(t *testing.T, provider provider.Provider, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, provider)
				require.Equal(t, "foo", provider.Type())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			withCleanRegistry(t)

			if tc.factory != nil {
				Register(tc.typ, tc.factory)
			}

			prv, err := Create(tc.typ, provider.Args{
				Config: map[string]any{"x": "y"},
			})

			tc.assert(t, prv, err)
		})
	}
}

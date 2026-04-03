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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	noopmetric "go.opentelemetry.io/otel/metric/noop"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/cache/metrics"
	"github.com/dadrus/heimdall/internal/cache/mocks"
	"github.com/dadrus/heimdall/internal/cache/noop"
	"github.com/dadrus/heimdall/internal/cache/types"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/x"
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
		require.PanicsWithValue(t, "cache factory is nil", func() {
			Register("foo", nil)
		})
	})

	t.Run("registers factory", func(t *testing.T) {
		factory := FactoryFunc(func(_ app.Context, _ map[string]any) (types.Cache, error) {
			return mocks.NewCacheMock(t), nil
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
		typ       string
		factory   Factory
		setupMock func(t *testing.T, appCtx *app.ContextMock)
		assert    func(t *testing.T, cch types.Cache, err error)
	}{
		"returns noop cache for noop type": {
			typ: "noop",

			assert: func(t *testing.T, cch types.Cache, err error) {
				t.Helper()

				require.NoError(t, err)
				require.IsType(t, &noop.Cache{}, cch)
			},
		},
		"returns error for unsupported cache type": {
			typ: "foo",
			assert: func(t *testing.T, cch types.Cache, err error) {
				t.Helper()

				require.Nil(t, cch)
				require.Error(t, err)
				require.ErrorIs(t, err, types.ErrUnsupportedType)
			},
		},
		"returns factory creation error": {
			typ: "foo",
			factory: FactoryFunc(func(_ app.Context, _ map[string]any) (types.Cache, error) {
				return nil, errors.New("test error")
			}),
			assert: func(t *testing.T, cch types.Cache, err error) {
				t.Helper()

				require.Nil(t, cch)
				require.Error(t, err)
				require.ErrorContains(t, err, "test error")
			},
		},
		"does not decorate cache if cover_cache is disabled": {
			typ: "foo",
			factory: FactoryFunc(func(_ app.Context, _ map[string]any) (types.Cache, error) {
				return mocks.NewCacheMock(t), nil
			}),
			setupMock: func(t *testing.T, appCtx *app.ContextMock) {
				t.Helper()

				appCtx.EXPECT().Config().Return(&config.Configuration{
					Metrics: config.MetricsConfig{Enabled: true, CoverCache: false},
				})
			},
			assert: func(t *testing.T, cch types.Cache, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.IsNotType(t, &metrics.Cache{}, cch)
			},
		},
		"does not decorate cache if metrics are globally disabled": {
			typ: "foo",
			factory: FactoryFunc(func(_ app.Context, _ map[string]any) (types.Cache, error) {
				return mocks.NewCacheMock(t), nil
			}),
			setupMock: func(t *testing.T, appCtx *app.ContextMock) {
				t.Helper()

				appCtx.EXPECT().Config().Return(&config.Configuration{
					Metrics: config.MetricsConfig{Enabled: false, CoverCache: true},
				})
			},
			assert: func(t *testing.T, cch types.Cache, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.IsNotType(t, &metrics.Cache{}, cch)
			},
		},
		"decorates cache if both metrics and cover_cache are enabled": {
			typ: "foo",
			factory: FactoryFunc(func(_ app.Context, _ map[string]any) (types.Cache, error) {
				created := mocks.NewCacheMock(t)
				created.EXPECT().Type().Return("mock-cache-type")

				return created, nil
			}),
			setupMock: func(t *testing.T, appCtx *app.ContextMock) {
				t.Helper()

				appCtx.EXPECT().Config().Return(
					&config.Configuration{
						Metrics: config.MetricsConfig{Enabled: true, CoverCache: true},
					},
				)
				appCtx.EXPECT().Meter().Return(noopmetric.Meter{})
			},
			assert: func(t *testing.T, cch types.Cache, err error) {
				t.Helper()

				require.NoError(t, err)
				require.IsType(t, &metrics.Cache{}, cch)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			withCleanRegistry(t)

			if tc.factory != nil {
				Register(tc.typ, tc.factory)
			}

			appCtx := app.NewContextMock(t)
			setupMock := x.IfThenElse(
				tc.setupMock != nil,
				tc.setupMock, func(t *testing.T, appCtx *app.ContextMock) { t.Helper() },
			)

			setupMock(t, appCtx)

			// fallback expectations for cases that do not care about config/meter
			appCtx.EXPECT().Config().Maybe().Return(&config.Configuration{})
			appCtx.EXPECT().Meter().Maybe().Return(noopmetric.Meter{})

			// WHEN
			cch, err := Create(appCtx, tc.typ, nil)

			// THEN
			tc.assert(t, cch, err)
		})
	}
}

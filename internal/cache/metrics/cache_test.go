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

package metrics

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/cache/mocks"
	"github.com/dadrus/heimdall/internal/cache/types"
)

func TestCacheType(t *testing.T) {
	t.Parallel()

	// GIVEN
	mockCache := mocks.NewCacheMock(t)
	mockCache.EXPECT().Type().Return("mock-cache-type")

	appCtx := app.NewContextMock(t)
	appCtx.EXPECT().Meter().Return(noop.Meter{})

	decorator, err := Decorate(appCtx, mockCache)
	require.NoError(t, err)

	// WHEN
	typ := decorator.Type()

	// THEN
	assert.Equal(t, "mock-cache-type", typ)
}

func TestCacheStart(t *testing.T) {
	t.Parallel()

	// GIVEN
	ctx := t.Context()

	mockCache := mocks.NewCacheMock(t)
	mockCache.EXPECT().Type().Return("mock-cache-type")
	mockCache.EXPECT().Start(ctx).Return(nil)

	appCtx := app.NewContextMock(t)
	appCtx.EXPECT().Meter().Return(noop.Meter{})

	decorator, err := Decorate(appCtx, mockCache)
	require.NoError(t, err)

	// WHEN
	err = decorator.Start(ctx)

	// THEN
	require.NoError(t, err)
	// expected mock calls are done
}

func TestCacheStop(t *testing.T) {
	t.Parallel()

	// GIVEN
	ctx := t.Context()

	mockCache := mocks.NewCacheMock(t)
	mockCache.EXPECT().Type().Return("mock-cache-type")
	mockCache.EXPECT().Stop(ctx).Return(nil)

	appCtx := app.NewContextMock(t)
	appCtx.EXPECT().Meter().Return(noop.Meter{})

	decorator, err := Decorate(appCtx, mockCache)
	require.NoError(t, err)

	// WHEN
	err = decorator.Stop(ctx)

	// THEN
	require.NoError(t, err)
	// expected mock calls are done
}

func TestCacheSet(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setupMocks  func(t *testing.T, cm *mocks.CacheMock)
		createMeter func(t *testing.T, mp metric.MeterProvider) metric.Meter
		assert      func(t *testing.T, err error, sm []metricdata.ScopeMetrics)
	}{
		"setting cache key results in an error": {
			setupMocks: func(t *testing.T, cm *mocks.CacheMock) {
				t.Helper()

				cm.EXPECT().
					Set(t.Context(), mock.Anything, mock.Anything, mock.Anything).
					Return(errors.New("test error"))
			},
			createMeter: func(t *testing.T, mp metric.MeterProvider) metric.Meter {
				t.Helper()

				return mp.Meter("cache-set-test")
			},
			assert: func(t *testing.T, err error, sm []metricdata.ScopeMetrics) {
				t.Helper()

				require.Error(t, err)

				require.Len(t, sm, 1)
				assert.Len(t, sm[0].Metrics, 1)
				assert.Equal(t, "cache.set.requests", sm[0].Metrics[0].Name)
				assert.Equal(t, "Total number of cache set requests", sm[0].Metrics[0].Description)
				assert.Equal(t, "{request}", sm[0].Metrics[0].Unit)

				sum, ok := sm[0].Metrics[0].Data.(metricdata.Sum[int64])
				require.True(t, ok)
				require.True(t, sum.IsMonotonic)

				require.Len(t, sum.DataPoints, 1)
				assert.Equal(t, int64(1), sum.DataPoints[0].Value)
				assert.Equal(t, 2, sum.DataPoints[0].Attributes.Len())

				val, present := sum.DataPoints[0].Attributes.Value(cacheBackendKey)
				require.True(t, present)
				assert.Equal(t, "mock-cache-type", val.AsString())

				val, present = sum.DataPoints[0].Attributes.Value(cacheResultKey)
				require.True(t, present)
				assert.Equal(t, "error", val.AsString())
			},
		},
		"setting cache key is successful": {
			setupMocks: func(t *testing.T, cm *mocks.CacheMock) {
				t.Helper()

				cm.EXPECT().
					Set(t.Context(), mock.Anything, mock.Anything, mock.Anything).
					Return(nil)
			},
			createMeter: func(t *testing.T, mp metric.MeterProvider) metric.Meter {
				t.Helper()

				return mp.Meter("cache-set-test")
			},
			assert: func(t *testing.T, err error, sm []metricdata.ScopeMetrics) {
				t.Helper()

				require.NoError(t, err)

				require.Len(t, sm, 1)
				assert.Len(t, sm[0].Metrics, 1)
				assert.Equal(t, "cache.set.requests", sm[0].Metrics[0].Name)
				assert.Equal(t, "Total number of cache set requests", sm[0].Metrics[0].Description)
				assert.Equal(t, "{request}", sm[0].Metrics[0].Unit)

				sum, ok := sm[0].Metrics[0].Data.(metricdata.Sum[int64])
				require.True(t, ok)
				require.True(t, sum.IsMonotonic)

				require.Len(t, sum.DataPoints, 1)
				assert.Equal(t, int64(1), sum.DataPoints[0].Value)
				assert.Equal(t, 2, sum.DataPoints[0].Attributes.Len())

				val, present := sum.DataPoints[0].Attributes.Value(cacheBackendKey)
				require.True(t, present)
				assert.Equal(t, "mock-cache-type", val.AsString())

				val, present = sum.DataPoints[0].Attributes.Value(cacheResultKey)
				require.True(t, present)
				assert.Equal(t, "success", val.AsString())
			},
		},
		"metrics collection disabled": {
			createMeter: func(t *testing.T, _ metric.MeterProvider) metric.Meter {
				t.Helper()

				return noop.Meter{}
			},
			setupMocks: func(t *testing.T, cm *mocks.CacheMock) {
				t.Helper()

				cm.EXPECT().
					Set(t.Context(), mock.Anything, mock.Anything, mock.Anything).
					Return(nil)
			},
			assert: func(t *testing.T, err error, sm []metricdata.ScopeMetrics) {
				t.Helper()

				require.NoError(t, err)
				require.Empty(t, sm)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			var rm metricdata.ResourceMetrics

			mr := sdkmetric.NewManualReader()
			mp := sdkmetric.NewMeterProvider(
				sdkmetric.WithResource(resource.Default()),
				sdkmetric.WithReader(mr),
			)

			mockCache := mocks.NewCacheMock(t)
			mockCache.EXPECT().Type().Return("mock-cache-type")
			tc.setupMocks(t, mockCache)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Meter().Return(tc.createMeter(t, mp))

			decorator, err := Decorate(appCtx, mockCache)
			require.NoError(t, err)

			// WHEN
			err = decorator.Set(t.Context(), "foo", []byte("bar"), 10*time.Second)

			// THEN
			require.NoError(t, mr.Collect(t.Context(), &rm))

			tc.assert(t, err, rm.ScopeMetrics)
		})
	}
}

func TestCacheGet(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setupMocks  func(t *testing.T, cm *mocks.CacheMock)
		createMeter func(t *testing.T, mp metric.MeterProvider) metric.Meter
		assert      func(t *testing.T, err error, value []byte, sm []metricdata.ScopeMetrics)
	}{
		"getting cache key results in an error": {
			setupMocks: func(t *testing.T, cm *mocks.CacheMock) {
				t.Helper()

				cm.EXPECT().
					Get(t.Context(), mock.Anything).
					Return(nil, errors.New("test error"))
			},
			createMeter: func(t *testing.T, mp metric.MeterProvider) metric.Meter {
				t.Helper()

				return mp.Meter("cache-set-test")
			},
			assert: func(t *testing.T, err error, value []byte, sm []metricdata.ScopeMetrics) {
				t.Helper()

				require.Error(t, err)
				require.Nil(t, value)

				require.Len(t, sm, 1)
				assert.Len(t, sm[0].Metrics, 1)
				assert.Equal(t, "cache.get.requests", sm[0].Metrics[0].Name)
				assert.Equal(t, "Total number of cache get requests", sm[0].Metrics[0].Description)
				assert.Equal(t, "{request}", sm[0].Metrics[0].Unit)

				sum, ok := sm[0].Metrics[0].Data.(metricdata.Sum[int64])
				require.True(t, ok)
				require.True(t, sum.IsMonotonic)

				require.Len(t, sum.DataPoints, 1)
				assert.Equal(t, int64(1), sum.DataPoints[0].Value)
				assert.Equal(t, 2, sum.DataPoints[0].Attributes.Len())

				val, present := sum.DataPoints[0].Attributes.Value(cacheBackendKey)
				require.True(t, present)
				assert.Equal(t, "mock-cache-type", val.AsString())

				val, present = sum.DataPoints[0].Attributes.Value(cacheResultKey)
				require.True(t, present)
				assert.Equal(t, "error", val.AsString())
			},
		},
		"getting cache key is a hit": {
			setupMocks: func(t *testing.T, cm *mocks.CacheMock) {
				t.Helper()

				cm.EXPECT().
					Get(t.Context(), mock.Anything).
					Return([]byte("val"), nil)
			},
			createMeter: func(t *testing.T, mp metric.MeterProvider) metric.Meter {
				t.Helper()

				return mp.Meter("cache-set-test")
			},
			assert: func(t *testing.T, err error, value []byte, sm []metricdata.ScopeMetrics) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, []byte("val"), value)

				require.Len(t, sm, 1)
				assert.Len(t, sm[0].Metrics, 1)
				assert.Equal(t, "cache.get.requests", sm[0].Metrics[0].Name)
				assert.Equal(t, "Total number of cache get requests", sm[0].Metrics[0].Description)
				assert.Equal(t, "{request}", sm[0].Metrics[0].Unit)

				sum, ok := sm[0].Metrics[0].Data.(metricdata.Sum[int64])
				require.True(t, ok)
				require.True(t, sum.IsMonotonic)

				require.Len(t, sum.DataPoints, 1)
				assert.Equal(t, int64(1), sum.DataPoints[0].Value)
				assert.Equal(t, 2, sum.DataPoints[0].Attributes.Len())

				val, present := sum.DataPoints[0].Attributes.Value(cacheBackendKey)
				require.True(t, present)
				assert.Equal(t, "mock-cache-type", val.AsString())

				val, present = sum.DataPoints[0].Attributes.Value(cacheResultKey)
				require.True(t, present)
				assert.Equal(t, "hit", val.AsString())
			},
		},
		"getting cache key is a miss": {
			setupMocks: func(t *testing.T, cm *mocks.CacheMock) {
				t.Helper()

				cm.EXPECT().
					Get(t.Context(), mock.Anything).
					Return(nil, types.ErrNoEntry)
			},
			createMeter: func(t *testing.T, mp metric.MeterProvider) metric.Meter {
				t.Helper()

				return mp.Meter("cache-set-test")
			},
			assert: func(t *testing.T, err error, value []byte, sm []metricdata.ScopeMetrics) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, types.ErrNoEntry)
				require.Nil(t, value)

				require.Len(t, sm, 1)
				assert.Len(t, sm[0].Metrics, 1)
				assert.Equal(t, "cache.get.requests", sm[0].Metrics[0].Name)
				assert.Equal(t, "Total number of cache get requests", sm[0].Metrics[0].Description)
				assert.Equal(t, "{request}", sm[0].Metrics[0].Unit)

				sum, ok := sm[0].Metrics[0].Data.(metricdata.Sum[int64])
				require.True(t, ok)
				require.True(t, sum.IsMonotonic)

				require.Len(t, sum.DataPoints, 1)
				assert.Equal(t, int64(1), sum.DataPoints[0].Value)
				assert.Equal(t, 2, sum.DataPoints[0].Attributes.Len())

				val, present := sum.DataPoints[0].Attributes.Value(cacheBackendKey)
				require.True(t, present)
				assert.Equal(t, "mock-cache-type", val.AsString())

				val, present = sum.DataPoints[0].Attributes.Value(cacheResultKey)
				require.True(t, present)
				assert.Equal(t, "miss", val.AsString())
			},
		},
		"metrics collection disabled": {
			createMeter: func(t *testing.T, _ metric.MeterProvider) metric.Meter {
				t.Helper()

				return noop.Meter{}
			},
			setupMocks: func(t *testing.T, cm *mocks.CacheMock) {
				t.Helper()

				cm.EXPECT().Get(t.Context(), mock.Anything).Return([]byte("val"), nil)
			},
			assert: func(t *testing.T, err error, value []byte, sm []metricdata.ScopeMetrics) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, []byte("val"), value)
				assert.Empty(t, sm)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			var rm metricdata.ResourceMetrics

			mr := sdkmetric.NewManualReader()
			mp := sdkmetric.NewMeterProvider(
				sdkmetric.WithResource(resource.Default()),
				sdkmetric.WithReader(mr),
			)

			mockCache := mocks.NewCacheMock(t)
			mockCache.EXPECT().Type().Return("mock-cache-type")
			tc.setupMocks(t, mockCache)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Meter().Return(tc.createMeter(t, mp))

			decorator, err := Decorate(appCtx, mockCache)
			require.NoError(t, err)

			// WHEN
			val, err := decorator.Get(t.Context(), "foo")

			// THEN
			require.NoError(t, mr.Collect(t.Context(), &rm))

			tc.assert(t, err, val, rm.ScopeMetrics)
		})
	}
}

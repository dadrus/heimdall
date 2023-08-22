// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
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

package opentelemetry

import (
	"reflect"
	"runtime"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/trace"

	"github.com/dadrus/heimdall/internal/x/opentelemetry/mocks"
)

func TestOptionsWithTracer(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		opt    opts
		tracer trace.Tracer
		assert func(t *testing.T, opt *opts)
	}{
		{
			uc:  "nil tracer",
			opt: defaultOptions,
			assert: func(t *testing.T, opt *opts) {
				t.Helper()

				assert.Equal(t, defaultOptions.tracer, opt.tracer)
			},
		},
		{
			uc:     "not nil tracer",
			opt:    defaultOptions,
			tracer: mocks.NewMockTracer(),
			assert: func(t *testing.T, opt *opts) {
				t.Helper()

				assert.IsType(t, &mocks.MockTracer{}, opt.tracer)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			apply := WithTracer(tc.tracer)
			opt := &tc.opt //nolint:gosec

			// WHEN
			apply(opt)

			// THEN
			tc.assert(t, opt)
		})
	}
}

func TestOptionsWithSpanObserver(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc       string
		opt      opts
		observer SpanObserver
		assert   func(t *testing.T, opt *opts)
	}{
		{
			uc:  "nil span observer",
			opt: defaultOptions,
			assert: func(t *testing.T, opt *opts) {
				t.Helper()

				f1 := runtime.FuncForPC(reflect.ValueOf(defaultOptions.spanObserver).Pointer()).Name()
				f2 := runtime.FuncForPC(reflect.ValueOf(opt.spanObserver).Pointer()).Name()

				assert.Equal(t, f1, f2)
			},
		},
		{
			uc:       "not nil span observer",
			opt:      defaultOptions,
			observer: func(_ *fiber.Ctx, span trace.Span) {},
			assert: func(t *testing.T, opt *opts) {
				t.Helper()

				f1 := runtime.FuncForPC(reflect.ValueOf(defaultOptions.spanObserver).Pointer()).Name()
				f2 := runtime.FuncForPC(reflect.ValueOf(opt.spanObserver).Pointer()).Name()

				assert.NotEqual(t, f1, f2)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			apply := WithSpanObserver(tc.observer)
			opt := &tc.opt //nolint:gosec

			// WHEN
			apply(opt)

			// THEN
			tc.assert(t, opt)
		})
	}
}

func TestOptionsWithOperationNameProvider(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc       string
		opt      opts
		provider OperationNameProvider
		assert   func(t *testing.T, opt *opts)
	}{
		{
			uc:  "nil operation name provider",
			opt: defaultOptions,
			assert: func(t *testing.T, opt *opts) {
				t.Helper()

				f1 := runtime.FuncForPC(reflect.ValueOf(defaultOptions.operationName).Pointer()).Name()
				f2 := runtime.FuncForPC(reflect.ValueOf(opt.operationName).Pointer()).Name()

				assert.Equal(t, f1, f2)
			},
		},
		{
			uc:       "not nil operation name provider",
			opt:      defaultOptions,
			provider: func(ctx *fiber.Ctx) string { return "" },
			assert: func(t *testing.T, opt *opts) {
				t.Helper()

				f1 := runtime.FuncForPC(reflect.ValueOf(defaultOptions.operationName).Pointer()).Name()
				f2 := runtime.FuncForPC(reflect.ValueOf(opt.operationName).Pointer()).Name()

				assert.NotEqual(t, f1, f2)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			apply := WithOperationNameProvider(tc.provider)
			opt := &tc.opt //nolint:gosec

			// WHEN
			apply(opt)

			// THEN
			tc.assert(t, opt)
		})
	}
}

func TestOptionsWithOperationFilter(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		opt    opts
		filter OperationFilter
		assert func(t *testing.T, opt *opts)
	}{
		{
			uc:  "nil operation filter",
			opt: defaultOptions,
			assert: func(t *testing.T, opt *opts) {
				t.Helper()

				f1 := runtime.FuncForPC(reflect.ValueOf(defaultOptions.filterOperation).Pointer()).Name()
				f2 := runtime.FuncForPC(reflect.ValueOf(opt.filterOperation).Pointer()).Name()

				assert.Equal(t, f1, f2)
			},
		},
		{
			uc:     "not nil operation filter",
			opt:    defaultOptions,
			filter: func(ctx *fiber.Ctx) bool { return true },
			assert: func(t *testing.T, opt *opts) {
				t.Helper()

				f1 := runtime.FuncForPC(reflect.ValueOf(defaultOptions.filterOperation).Pointer()).Name()
				f2 := runtime.FuncForPC(reflect.ValueOf(opt.filterOperation).Pointer()).Name()

				assert.NotEqual(t, f1, f2)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			apply := WithOperationFilter(tc.filter)
			opt := &tc.opt //nolint:gosec

			// WHEN
			apply(opt)

			// THEN
			tc.assert(t, opt)
		})
	}
}

func TestOptionsWithSkipSpanWithoutParent(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		opt    opts
		skip   bool
		assert func(t *testing.T, opt *opts)
	}{
		{
			uc:  "default setting",
			opt: defaultOptions,
			assert: func(t *testing.T, opt *opts) {
				t.Helper()

				assert.False(t, opt.skipSpansWithoutParent)
			},
		},
		{
			uc:   "set to skip",
			opt:  defaultOptions,
			skip: true,
			assert: func(t *testing.T, opt *opts) {
				t.Helper()

				assert.True(t, opt.skipSpansWithoutParent)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			apply := WithSkipSpanWithoutParent(tc.skip)
			opt := &tc.opt //nolint:gosec

			// WHEN
			apply(opt)

			// THEN
			tc.assert(t, opt)
		})
	}
}

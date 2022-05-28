package tracing

import (
	"reflect"
	"runtime"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/mocktracer"
	"github.com/stretchr/testify/assert"
)

func TestOptionsWithTracer(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		opt    opts
		tracer opentracing.Tracer
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
			tracer: &mocktracer.MockTracer{},
			assert: func(t *testing.T, opt *opts) {
				t.Helper()

				assert.IsType(t, &mocktracer.MockTracer{}, opt.tracer)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			apply := WithTracer(tc.tracer)

			// WHEN
			apply(&tc.opt)

			// THEN
			tc.assert(t, &tc.opt)
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
			observer: func(span opentracing.Span, _ *fiber.Ctx) {},
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

			// WHEN
			apply(&tc.opt)

			// THEN
			tc.assert(t, &tc.opt)
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

			// WHEN
			apply(&tc.opt)

			// THEN
			tc.assert(t, &tc.opt)
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
			apply := WithOperationFiler(tc.filter)

			// WHEN
			apply(&tc.opt)

			// THEN
			tc.assert(t, &tc.opt)
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

			// WHEN
			apply(&tc.opt)

			// THEN
			tc.assert(t, &tc.opt)
		})
	}
}

package prometheus

import (
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
)

func TestOptionsWithRegisterer(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		opt    opts
		value  prometheus.Registerer
		assert func(t *testing.T, opt *opts)
	}{
		{
			uc:  "nil registerer",
			opt: defaultOptions,
			assert: func(t *testing.T, opt *opts) {
				t.Helper()

				assert.Equal(t, prometheus.DefaultRegisterer, opt.registerer)
			},
		},
		{
			uc:    "not nil registerer",
			opt:   defaultOptions,
			value: prometheus.NewRegistry(),
			assert: func(t *testing.T, opt *opts) {
				t.Helper()

				assert.NotNil(t, opt.registerer)
				assert.NotEqual(t, prometheus.DefaultRegisterer, opt.registerer)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			apply := WithRegisterer(tc.value)

			// WHEN
			apply(&tc.opt)

			// THEN
			tc.assert(t, &tc.opt)
		})
	}
}

func TestOptionsWithServiceName(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		opt    opts
		value  string
		assert func(t *testing.T, opt *opts)
	}{
		{
			uc:  "empty service name",
			opt: opts{},
			assert: func(t *testing.T, opt *opts) {
				t.Helper()

				assert.Empty(t, opt.labels)
			},
		},
		{
			uc:    "not empty service name",
			opt:   opts{labels: make(prometheus.Labels)},
			value: "foo",
			assert: func(t *testing.T, opt *opts) {
				t.Helper()

				assert.Len(t, opt.labels, 1)
				assert.Equal(t, "foo", opt.labels["service"])
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			apply := WithServiceName(tc.value)

			// WHEN
			apply(&tc.opt)

			// THEN
			tc.assert(t, &tc.opt)
		})
	}
}

func TestOptionsWithNamespace(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		opt    opts
		value  string
		assert func(t *testing.T, opt *opts)
	}{
		{
			uc:  "empty namespace",
			opt: opts{},
			assert: func(t *testing.T, opt *opts) {
				t.Helper()

				assert.Empty(t, opt.namespace)
			},
		},
		{
			uc:    "not empty service name",
			opt:   opts{},
			value: "foo",
			assert: func(t *testing.T, opt *opts) {
				t.Helper()

				assert.Equal(t, "foo", opt.namespace)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			apply := WithNamespace(tc.value)

			// WHEN
			apply(&tc.opt)

			// THEN
			tc.assert(t, &tc.opt)
		})
	}
}

func TestOptionsWithSubsystem(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		opt    opts
		value  string
		assert func(t *testing.T, opt *opts)
	}{
		{
			uc:  "empty subsystem",
			opt: opts{},
			assert: func(t *testing.T, opt *opts) {
				t.Helper()

				assert.Empty(t, opt.subsystem)
			},
		},
		{
			uc:    "not empty subsystem",
			opt:   opts{},
			value: "foo",
			assert: func(t *testing.T, opt *opts) {
				t.Helper()

				assert.Equal(t, "foo", opt.subsystem)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			apply := WithSubsystem(tc.value)

			// WHEN
			apply(&tc.opt)

			// THEN
			tc.assert(t, &tc.opt)
		})
	}
}

func TestOptionsWithLabel(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		opt    opts
		name   string
		value  string
		assert func(t *testing.T, opt *opts)
	}{
		{
			uc:    "empty label name",
			opt:   opts{},
			value: "foo",
			assert: func(t *testing.T, opt *opts) {
				t.Helper()

				assert.Empty(t, opt.labels)
			},
		},
		{
			uc:   "empty label value",
			opt:  opts{},
			name: "foo",
			assert: func(t *testing.T, opt *opts) {
				t.Helper()

				assert.Empty(t, opt.labels)
			},
		},
		{
			uc:    "not empty label name & value",
			opt:   opts{labels: make(prometheus.Labels)},
			name:  "foo",
			value: "bar",
			assert: func(t *testing.T, opt *opts) {
				t.Helper()

				assert.Len(t, opt.labels, 1)
				assert.Equal(t, "bar", opt.labels["foo"])
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			apply := WithLabel(tc.name, tc.value)

			// WHEN
			apply(&tc.opt)

			// THEN
			tc.assert(t, &tc.opt)
		})
	}
}

func TestOptionsWithLabels(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		opt    opts
		labels map[string]string
		assert func(t *testing.T, opt *opts)
	}{
		{
			uc:  "empty labels map",
			opt: opts{},
			assert: func(t *testing.T, opt *opts) {
				t.Helper()

				assert.Empty(t, opt.labels)
			},
		},
		{
			uc:     "map with empty key",
			opt:    opts{},
			labels: map[string]string{"": "bar"},
			assert: func(t *testing.T, opt *opts) {
				t.Helper()

				assert.Empty(t, opt.labels)
			},
		},
		{
			uc:     "map with empty value",
			opt:    opts{},
			labels: map[string]string{"foo": ""},
			assert: func(t *testing.T, opt *opts) {
				t.Helper()

				assert.Empty(t, opt.labels)
			},
		},
		{
			uc:  "map with multiple not empty label name & value",
			opt: opts{labels: make(prometheus.Labels)},
			labels: map[string]string{
				"foo": "bar",
				"baz": "zab",
			},
			assert: func(t *testing.T, opt *opts) {
				t.Helper()

				assert.Len(t, opt.labels, 2)
				assert.Equal(t, "bar", opt.labels["foo"])
				assert.Equal(t, "zab", opt.labels["baz"])
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			apply := WithLabels(tc.labels)

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
		value  OperationFilter
		assert func(t *testing.T, opt *opts)
	}{
		{
			uc:  "without operations filter set",
			opt: opts{},
			assert: func(t *testing.T, opt *opts) {
				t.Helper()

				assert.Nil(t, opt.filterOperation)
			},
		},
		{
			uc:    "not empty subsystem",
			opt:   opts{},
			value: func(ctx *fiber.Ctx) bool { return true },
			assert: func(t *testing.T, opt *opts) {
				t.Helper()

				assert.NotNil(t, opt.filterOperation)
				assert.True(t, opt.filterOperation(nil))
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			apply := WithOperationFilter(tc.value)

			// WHEN
			apply(&tc.opt)

			// THEN
			tc.assert(t, &tc.opt)
		})
	}
}

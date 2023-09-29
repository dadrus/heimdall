// Copyright 2023 Dimitrij Drus <dadrus@gmx.de>
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

package otelmetrics

import (
	"net/http"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdk "go.opentelemetry.io/otel/sdk/metric"
)

func TestOptionsWithMeterProvider(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		opt    Option
		assert func(t *testing.T, opt *config)
	}{
		{
			uc:  "nil provider",
			opt: WithSubsystem("foo"),
			assert: func(t *testing.T, opt *config) {
				t.Helper()

				assert.Equal(t, otel.GetMeterProvider(), opt.provider)
			},
		},
		{
			uc:  "not nil registerer",
			opt: WithMeterProvider(sdk.NewMeterProvider()),
			assert: func(t *testing.T, opt *config) {
				t.Helper()

				assert.NotNil(t, opt.provider)
				assert.NotEqual(t, prometheus.DefaultRegisterer, opt.provider)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// WHEN
			cfg := newConfig(tc.opt)

			// THEN
			tc.assert(t, cfg)
		})
	}
}

func TestOptionsWithAttributes(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc         string
		opt        config
		attributes []attribute.KeyValue
		assert     func(t *testing.T, opt *config)
	}{
		{
			uc:  "without attributes",
			opt: config{},
			assert: func(t *testing.T, opt *config) {
				t.Helper()

				assert.Empty(t, opt.attributes)
			},
		},
		{
			uc:  "with multiple attibutes",
			opt: config{},
			attributes: []attribute.KeyValue{
				attribute.String("foo", "bar"),
				attribute.String("baz", "zab"),
			},
			assert: func(t *testing.T, opt *config) {
				t.Helper()

				assert.Len(t, opt.attributes, 2)
				assert.Equal(t, attribute.Key("foo"), opt.attributes[0].Key)
				assert.Equal(t, "bar", opt.attributes[0].Value.AsString())
				assert.Equal(t, attribute.Key("baz"), opt.attributes[1].Key)
				assert.Equal(t, "zab", opt.attributes[1].Value.AsString())
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			apply := WithAttributes(tc.attributes...)
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
		opt    config
		value  OperationFilter
		assert func(t *testing.T, opt *config)
	}{
		{
			uc:  "without operations filter set",
			opt: config{},
			assert: func(t *testing.T, opt *config) {
				t.Helper()

				assert.Nil(t, opt.shouldProcess)
			},
		},
		{
			uc:    "with filter",
			opt:   config{},
			value: func(req *http.Request) bool { return false },
			assert: func(t *testing.T, opt *config) {
				t.Helper()

				assert.NotNil(t, opt.shouldProcess)
				assert.False(t, opt.shouldProcess(nil))
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			apply := WithOperationFilter(tc.value)
			opt := &tc.opt //nolint:gosec

			// WHEN
			apply(opt)

			// THEN
			tc.assert(t, opt)
		})
	}
}

func TestOptionsWithServerName(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		opt    config
		name   string
		assert func(t *testing.T, opt *config)
	}{
		{
			uc:  "without server name",
			opt: config{},
			assert: func(t *testing.T, opt *config) {
				t.Helper()

				assert.Empty(t, opt.server)
			},
		},
		{
			uc:   "with server name",
			opt:  config{},
			name: "foobar.local",
			assert: func(t *testing.T, opt *config) {
				t.Helper()

				assert.Equal(t, "foobar.local", opt.server)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			apply := WithServerName(tc.name)
			opt := &tc.opt //nolint:gosec

			// WHEN
			apply(opt)

			// THEN
			tc.assert(t, opt)
		})
	}
}

func TestOptionsWithSubsystem(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		opt    config
		name   string
		assert func(t *testing.T, opt *config)
	}{
		{
			uc:  "without subsystem name",
			opt: config{},
			assert: func(t *testing.T, opt *config) {
				t.Helper()

				assert.False(t, opt.subsystem.Valid())
			},
		},
		{
			uc:   "with subsystem name",
			opt:  config{},
			name: "foobar",
			assert: func(t *testing.T, opt *config) {
				t.Helper()

				assert.True(t, opt.subsystem.Valid())
				assert.Equal(t, "foobar", opt.subsystem.Value.AsString())
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			apply := WithSubsystem(tc.name)
			opt := &tc.opt //nolint:gosec

			// WHEN
			apply(opt)

			// THEN
			tc.assert(t, opt)
		})
	}
}

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

package propagators

import (
	"testing"

	"github.com/stretchr/testify/assert"
	datadog "github.com/tonglil/opentelemetry-go-datadog-propagator"
	"go.opentelemetry.io/otel/propagation"
)

func TestAvailablePropagators(t *testing.T) {
	for uc, tc := range map[string]struct {
		setup  func(t *testing.T)
		assert func(t *testing.T, propagator propagation.TextMapPropagator)
	}{
		"datadog propagator can be used": {
			setup: func(t *testing.T) {
				t.Helper()

				t.Setenv("OTEL_PROPAGATORS", "datadog")
			},
			assert: func(t *testing.T, propagator propagation.TextMapPropagator) {
				t.Helper()

				assert.IsType(t, datadog.Propagator{}, propagator)
			},
		},
		"all available propagators can be used": {
			setup: func(t *testing.T) {
				t.Helper()

				t.Setenv("OTEL_PROPAGATORS", "tracecontext,baggage,b3,b3multi,jaeger,xray,ottrace,datadog")
			},
			assert: func(t *testing.T, propagator propagation.TextMapPropagator) {
				t.Helper()

				assert.Len(t, propagator, 8)
				assert.Contains(t, propagator, datadog.Propagator{})
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			tc.setup(t)

			// WHEN
			prop := New()

			// THEN
			tc.assert(t, prop)
		})
	}
}

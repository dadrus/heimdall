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

package exporters

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
)

func TestNewWithoutSetEnvVariable(t *testing.T) {
	t.Parallel()

	// WHEN
	expts, err := New(context.Background())

	// THEN
	require.NoError(t, err)
	assert.Len(t, expts, 1)
	assert.IsType(t, expts[0], &otlptrace.Exporter{})
}

func TestNewWithSetEnvVariable(t *testing.T) {
	// GIVEN
	t.Setenv(otelTracesExportersEnvKey, "none")

	// WHEN
	expts, err := New(context.Background())

	// THEN
	require.NoError(t, err)
	assert.Len(t, expts, 1)
	assert.IsType(t, noopExporter{}, expts[0])
}

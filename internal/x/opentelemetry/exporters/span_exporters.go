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
	"os"
	"strings"

	"go.opentelemetry.io/otel/sdk/trace"
)

// NewSpanExporters returns a slice of trace.SpanExporters defined by the
// OTEL_TRACES_EXPORTER environment variable. An "otel" SpanExporter is returned
// if no exporter is defined for the environment variable. A no-op
// SpanExporter will be returned if "none" is defined anywhere in the
// environment variable.
func NewSpanExporters(ctx context.Context) ([]trace.SpanExporter, error) {
	exporterNames, ok := os.LookupEnv("OTEL_TRACES_EXPORTER")
	if !ok {
		return createSpanExporters(ctx)
	}

	return createSpanExporters(ctx, strings.Split(exporterNames, ",")...)
}

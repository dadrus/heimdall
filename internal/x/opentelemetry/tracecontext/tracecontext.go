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

package tracecontext

import (
	"context"

	trace2 "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

type TraceContext struct {
	TraceID  string
	SpanID   string
	ParentID string
}

func Extract(ctx context.Context) *TraceContext {
	span := trace.SpanFromContext(ctx)
	spanCtx := span.SpanContext()

	if spanCtx.IsValid() {
		ctxInfo := &TraceContext{}

		if roSpan, ok := span.(trace2.ReadOnlySpan); ok && roSpan.Parent().IsValid() {
			ctxInfo.ParentID = roSpan.Parent().SpanID().String()
		}

		ctxInfo.TraceID = spanCtx.TraceID().String()
		ctxInfo.SpanID = spanCtx.SpanID().String()

		return ctxInfo
	}

	return nil
}

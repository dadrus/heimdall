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
	"github.com/gofiber/fiber/v2"
	"go.opentelemetry.io/otel/trace"
)

type (
	SpanObserver          func(*fiber.Ctx, trace.Span)
	OperationNameProvider func(*fiber.Ctx) string
	OperationFilter       func(*fiber.Ctx) bool
)

type opts struct {
	tracer                 trace.Tracer
	spanObserver           SpanObserver
	operationName          OperationNameProvider
	filterOperation        OperationFilter
	skipSpansWithoutParent bool
}

type Option func(*opts)

func WithTracer(tracer trace.Tracer) Option {
	return func(o *opts) {
		if tracer != nil {
			o.tracer = tracer
		}
	}
}

func WithSpanObserver(observer SpanObserver) Option {
	return func(o *opts) {
		if observer != nil {
			o.spanObserver = observer
		}
	}
}

func WithOperationNameProvider(provider OperationNameProvider) Option {
	return func(o *opts) {
		if provider != nil {
			o.operationName = provider
		}
	}
}

func WithOperationFilter(filter OperationFilter) Option {
	return func(o *opts) {
		if filter != nil {
			o.filterOperation = filter
		}
	}
}

func WithSkipSpanWithoutParent(flag bool) Option {
	return func(o *opts) {
		o.skipSpansWithoutParent = flag
	}
}

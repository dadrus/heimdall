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
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v2"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

const (
	tracerName    = "github.com/dadrus/heimdall/internal/fiber/middleware/opentel"
	tracerVersion = "semver:0.1.0"
)

// nolint: gochecknoglobals
var defaultOptions = opts{
	tracer: otel.GetTracerProvider().Tracer(tracerName, trace.WithInstrumentationVersion(tracerVersion)),
	operationName: func(ctx *fiber.Ctx) string {
		return fmt.Sprintf("EntryPoint %s %s%s",
			strings.ToLower(ctx.Protocol()), ctx.Context().LocalAddr().String(), ctx.Path())
	},
	filterOperation:        func(ctx *fiber.Ctx) bool { return false },
	skipSpansWithoutParent: false,
	spanObserver:           func(ctx *fiber.Ctx, span trace.Span) {},
}

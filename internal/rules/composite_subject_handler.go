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

package rules

import (
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
)

type compositeSubjectHandler []subjectHandler

func (cm compositeSubjectHandler) Execute(ctx heimdall.Context, sub *subject.Subject) error {
	logger := zerolog.Ctx(ctx.AppContext())

	var span trace.Span

	appContext := ctx.AppContext()

	//if !trace.SpanFromContext(appContext).IsRecording() {
	tracer := otel.GetTracerProvider().Tracer("heimdall")
	appContext, span = tracer.Start(appContext, "heimdall.subject-handler")
	//}
	for _, handler := range cm {

		err := handler.Execute(ctx, sub)
		if err != nil {
			logger.Info().Err(err).Msg("Pipeline step execution failed")

			if handler.ContinueOnError() {
				logger.Info().Msg("Error ignored. Continuing pipeline execution")
			} else {
				return err
			}
		}
	}

	if span != nil {
		defer span.End()
	}

	return nil
}

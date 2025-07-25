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
	"strings"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type compositeSubjectHandler []subjectHandler

func (cm compositeSubjectHandler) Execute(ctx heimdall.RequestContext, sub *subject.Subject) error {
	logger := zerolog.Ctx(ctx.Context())

	for _, handler := range cm {
		err := handler.Execute(ctx, sub)
		if err != nil {
			logger.Info().Err(err).Msg("Pipeline step execution failed")

			if strings.Contains(err.Error(), "tls:") {
				return errorchain.New(heimdall.ErrInternal).CausedBy(err)
			}

			if handler.ContinueOnError() {
				logger.Info().Msg("Error ignored. Continuing pipeline execution")
			} else {
				return err
			}
		}
	}

	return nil
}

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
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/rs/zerolog"
	"strings"

	"github.com/dadrus/heimdall/internal/accesscontext"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
)

type compositeSubjectCreator []subjectCreator

func (ca compositeSubjectCreator) Execute(ctx heimdall.RequestContext) (*subject.Subject, error) {
	logger := zerolog.Ctx(ctx.Context())

	var (
		sub *subject.Subject
		err error
	)

	for idx, a := range ca {
		sub, err = a.Execute(ctx)
		if err != nil {
			logger.Warn().Err(err).Msg("Pipeline step execution failed")

			if strings.Contains(err.Error(), "tls:") {
				err = errorchain.New(heimdall.ErrInternal).CausedBy(err)

				break
			}

			if idx < len(ca)-1 {
				logger.Info().Msg("Falling back to next configured one.")

				continue
			}

			break
		}

		accesscontext.SetSubject(ctx.Context(), sub.ID)

		return sub, nil
	}

	return nil, err
}

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
	"errors"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/accesscontext"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/subject"
)

type compositeSubjectCreator []subjectHandler

func (ca compositeSubjectCreator) Execute(ctx heimdall.Context, sub subject.Subject) error {
	logger := zerolog.Ctx(ctx.AppContext())

	var err error

	for idx, a := range ca {
		err = a.Execute(ctx, sub)
		if err != nil {
			logger.Info().Err(err).Msg("Pipeline step execution failed")

			if (errors.Is(err, heimdall.ErrArgument) || a.ContinueOnError()) && idx < len(ca) {
				logger.Info().Msg("Falling back to next configured one.")

				continue
			}

			break
		}

		accesscontext.SetSubject(ctx.AppContext(), sub)

		return nil
	}

	return err
}

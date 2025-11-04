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

	"github.com/dadrus/heimdall/internal/accesscontext"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/identity"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type compositePrincipalCreator []heimdall.Step

func (cp compositePrincipalCreator) IsInsecure() bool {
	return len(cp) == 0 || cp[0].IsInsecure()
}

func (cp compositePrincipalCreator) Execute(ctx heimdall.Context, sub identity.Subject) error {
	logger := zerolog.Ctx(ctx.Context())

	var err error

	for idx, a := range cp {
		err = a.Execute(ctx, sub)
		if err != nil {
			logger.Warn().Err(err).Msg("Pipeline step execution failed")

			if strings.Contains(err.Error(), "tls:") {
				err = errorchain.New(heimdall.ErrInternal).CausedBy(err)

				break
			}

			if idx < len(cp)-1 {
				logger.Info().Msg("Falling back to next configured one.")

				continue
			}

			break
		}

		accesscontext.SetSubject(ctx.Context(), sub.ID())

		return nil
	}

	return err
}

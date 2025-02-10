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

	"github.com/dadrus/heimdall/internal/heimdall"
)

type compositeErrorHandler []errorHandler

func (eh compositeErrorHandler) Execute(ctx heimdall.Context, exErr error) error {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Handling pipeline error")

	for _, handler := range eh {
		if err := handler.Execute(ctx, exErr); err != nil {
			if errors.Is(err, errErrorHandlerNotApplicable) {
				continue
			}

			logger.Error().Err(err).Msg("Failed to execute error handler")

			return err
		}

		return nil
	}

	logger.Debug().Msg("No applicable error handler found")

	return exErr
}

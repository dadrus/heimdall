// Copyright 2023 Dimitrij Drus <dadrus@gmx.de>
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

package dump

import (
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
)

func New() fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		logger := zerolog.Ctx(ctx.UserContext())

		if logger.GetLevel() != zerolog.TraceLevel {
			return ctx.Next()
		}

		logger.Trace().Msg("Request: \n" + ctx.Context().Request.String())

		err := ctx.Next()
		if err != nil {
			logger.Trace().Err(err).Msg("Failed processing request")
		} else {
			logger.Trace().Msg("Response: \n" + ctx.Context().Response.String())
		}

		return err
	}
}

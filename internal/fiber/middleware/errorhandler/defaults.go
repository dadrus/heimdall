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

package errorhandler

import "github.com/gofiber/fiber/v2"

var defaultOptions = opts{ //nolint:gochecknoglobals
	onAuthenticationError: func(ctx *fiber.Ctx) { ctx.Status(fiber.StatusUnauthorized) },
	onAuthorizationError:  func(ctx *fiber.Ctx) { ctx.Status(fiber.StatusForbidden) },
	onCommunicationError:  func(ctx *fiber.Ctx) { ctx.Status(fiber.StatusBadGateway) },
	onPreconditionError:   func(ctx *fiber.Ctx) { ctx.Status(fiber.StatusBadRequest) },
	onBadMethodError:      func(ctx *fiber.Ctx) { ctx.Status(fiber.StatusMethodNotAllowed) },
	onNoRuleError:         func(ctx *fiber.Ctx) { ctx.Status(fiber.StatusNotFound) },
	onInternalError:       func(ctx *fiber.Ctx) { ctx.Status(fiber.StatusInternalServerError) },
}

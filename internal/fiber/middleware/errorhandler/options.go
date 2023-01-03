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

type opts struct {
	verboseErrors         bool
	onAuthenticationError func(ctx *fiber.Ctx)
	onAuthorizationError  func(ctx *fiber.Ctx)
	onCommunicationError  func(ctx *fiber.Ctx)
	onPreconditionError   func(ctx *fiber.Ctx)
	onBadMethodError      func(ctx *fiber.Ctx)
	onNoRuleError         func(ctx *fiber.Ctx)
	onInternalError       func(ctx *fiber.Ctx)
}

type Option func(*opts)

func WithPreconditionErrorCode(code int) Option {
	return func(o *opts) {
		if code != 0 {
			o.onPreconditionError = func(ctx *fiber.Ctx) { ctx.Status(code) }
		}
	}
}

func WithAuthenticationErrorCode(code int) Option {
	return func(o *opts) {
		if code != 0 {
			o.onAuthenticationError = func(ctx *fiber.Ctx) { ctx.Status(code) }
		}
	}
}

func WithAuthorizationErrorCode(code int) Option {
	return func(o *opts) {
		if code != 0 {
			o.onAuthorizationError = func(ctx *fiber.Ctx) { ctx.Status(code) }
		}
	}
}

func WithCommunicationErrorCode(code int) Option {
	return func(o *opts) {
		if code != 0 {
			o.onCommunicationError = func(ctx *fiber.Ctx) { ctx.Status(code) }
		}
	}
}

func WithInternalServerErrorCode(code int) Option {
	return func(o *opts) {
		if code != 0 {
			o.onInternalError = func(ctx *fiber.Ctx) { ctx.Status(code) }
		}
	}
}

func WithMethodErrorCode(code int) Option {
	return func(o *opts) {
		if code != 0 {
			o.onBadMethodError = func(ctx *fiber.Ctx) { ctx.Status(code) }
		}
	}
}

func WithNoRuleErrorCode(code int) Option {
	return func(o *opts) {
		if code != 0 {
			o.onNoRuleError = func(ctx *fiber.Ctx) { ctx.Status(code) }
		}
	}
}

func WithVerboseErrors(flag bool) Option {
	return func(o *opts) {
		o.verboseErrors = flag
	}
}

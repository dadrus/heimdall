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

import (
    "errors"

    "github.com/gofiber/fiber/v2"
    "github.com/rs/zerolog"

    "github.com/dadrus/heimdall/internal/accesscontext"
    "github.com/dadrus/heimdall/internal/heimdall"
)

func New(opts ...Option) fiber.Handler {
    options := defaultOptions

    for _, opt := range opts {
        opt(&options)
    }

    h := &handler{opts: options}

    return h.handle
}

type handler struct {
    opts
}

func (h *handler) handle(ctx *fiber.Ctx) error { //nolint:cyclop
    err := ctx.Next()
    if err == nil {
        return nil
    }

    accesscontext.SetError(ctx.UserContext(), err)

    switch {
    case errors.Is(err, heimdall.ErrAuthentication):
        h.onAuthenticationError(ctx)
    case errors.Is(err, heimdall.ErrAuthorization):
        h.onAuthorizationError(ctx)
    case errors.Is(err, heimdall.ErrCommunicationTimeout) || errors.Is(err, heimdall.ErrCommunication):
        h.onCommunicationError(ctx)
    case errors.Is(err, heimdall.ErrArgument):
        h.onPreconditionError(ctx)
    case errors.Is(err, heimdall.ErrMethodNotAllowed):
        h.onBadMethodError(ctx)
    case errors.Is(err, heimdall.ErrNoRuleFound):
        h.onNoRuleError(ctx)
    case errors.Is(err, &heimdall.RedirectError{}):
        var redirectError *heimdall.RedirectError

        errors.As(err, &redirectError)

        return ctx.Redirect(redirectError.RedirectTo, redirectError.Code)
    default:
        logger := zerolog.Ctx(ctx.UserContext())
        logger.Error().Err(err).Msg("Internal error occurred")

        h.onInternalError(ctx)
    }

    if h.verboseErrors {
        return ctx.Format(err)
    }

    return nil
}

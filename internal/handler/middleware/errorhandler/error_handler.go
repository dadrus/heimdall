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

package errorhandler

import (
	"errors"
	"net/http"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/accesscontext"
	"github.com/dadrus/heimdall/internal/heimdall"
)

//go:generate mockery --name ErrorHandler --structname ErrorHandlerMock

type ErrorHandler interface {
	HandleError(rw http.ResponseWriter, req *http.Request, err error)
}

func New(opts ...Option) ErrorHandler {
	options := defaultOptions()

	for _, opt := range opts {
		opt(options)
	}

	return &errorHandler{opts: options}
}

type errorHandler struct {
	*opts
}

func (h *errorHandler) HandleError(rw http.ResponseWriter, req *http.Request, err error) {
	ctx := req.Context()

	switch {
	case errors.Is(err, heimdall.ErrAuthentication):
		h.onAuthenticationError(rw, req, err)
	case errors.Is(err, heimdall.ErrAuthorization):
		h.onAuthorizationError(rw, req, err)
	case errors.Is(err, heimdall.ErrCommunicationTimeout) || errors.Is(err, heimdall.ErrCommunication):
		h.onCommunicationError(rw, req, err)
	case errors.Is(err, heimdall.ErrArgument):
		h.onPreconditionError(rw, req, err)
	case errors.Is(err, heimdall.ErrMethodNotAllowed):
		h.onBadMethodError(rw, req, err)
	case errors.Is(err, heimdall.ErrNoRuleFound):
		h.onNoRuleError(rw, req, err)
	case errors.Is(err, &heimdall.RedirectError{}):
		var redirectError *heimdall.RedirectError

		errors.As(err, &redirectError)

		rw.Header().Set("Location", redirectError.RedirectTo)
		rw.WriteHeader(redirectError.Code)

		return
	default:
		logger := zerolog.Ctx(ctx)
		logger.Error().Err(err).Msg("Internal error occurred")

		h.onInternalError(rw, req, err)
	}

	accesscontext.SetError(ctx, err)
}

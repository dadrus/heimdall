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
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

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

//nolint:cyclop
func (h *errorHandler) HandleError(rw http.ResponseWriter, req *http.Request, err error) {
	ctx := req.Context()

	switch {
	case errors.Is(err, pipeline.ErrAuthentication):
		h.onAuthenticationError(rw, req, err)
	case errors.Is(err, pipeline.ErrAuthorization):
		h.onAuthorizationError(rw, req, err)
	case errors.Is(err, pipeline.ErrCommunicationTimeout) || errors.Is(err, pipeline.ErrCommunication):
		h.onCommunicationError(rw, req, err)
	case errors.Is(err, pipeline.ErrArgument):
		h.onPreconditionError(rw, req, err)
	case errors.Is(err, pipeline.ErrNoRuleFound):
		h.onNoRuleError(rw, req, err)
	case errors.Is(err, &pipeline.RedirectError{}):
		var redirectError *pipeline.RedirectError

		errors.As(err, &redirectError)

		rw.Header().Set("Location", redirectError.RedirectTo)
		rw.WriteHeader(redirectError.Code)
	case errors.Is(err, &pipeline.GenericError{}):
		var genericError *pipeline.GenericError

		errors.As(err, &genericError)

		for name, values := range genericError.Headers {
			for _, value := range values {
				rw.Header().Add(name, value)
			}
		}

		rw.WriteHeader(genericError.Code)

		if len(genericError.Body) != 0 {
			if _, err := rw.Write(stringx.ToBytes(genericError.Body)); err != nil {
				logger := zerolog.Ctx(ctx)
				logger.Error().Err(err).Msg("Internal error occurred")
			}
		}

		err = genericError.Cause
	default:
		logger := zerolog.Ctx(ctx)
		logger.Error().Err(err).Msg("Internal error occurred")

		h.onInternalError(rw, req, err)
	}

	accesscontext.SetError(ctx, err)
}

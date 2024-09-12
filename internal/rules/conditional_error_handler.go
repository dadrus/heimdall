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

package rules

import (
	"errors"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
)

var errErrorHandlerNotApplicable = errors.New("error handler not applicable")

type conditionalErrorHandler struct {
	h errorHandler
	c executionCondition
}

func (h *conditionalErrorHandler) Execute(ctx heimdall.Context, causeErr error) error {
	logger := zerolog.Ctx(ctx.AppContext())

	logger.Debug().Str("_id", h.h.ID()).Msg("Checking error handler execution condition")

	if canExecute, err := h.c.CanExecuteOnError(ctx, causeErr); err != nil {
		return err
	} else if canExecute {
		return h.h.Execute(ctx, causeErr)
	}

	logger.Debug().Str("_id", h.h.ID()).Msg("Error handler not applicable")

	return errErrorHandlerNotApplicable
}

func (h *conditionalErrorHandler) ID() string { return h.h.ID() }

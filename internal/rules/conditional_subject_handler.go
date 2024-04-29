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
	"github.com/goccy/go-json"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/subject"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

type conditionalSubjectHandler struct {
	h subjectHandler
	c executionCondition
}

func (h *conditionalSubjectHandler) Execute(ctx heimdall.Context, sub subject.Subject) error {
	logger := zerolog.Ctx(ctx.AppContext())

	logger.Debug().Str("_id", h.h.ID()).Msg("Checking execution condition")

	if logger.GetLevel() == zerolog.TraceLevel {
		dump, err := json.Marshal(sub)
		if err != nil {
			logger.Trace().Err(err).Msg("Failed to dump subject")
		} else {
			logger.Trace().Msg("Subject: \n" + stringx.ToString(dump))
		}
	}

	if canExecute, err := h.c.CanExecute(ctx, sub); err != nil {
		return err
	} else if canExecute {
		return h.h.Execute(ctx, sub)
	}

	logger.Debug().Str("_id", h.h.ID()).Msg("Execution skipped")

	return nil
}

func (h *conditionalSubjectHandler) ID() string { return h.h.ID() }

func (h *conditionalSubjectHandler) ContinueOnError() bool { return h.h.ContinueOnError() }

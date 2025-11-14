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
	"github.com/dadrus/heimdall/internal/rules/mechanisms/identity"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

type conditionalStep struct {
	h heimdall.Step
	c executionCondition
}

func (s *conditionalStep) Execute(ctx heimdall.Context, sub identity.Subject) error {
	logger := zerolog.Ctx(ctx.Context())

	logger.Debug().Str("_id", s.h.ID()).Msg("Checking execution condition")

	if logger.GetLevel() == zerolog.TraceLevel {
		dump, err := json.Marshal(sub)
		if err != nil {
			logger.Trace().Err(err).Msg("Failed to dump identity")
		} else {
			logger.Trace().Msg("Subject: \n" + stringx.ToString(dump))
		}
	}

	if canExecute, err := s.c.CanExecuteOnSubject(ctx, sub); err != nil {
		return err
	} else if canExecute {
		return s.h.Execute(ctx, sub)
	}

	logger.Debug().Str("_id", s.h.ID()).Msg("Execution skipped")

	return nil
}

func (s *conditionalStep) ID() string { return s.h.ID() }

func (s *conditionalStep) IsInsecure() bool { return s.h.IsInsecure() }

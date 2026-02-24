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

	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

type conditionalStep struct {
	s pipeline.Step
	c executionCondition
}

func newConditionalStep(s pipeline.Step, c executionCondition) *conditionalStep {
	return &conditionalStep{s: s, c: c}
}

func (s *conditionalStep) Accept(visitor pipeline.Visitor) { s.s.Accept(visitor) }

func (s *conditionalStep) Execute(ctx pipeline.Context, sub pipeline.Subject) error {
	logger := zerolog.Ctx(ctx.Context())

	logger.Debug().Str("_id", s.s.ID()).Msg("Checking execution condition")

	if logger.GetLevel() == zerolog.TraceLevel {
		if dump, err := json.Marshal(sub); err != nil {
			logger.Trace().Err(err).Msg("Failed to dump identity")
		} else {
			logger.Trace().Msg("Subject: \n" + stringx.ToString(dump))
		}
	}

	if canExecute, err := s.c.CanExecuteOnSubject(ctx, sub); err != nil {
		return err
	} else if canExecute {
		return s.s.Execute(ctx, sub)
	}

	logger.Debug().Str("_id", s.s.ID()).Msg("Execution skipped")

	return nil
}

func (s *conditionalStep) ID() string                   { return s.s.ID() }
func (s *conditionalStep) Type() string                 { return s.s.Type() }
func (s *conditionalStep) Kind() pipeline.MechanismKind { return s.s.Kind() }

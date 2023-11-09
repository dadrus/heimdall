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
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type ruleExecutor struct {
	r rule.Repository
}

func newRuleExecutor(repository rule.Repository) rule.Executor {
	return &ruleExecutor{r: repository}
}

func (e *ruleExecutor) Execute(ctx heimdall.Context) (rule.Backend, error) {
	req := ctx.Request()

	//nolint:contextcheck
	zerolog.Ctx(ctx.AppContext()).Debug().
		Str("_method", req.Method).
		Str("_url", req.URL.String()).
		Msg("Analyzing request")

	rul, err := e.r.FindRule(req.URL)
	if err != nil {
		return nil, err
	}

	method := ctx.Request().Method
	if !rul.MatchesMethod(method) {
		return nil, errorchain.NewWithMessagef(heimdall.ErrMethodNotAllowed,
			"rule (id=%s, src=%s) doesn't match %s method", rul.ID(), rul.SrcID(), method)
	}

	return rul.Execute(ctx)
}

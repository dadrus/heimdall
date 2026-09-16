// Copyright 2026 Dimitrij Drus <dadrus@gmx.de>
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

package validate

import (
	"context"

	"github.com/go-jose/go-jose/v4"

	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/secrets"
)

type noopRepository struct{}

func (noopRepository) FindRule(_ pipeline.Context) (rule.Rule, error) {
	return nil, errFunctionNotSupported
}

func (noopRepository) AddRuleSet(_ context.Context, _ rule.RuleSet, _ []rule.Rule) error { return nil }

func (noopRepository) UpdateRuleSet(_ context.Context, _ rule.RuleSet, _ []rule.Rule) error {
	return errFunctionNotSupported
}

func (noopRepository) DeleteRuleSet(_ context.Context, _ rule.RuleSet) error {
	return errFunctionNotSupported
}

type noopRegistry struct{}

func (noopRegistry) Notify(_ secrets.Reference) {}
func (noopRegistry) Keys() []jose.JSONWebKey    { return nil }

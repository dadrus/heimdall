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

package rule

import (
	"context"

	"github.com/dadrus/heimdall/internal/rules/config"
)

//go:generate mockery --name SetProcessor --structname RuleSetProcessorMock

type SetProcessor interface {
	OnCreated(ctx context.Context, ruleSet *config.RuleSet) error
	OnUpdated(ctx context.Context, ruleSet *config.RuleSet) error
	OnDeleted(ctx context.Context, ruleSet *config.RuleSet) error
}

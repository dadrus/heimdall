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

package authorizers

import (
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
)

// by intention. Used only during application bootstrap
//
//nolint:gochecknoinits
func init() {
	registerTypeFactory(
		func(ctx CreationContext, id string, typ string, _ map[string]any) (bool, Authorizer, error) {
			if typ != AuthorizerAllow {
				return false, nil, nil
			}

			return true, newAllowAuthorizer(id), nil
		})
}

type allowAuthorizer struct {
	id string
}

func newAllowAuthorizer(id string) *allowAuthorizer {
	return &allowAuthorizer{id: id}
}

func (a *allowAuthorizer) Execute(ctx heimdall.Context, _ *subject.Subject) error {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Str("_id", a.id).Msg("Authorizing using allow authorizer")

	return nil
}

func (a *allowAuthorizer) WithConfig(map[string]any) (Authorizer, error) {
	return a, nil
}

func (a *allowAuthorizer) ID() string { return a.id }

func (a *allowAuthorizer) ContinueOnError() bool { return false }

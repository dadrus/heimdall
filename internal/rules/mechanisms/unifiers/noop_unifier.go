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

package unifiers

import (
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
)

// by intention. Used only during application bootstrap
// nolint
func init() {
	registerUnifierTypeFactory(
		func(id string, typ string, conf map[string]any) (bool, Unifier, error) {
			if typ != UnifierNoop {
				return false, nil, nil
			}

			return true, newNoopUnifier(id), nil
		})
}

func newNoopUnifier(id string) *noopUnifier { return &noopUnifier{id: id} }

type noopUnifier struct {
	id string
}

func (m *noopUnifier) Execute(ctx heimdall.Context, sub *subject.Subject) error {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Unifying using noop unifier")

	return nil
}

func (m *noopUnifier) WithConfig(map[string]any) (Unifier, error) { return m, nil }

func (m *noopUnifier) HandlerID() string { return m.id }

func (m *noopUnifier) ContinueOnError() bool { return false }

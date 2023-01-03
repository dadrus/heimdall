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

package mocks

import (
	"net/url"

	"github.com/stretchr/testify/mock"

	"github.com/dadrus/heimdall/internal/rules/rule"
)

type MockRepository struct {
	mock.Mock
}

func (m *MockRepository) FindRule(reqURL *url.URL) (rule.Rule, error) {
	args := m.Called(reqURL)

	if val := args.Get(0); val != nil {
		// nolint: forcetypeassert
		return val.(rule.Rule), nil
	}

	return nil, args.Error(1)
}

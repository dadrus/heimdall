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
	"github.com/stretchr/testify/mock"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
)

type MockAuthenticator struct {
	mock.Mock
}

func (m *MockAuthenticator) Execute(ctx heimdall.Context) (*subject.Subject, error) {
	args := m.Called(ctx)

	if val := args.Get(0); val != nil {
		// nolint: forcetypeassert
		return val.(*subject.Subject), nil
	}

	return nil, args.Error(1)
}

func (m *MockAuthenticator) WithConfig(config map[string]any) (authenticators.Authenticator, error) {
	args := m.Called(config)

	if val := args.Get(0); val != nil {
		// nolint: forcetypeassert
		return val.(authenticators.Authenticator), nil
	}

	return nil, args.Error(1)
}

func (m *MockAuthenticator) IsFallbackOnErrorAllowed() bool {
	return m.Called().Bool(0)
}

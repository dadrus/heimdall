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

	"github.com/dadrus/heimdall/internal/heimdall"
)

type MockRule struct {
	mock.Mock
}

func (m *MockRule) ID() string                       { return m.Called().String(0) }
func (m *MockRule) SrcID() string                    { return m.Called().String(0) }
func (m *MockRule) MatchesMethod(method string) bool { return m.Called(method).Bool(0) }
func (m *MockRule) MatchesURL(reqURL *url.URL) bool  { return m.Called(reqURL).Bool(0) }

func (m *MockRule) Execute(ctx heimdall.Context) (*url.URL, error) {
	args := m.Called(ctx)

	if val := args.Get(0); val != nil {
		return val.(*url.URL), nil // nolint: forcetypeassert
	}

	return nil, args.Error(1)
}

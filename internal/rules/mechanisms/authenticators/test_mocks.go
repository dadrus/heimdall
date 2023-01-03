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

package authenticators

import (
	"net/http"

	"github.com/stretchr/testify/mock"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators/extractors"
)

type dummyAuthData struct {
	Val string
}

func (c dummyAuthData) ApplyTo(req *http.Request) { req.Header.Add("Dummy", c.Val) }
func (c dummyAuthData) Value() string             { return c.Val }

type mockAuthDataGetter struct {
	mock.Mock
}

func (m *mockAuthDataGetter) GetAuthData(s heimdall.Context) (extractors.AuthData, error) {
	args := m.Called(s)

	if val := args.Get(0); val != nil {
		res, ok := val.(extractors.AuthData)
		if !ok {
			panic("extractors.AuthData expected")
		}

		return res, args.Error(1)
	}

	return nil, args.Error(1)
}

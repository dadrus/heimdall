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
	"time"

	"github.com/stretchr/testify/mock"
)

type MockCache struct {
	mock.Mock
}

func (m *MockCache) Start() { m.Called() }

func (m *MockCache) Stop() { m.Called() }

func (m *MockCache) Get(key string) any { return m.Called(key).Get(0) }

func (m *MockCache) Set(key string, value any, ttl time.Duration) { m.Called(key, value, ttl) }

func (m *MockCache) Delete(key string) { m.Called(key) }

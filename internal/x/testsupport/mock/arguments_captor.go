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

package mock

import "github.com/stretchr/testify/mock"

type ArgumentsCaptor struct {
	capturedArgs []mock.Arguments
}

func NewArgumentsCaptor(m *mock.Mock, name string) *ArgumentsCaptor {
	captor := &ArgumentsCaptor{}

	m.TestData().Set(name, captor)

	return captor
}

func (c *ArgumentsCaptor) Capture(args mock.Arguments) {
	c.capturedArgs = append(c.capturedArgs, args)
}

func (c *ArgumentsCaptor) Values(call int) mock.Arguments {
	if len(c.capturedArgs)-1 >= call {
		return c.capturedArgs[call]
	}

	return nil
}

func ArgumentsCaptorFrom(m *mock.Mock, name string) *ArgumentsCaptor {
	return m.TestData().Get(name).Data().(*ArgumentsCaptor) // nolint: forcetypeassert
}

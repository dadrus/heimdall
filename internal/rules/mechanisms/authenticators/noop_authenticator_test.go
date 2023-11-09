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
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall/mocks"
)

func TestNoopAuthenticatorExecution(t *testing.T) {
	t.Parallel()

	// GIVEN
	ctx := mocks.NewContextMock(t)
	ctx.EXPECT().AppContext().Return(context.Background())

	auth := newNoopAuthenticator("test")

	// WHEN
	sub, err := auth.Execute(ctx)

	// THEN
	require.NoError(t, err)
	require.NotNil(t, sub)
	assert.Empty(t, sub)
}

func TestCreateNoopAuthenticatorFromPrototype(t *testing.T) {
	t.Parallel()

	// GIVEN
	prototype := newNoopAuthenticator("test")

	// WHEN
	auth1, err1 := prototype.WithConfig(nil)
	auth2, err2 := prototype.WithConfig(map[string]any{"foo": "bar"})

	// THEN
	require.NoError(t, err1)
	assert.Equal(t, prototype, auth1)

	require.NoError(t, err2)
	assert.Equal(t, prototype, auth2)
}

func TestNoopAuthenticatorIsFallbackOnErrorAllowed(t *testing.T) {
	t.Parallel()

	// GIVEN
	auth := newNoopAuthenticator("test")

	// WHEN
	isAllowed := auth.IsFallbackOnErrorAllowed()

	// THEN
	require.False(t, isAllowed)
}

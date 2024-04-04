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

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/subject"
)

func TestUnauthorizedAuthenticatorExecution(t *testing.T) {
	t.Parallel()
	// GIVEN
	var identifier interface{ ID() string }

	sub := subject.Subject{}

	ctx := mocks.NewContextMock(t)
	ctx.EXPECT().AppContext().Return(context.Background())

	auth := newUnauthorizedAuthenticator("unauth")

	// WHEN
	err := auth.Execute(ctx, sub)

	// THEN
	require.ErrorIs(t, err, heimdall.ErrAuthentication)
	require.ErrorContains(t, err, "denied by authenticator")

	require.ErrorAs(t, err, &identifier)
	assert.Equal(t, "unauth", identifier.ID())
}

func TestCreateUnauthorizedAuthenticatorFromPrototype(t *testing.T) {
	t.Parallel()
	// GIVEN
	prototype := newUnauthorizedAuthenticator("unauth")

	// WHEN
	auth, err := prototype.WithConfig(nil)

	// THEN
	require.NoError(t, err)

	uaa, ok := auth.(*unauthorizedAuthenticator)
	require.True(t, ok)

	// prototype and "created" authenticator are same
	assert.Equal(t, prototype, uaa)
	assert.Equal(t, "unauth", uaa.ID())
}

func TestUnauthorizedAuthenticatorIsFallbackOnErrorAllowed(t *testing.T) {
	t.Parallel()

	// GIVEN
	auth := newUnauthorizedAuthenticator("unauth")

	// WHEN
	isAllowed := auth.ContinueOnError()

	// THEN
	require.False(t, isAllowed)
	require.Equal(t, "unauth", auth.ID())
}

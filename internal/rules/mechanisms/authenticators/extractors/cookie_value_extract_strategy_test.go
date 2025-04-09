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

package extractors

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
)

func TestExtractExistingCookieValue(t *testing.T) {
	t.Parallel()

	// GIVEN
	cookieName := "Test-Cookie"
	cookieValue := "foo"

	fnt := mocks.NewRequestFunctionsMock(t)
	fnt.EXPECT().Cookie(cookieName).Return(cookieValue)

	ctx := mocks.NewRequestContextMock(t)
	ctx.EXPECT().Request().Return(&heimdall.Request{RequestFunctions: fnt})

	strategy := CookieValueExtractStrategy{Name: cookieName}

	// WHEN
	val, err := strategy.GetAuthData(ctx)

	// THEN
	require.NoError(t, err)
	assert.Equal(t, cookieValue, val)
}

func TestExtractNotExistingCookieValue(t *testing.T) {
	t.Parallel()

	// GIVEN
	fnt := mocks.NewRequestFunctionsMock(t)
	fnt.EXPECT().Cookie(mock.Anything).Return("")

	ctx := mocks.NewRequestContextMock(t)
	ctx.EXPECT().Request().Return(&heimdall.Request{RequestFunctions: fnt})

	strategy := CookieValueExtractStrategy{Name: "Test-Cookie"}

	// WHEN
	_, err := strategy.GetAuthData(ctx)

	// THEN
	require.Error(t, err)
	require.ErrorIs(t, err, heimdall.ErrArgument)
}

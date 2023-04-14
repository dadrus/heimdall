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
	"context"
	"net/http"
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
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "foobar.local", nil)
	require.NoError(t, err)

	ctx := &mocks.ContextMock{}
	ctx.On("RequestCookie", cookieName).Return(cookieValue)

	strategy := CookieValueExtractStrategy{Name: cookieName}

	// WHEN
	val, err := strategy.GetAuthData(ctx)

	// THEN
	assert.NoError(t, err)
	assert.Equal(t, cookieValue, val.Value())

	val.ApplyTo(req)
	cookie, err := req.Cookie(cookieName)
	assert.NoError(t, err)
	assert.Equal(t, cookieValue, cookie.Value)

	assert.Equal(t, cookie.Value, val.Value())

	ctx.AssertExpectations(t)
}

func TestExtractNotExistingCookieValue(t *testing.T) {
	t.Parallel()

	// GIVEN
	ctx := &mocks.ContextMock{}
	ctx.On("RequestCookie", mock.Anything).Return("")

	strategy := CookieValueExtractStrategy{Name: "Test-Cookie"}

	// WHEN
	_, err := strategy.GetAuthData(ctx)

	// THEN
	assert.Error(t, err)
	assert.ErrorIs(t, err, heimdall.ErrArgument)

	ctx.AssertExpectations(t)
}

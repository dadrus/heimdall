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

	"github.com/dadrus/heimdall/internal/heimdall/mocks"
)

func TestCompositeExtractCookieValueWithoutSchema(t *testing.T) {
	t.Parallel()

	// GIVEN
	headerName := "test-header"
	cookieName := "Test-Cookie"
	actualValue := "foo"

	ctx := &mocks.ContextMock{}
	ctx.On("RequestCookie", cookieName).Return(actualValue)
	ctx.On("RequestHeader", headerName).Return("")

	strategy := CompositeExtractStrategy{
		HeaderValueExtractStrategy{Name: headerName},
		CookieValueExtractStrategy{Name: cookieName},
	}

	// WHEN
	val, err := strategy.GetAuthData(ctx)

	// THEN
	assert.NoError(t, err)
	assert.Equal(t, actualValue, val.Value())
	ctx.AssertExpectations(t)
}

func TestCompositeExtractHeaderValueWithSchema(t *testing.T) {
	t.Parallel()

	// GIVEN
	headerName := "Test-Header"
	queryParamName := "test_param"
	headerSchema := "bar:"
	actualValue := "foo"

	ctx := &mocks.ContextMock{}
	ctx.On("RequestHeader", headerName).Return(headerSchema + " " + actualValue)
	ctx.On("RequestQueryParameter", queryParamName).Return("")

	strategy := CompositeExtractStrategy{
		QueryParameterExtractStrategy{Name: queryParamName},
		HeaderValueExtractStrategy{Name: headerName, Schema: headerSchema},
	}

	// WHEN
	val, err := strategy.GetAuthData(ctx)

	// THEN
	assert.NoError(t, err)
	assert.Equal(t, actualValue, val.Value())
	ctx.AssertExpectations(t)
}

func TestCompositeExtractStrategyOrder(t *testing.T) {
	t.Parallel()

	// GIVEN
	headerName := "Test-Header"
	queryParamName := "test_param"
	headerSchema := "bar:"
	actualValue := "foo"

	ctx := &mocks.ContextMock{}
	ctx.On("RequestHeader", headerName).Return(headerSchema + " " + actualValue)

	strategy := CompositeExtractStrategy{
		HeaderValueExtractStrategy{Name: headerName, Schema: headerSchema},
		QueryParameterExtractStrategy{Name: queryParamName},
	}

	// WHEN
	val, err := strategy.GetAuthData(ctx)

	// THEN
	assert.NoError(t, err)
	assert.Equal(t, actualValue, val.Value())
	ctx.AssertExpectations(t)
}

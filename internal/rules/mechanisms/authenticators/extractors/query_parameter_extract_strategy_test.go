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
	"fmt"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
)

func TestExtractQueryParameter(t *testing.T) {
	t.Parallel()

	// GIVEN
	queryParam := "test_param"
	queryParamValue := "foo"

	fnt := mocks.NewRequestFunctionsMock(t)

	ctx := mocks.NewContextMock(t)
	ctx.EXPECT().Request().Return(&heimdall.Request{
		RequestFunctions: fnt,
		URL:              &url.URL{RawQuery: fmt.Sprintf("%s=%s", queryParam, queryParamValue)},
	})

	strategy := QueryParameterExtractStrategy{Name: queryParam}

	// WHEN
	val, err := strategy.GetAuthData(ctx)

	// THEN
	require.NoError(t, err)
	assert.Equal(t, queryParamValue, val)
}

func TestExtractNotExistingQueryParameterValue(t *testing.T) {
	t.Parallel()

	// GIVEN
	fnt := mocks.NewRequestFunctionsMock(t)

	ctx := mocks.NewContextMock(t)
	ctx.EXPECT().Request().Return(&heimdall.Request{
		RequestFunctions: fnt,
		URL:              &url.URL{},
	})

	strategy := QueryParameterExtractStrategy{Name: "Test-Cookie"}

	// WHEN
	_, err := strategy.GetAuthData(ctx)

	// THEN
	require.Error(t, err)
	require.ErrorIs(t, err, heimdall.ErrArgument)
}

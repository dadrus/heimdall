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

package rules

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall/mocks"
	rulemocks "github.com/dadrus/heimdall/internal/rules/mocks"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestCompositeErrorHandlerExecutionWithFallback(t *testing.T) {
	t.Parallel()

	// GIVEN
	ctx := mocks.NewContextMock(t)
	ctx.EXPECT().AppContext().Return(context.Background())

	eh1 := rulemocks.NewErrorHandlerMock(t)
	eh1.EXPECT().Execute(ctx, testsupport.ErrTestPurpose).Return(false, nil)

	eh2 := rulemocks.NewErrorHandlerMock(t)
	eh2.EXPECT().Execute(ctx, testsupport.ErrTestPurpose).Return(true, nil)

	eh := compositeErrorHandler{eh1, eh2}

	// WHEN
	ok, err := eh.Execute(ctx, testsupport.ErrTestPurpose)

	// THEN
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestCompositeErrorHandlerExecutionWithoutFallback(t *testing.T) {
	t.Parallel()

	// GIVEN
	ctx := mocks.NewContextMock(t)
	ctx.EXPECT().AppContext().Return(context.Background())

	eh1 := rulemocks.NewErrorHandlerMock(t)
	eh1.EXPECT().Execute(ctx, testsupport.ErrTestPurpose).Return(true, nil)

	eh2 := rulemocks.NewErrorHandlerMock(t)

	eh := compositeErrorHandler{eh1, eh2}

	// WHEN
	ok, err := eh.Execute(ctx, testsupport.ErrTestPurpose)

	// THEN
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestCompositeErrorHandlerExecutionWithNoApplicableErrorHandler(t *testing.T) {
	t.Parallel()

	// GIVEN
	ctx := mocks.NewContextMock(t)
	ctx.EXPECT().AppContext().Return(context.Background())

	eh1 := rulemocks.NewErrorHandlerMock(t)
	eh1.EXPECT().Execute(ctx, testsupport.ErrTestPurpose).Return(false, nil)

	eh2 := rulemocks.NewErrorHandlerMock(t)
	eh2.EXPECT().Execute(ctx, testsupport.ErrTestPurpose).Return(false, nil)

	eh := compositeErrorHandler{eh1, eh2}

	// WHEN
	ok, err := eh.Execute(ctx, testsupport.ErrTestPurpose)

	// THEN
	require.Error(t, err)
	assert.False(t, ok)
}

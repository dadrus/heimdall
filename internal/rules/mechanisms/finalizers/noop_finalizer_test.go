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

package finalizers

import (
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
)

func TestNoopFinalizerExecution(t *testing.T) {
	t.Parallel()

	// GIVEN
	appCtx := app.NewContextMock(t)
	appCtx.EXPECT().Logger().Return(log.Logger)

	ctx := mocks.NewRequestContextMock(t)
	ctx.EXPECT().Context().Return(t.Context())

	finalizer := newNoopFinalizer(appCtx, "foo")

	// WHEN
	err := finalizer.Execute(ctx, nil)

	// THEN
	require.NoError(t, err)
	assert.Equal(t, "foo", finalizer.ID())
	assert.False(t, finalizer.ContinueOnError())
}

func TestCreateNoopFinalizerFromPrototype(t *testing.T) {
	t.Parallel()

	// GIVEN
	appCtx := app.NewContextMock(t)
	appCtx.EXPECT().Logger().Return(log.Logger)

	prototype := newNoopFinalizer(appCtx, "baz")

	// WHEN
	fin1, err1 := prototype.WithConfig(nil)
	fin2, err2 := prototype.WithConfig(map[string]any{"foo": "bar"})

	// THEN
	require.NoError(t, err1)
	assert.Equal(t, prototype, fin1)

	require.NoError(t, err2)
	assert.Equal(t, prototype, fin2)
}

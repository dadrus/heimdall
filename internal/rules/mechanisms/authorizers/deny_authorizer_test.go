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

package authorizers

import (
	"context"
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
)

func TestCreateDenyAuthorizerFromPrototype(t *testing.T) {
	// GIVEN
	appCtx := app.NewContextMock(t)
	appCtx.EXPECT().Logger().Return(log.Logger)

	prototype := newDenyAuthorizer(appCtx, "foo")

	// WHEN
	conf1, err1 := prototype.WithConfig(nil)
	conf2, err2 := prototype.WithConfig(map[string]any{"foo": "bar"})

	// THEN
	require.NoError(t, err1)
	require.NoError(t, err2)

	assert.Equal(t, prototype, conf1)
	assert.Equal(t, prototype, conf2)

	assert.IsType(t, &denyAuthorizer{}, conf1)
	assert.IsType(t, &denyAuthorizer{}, conf2)

	// nolint: forcetypeassert
	assert.Equal(t, "foo", conf1.(*denyAuthorizer).ID())
	assert.False(t, conf1.ContinueOnError())
	assert.False(t, conf2.ContinueOnError())
	assert.False(t, prototype.ContinueOnError())
}

func TestDenyAuthorizerExecute(t *testing.T) {
	// GIVEN
	var identifier interface{ ID() string }

	ctx := mocks.NewRequestContextMock(t)
	ctx.EXPECT().Context().Return(context.Background())

	appCtx := app.NewContextMock(t)
	appCtx.EXPECT().Logger().Return(log.Logger)

	auth := newDenyAuthorizer(appCtx, "bar")

	// WHEN
	err := auth.Execute(ctx, nil)

	// THEN
	require.Error(t, err)
	require.ErrorIs(t, err, heimdall.ErrAuthorization)
	require.Contains(t, err.Error(), "denied by authorizer")

	require.ErrorAs(t, err, &identifier)
	assert.Equal(t, "bar", identifier.ID())
}

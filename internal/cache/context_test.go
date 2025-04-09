// Copyright 2024 Dimitrij Drus <dadrus@gmx.de>
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

package cache

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/cache/mocks"
	"github.com/dadrus/heimdall/internal/cache/noop"
)

func TestContextNoCacheConfigured(t *testing.T) {
	t.Parallel()

	// WHEN
	cch := Ctx(t.Context())

	// THEN
	require.NotNil(t, cch)
	assert.IsType(t, &noop.Cache{}, cch)
}

func TestContextCacheConfigured(t *testing.T) {
	t.Parallel()

	// GIVEN
	cache := mocks.NewCacheMock(t)
	ctx := WithContext(t.Context(), cache)

	// WHEN
	cch := Ctx(ctx)

	// THEN
	require.NotNil(t, cch)
	assert.IsType(t, &mocks.CacheMock{}, cch)
}

func TestContextCacheIsNotConfiguredTwice(t *testing.T) {
	t.Parallel()

	// GIVEN
	cch1 := mocks.NewCacheMock(t)
	cch2 := mocks.NewCacheMock(t)

	ctx := t.Context()

	// WHEN
	ctx1 := WithContext(ctx, cch1)
	ctx2 := WithContext(ctx1, cch1)
	ctx3 := WithContext(ctx2, cch2)

	// THEN
	assert.Equal(t, ctx1, ctx2)
	assert.NotEqual(t, ctx2, ctx3)

	assert.Equal(t, cch1, Ctx(ctx1))
	assert.Equal(t, cch1, Ctx(ctx2))
	assert.Equal(t, cch2, Ctx(ctx3))
}

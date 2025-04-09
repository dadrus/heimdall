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

package redis

import (
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/validation"
)

func TestCacheUsage(t *testing.T) {
	t.Parallel()

	validator, err := validation.NewValidator(
		validation.WithTagValidator(config.EnforcementSettings{}),
	)
	require.NoError(t, err)

	appCtx := app.NewContextMock(t)
	appCtx.EXPECT().Validator().Return(validator)

	db := miniredis.RunT(t)
	cch, err := NewStandaloneCache(
		appCtx,
		map[string]any{
			"address":      db.Addr(),
			"client_cache": map[string]any{"disabled": true},
			"tls":          map[string]any{"disabled": true},
		},
	)
	require.NoError(t, err)

	err = cch.Start(t.Context())
	require.NoError(t, err)

	defer cch.Stop(t.Context())

	for uc, tc := range map[string]struct {
		uc             string
		key            string
		configureCache func(*testing.T, cache.Cache)
		assert         func(t *testing.T, err error, data []byte)
	}{
		"can retrieve not expired value": {
			key: "foo",
			configureCache: func(t *testing.T, cch cache.Cache) {
				t.Helper()

				err := cch.Set(t.Context(), "foo", []byte("bar"), 10*time.Minute)
				require.NoError(t, err)
			},
			assert: func(t *testing.T, err error, data []byte) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, []byte("bar"), data)
			},
		},
		"cannot retrieve expired value": {
			key: "bar",
			configureCache: func(t *testing.T, cch cache.Cache) {
				t.Helper()

				err := cch.Set(t.Context(), "bar", []byte("baz"), 1*time.Millisecond)
				require.NoError(t, err)

				db.FastForward(200 * time.Millisecond)
			},
			assert: func(t *testing.T, err error, data []byte) {
				t.Helper()

				require.Error(t, err)
				assert.Nil(t, data)
			},
		},
		"cannot retrieve not existing value": {
			key: "baz",
			configureCache: func(t *testing.T, _ cache.Cache) {
				t.Helper()
			},
			assert: func(t *testing.T, err error, data []byte) {
				t.Helper()

				require.Error(t, err)
				assert.Nil(t, data)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// WHEN
			tc.configureCache(t, cch)

			data, err := cch.Get(t.Context(), tc.key)

			// THEN
			tc.assert(t, err, data)
		})
	}
}

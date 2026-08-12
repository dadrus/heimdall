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

package authstrategy

import (
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApplyBasicAuthStrategy(t *testing.T) {
	t.Parallel()

	// GIVEN
	user := "Foo"
	password := "Bar"
	expectedValue := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))

	original := &http.Request{
		Header: http.Header{
			"X-Test": []string{"foo"},
		},
	}

	req := *original
	s := BasicAuth{User: user, Password: password}

	// WHEN
	err := s.Apply(&req)

	// THEN
	require.NoError(t, err)

	assert.Equal(t, expectedValue, req.Header.Get("Authorization"))
	assert.Equal(t, "foo", req.Header.Get("X-Test"))

	assert.Empty(t, original.Header.Get("Authorization"))
	assert.Equal(t, "foo", original.Header.Get("X-Test"))
}

func TestBasicAuthStrategyHash(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		strategy1   *BasicAuth
		strategy2   *BasicAuth
		expectEqual bool
	}{
		"same configuration": {
			strategy1:   &BasicAuth{User: "Foo", Password: "Bar"},
			strategy2:   &BasicAuth{User: "Foo", Password: "Bar"},
			expectEqual: true,
		},
		"different user": {
			strategy1: &BasicAuth{User: "Foo", Password: "Bar"},
			strategy2: &BasicAuth{User: "Baz", Password: "Bar"},
		},
		"different password": {
			strategy1: &BasicAuth{User: "Foo", Password: "Bar"},
			strategy2: &BasicAuth{User: "Foo", Password: "Baz"},
		},
		"field boundaries are preserved": {
			strategy1: &BasicAuth{User: "a", Password: "bc"},
			strategy2: &BasicAuth{User: "ab", Password: "c"},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// WHEN
			hash1 := tc.strategy1.Hash()
			hash2 := tc.strategy2.Hash()

			// THEN
			assert.NotEmpty(t, hash1)
			assert.NotEmpty(t, hash2)

			if tc.expectEqual {
				assert.Equal(t, hash1, hash2)
			} else {
				assert.NotEqual(t, hash1, hash2)
			}
		})
	}
}

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
	"context"
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
	req := &http.Request{Header: http.Header{}}
	s := BasicAuth{User: user, Password: password}

	// WHEN
	err := s.Apply(context.Background(), req)

	// THEN
	require.NoError(t, err)
	assert.Equal(t, expectedValue, req.Header.Get("Authorization"))
}

func TestBasicAuthStrategyHash(t *testing.T) {
	t.Parallel()

	// GIVEN
	s1 := &BasicAuth{User: "Foo", Password: "Bar"}
	s2 := &BasicAuth{User: "Foo", Password: "Baz"}

	// WHEN
	hash1 := s1.Hash()
	hash2 := s2.Hash()

	// THEN
	assert.NotEmpty(t, hash1)
	assert.NotEmpty(t, hash2)
	assert.NotEqual(t, hash1, hash2)
}

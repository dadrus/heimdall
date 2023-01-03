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

package endpoint

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestApplyApiKeyStrategyOnHeader(t *testing.T) {
	t.Parallel()

	// GIVEN
	name := "Foo"
	value := "Bar"
	req := &http.Request{Header: http.Header{}}
	s := APIKeyStrategy{Name: name, Value: value, In: "header"}

	// WHEN
	err := s.Apply(context.Background(), req)

	// THEN
	assert.NoError(t, err)
	assert.Equal(t, value, req.Header.Get(name))
}

func TestApplyApiKeyStrategyOnCookie(t *testing.T) {
	t.Parallel()

	// GIVEN
	name := "Foo"
	value := "Bar"
	req := &http.Request{Header: http.Header{}}
	s := APIKeyStrategy{Name: name, Value: value, In: "cookie"}

	// WHEN
	err := s.Apply(context.Background(), req)

	// THEN
	assert.NoError(t, err)

	cookie, err := req.Cookie(name)
	assert.NoError(t, err)
	assert.Equal(t, value, cookie.Value)
}

func TestAPIKeyStrategyHash(t *testing.T) {
	t.Parallel()

	// GIVEN
	s1 := &APIKeyStrategy{In: "header", Name: "Foo", Value: "Bar"}
	s2 := &APIKeyStrategy{In: "cookie", Name: "Foo", Value: "Bar"}

	// WHEN
	hash1 := s1.Hash()
	hash2 := s2.Hash()

	// THEN
	assert.NotEmpty(t, hash1)
	assert.NotEmpty(t, hash2)
	assert.NotEqual(t, hash1, hash2)
}

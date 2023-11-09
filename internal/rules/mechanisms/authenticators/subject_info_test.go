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

package authenticators

import (
	"testing"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
)

func TestSubjectInfoCreateSubject(t *testing.T) {
	t.Parallel()

	type Nested struct {
		Val bool `json:"val"`
	}

	type Complex struct {
		Array  []int  `json:"array"`
		Nested Nested `json:"nested"`
	}

	type IDT struct {
		Subject             string   `json:"subject"`
		SomeStringAttribute string   `json:"some_string_attribute"`
		SomeInt64Attribute  int64    `json:"some_int_64_attribute"`
		StringSlice         []string `json:"string_slice"`
		Complex             Complex  `json:"complex"`
	}

	id := IDT{
		Subject:             "foo",
		SomeStringAttribute: "attr",
		SomeInt64Attribute:  -6,
		StringSlice:         []string{"val1", "val2"},
		Complex: Complex{
			Array:  []int{1, 2, 3},
			Nested: Nested{Val: true},
		},
	}

	raw, err := json.Marshal(id)
	require.NoError(t, err)

	for _, tc := range []struct {
		uc        string
		configure func(t *testing.T, s *SubjectInfo)
		assert    func(t *testing.T, err error, sub *subject.Subject)
	}{
		{
			uc: "subject is extracted and attributes are the whole object",
			configure: func(t *testing.T, s *SubjectInfo) {
				t.Helper()

				s.IDFrom = "subject"
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, "foo", sub.ID)

				var attrs map[string]interface{}
				e := json.Unmarshal(raw, &attrs)
				require.NoError(t, e)
				assert.Equal(t, attrs, sub.Attributes)
			},
		},
		{
			uc: "subject is extracted and attributes are the nested object",
			configure: func(t *testing.T, s *SubjectInfo) {
				t.Helper()

				s.IDFrom = "string_slice.1"
				s.AttributesFrom = "complex.nested"
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, "val2", sub.ID)

				rawNested, err := json.Marshal(id.Complex.Nested)
				require.NoError(t, err)

				var attrs map[string]interface{}
				e := json.Unmarshal(rawNested, &attrs)
				require.NoError(t, e)
				assert.Equal(t, attrs, sub.Attributes)
			},
		},
		{
			uc: "attributes could no be extracted",
			configure: func(t *testing.T, s *SubjectInfo) {
				t.Helper()

				s.IDFrom = "subject"
				s.AttributesFrom = "foobar"
			},
			assert: func(t *testing.T, err error, _ *subject.Subject) {
				t.Helper()
				require.Error(t, err)
				require.ErrorContains(t, err, "could not extract attributes")
			},
		},
		{
			uc: "subject could not be extracted",
			configure: func(t *testing.T, s *SubjectInfo) {
				t.Helper()

				s.IDFrom = "foo"
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()
				require.Error(t, err)
				require.ErrorContains(t, err, "could not extract subject")
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			s := SubjectInfo{}
			tc.configure(t, &s)

			// WHEN
			sub, err := s.CreateSubject(raw)

			// THEN
			tc.assert(t, err, sub)
		})
	}
}

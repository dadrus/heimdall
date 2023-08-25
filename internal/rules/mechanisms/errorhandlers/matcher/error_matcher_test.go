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

package matcher

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type TestError struct {
	id string
}

func (e *TestError) ID() string {
	return e.id
}

func (e *TestError) Error() string {
	return "Test Error"
}

func TestErrorTypeMatcher(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc       string
		em       []ErrorDescriptor
		err      error
		matching bool
	}{
		{
			uc: "matches single error",
			em: []ErrorDescriptor{
				{
					Errors:    []error{heimdall.ErrInternal, heimdall.ErrConfiguration},
					HandlerID: "foobar",
				},
			},
			err:      errorchain.New(&TestError{id: "foobar"}).CausedBy(heimdall.ErrConfiguration),
			matching: true,
		},
		{
			uc: "doesn't match single error",
			em: []ErrorDescriptor{
				{
					Errors:    []error{heimdall.ErrInternal, heimdall.ErrConfiguration},
					HandlerID: "barfoo",
				},
			},
			err:      errorchain.New(heimdall.ErrArgument).CausedBy(&TestError{id: "barfoo"}),
			matching: false,
		},
		{
			uc: "matches at least one error",
			em: []ErrorDescriptor{
				{
					Errors:    []error{heimdall.ErrInternal, heimdall.ErrConfiguration},
					HandlerID: "barfoo",
				},
				{
					Errors:    []error{heimdall.ErrInternal, heimdall.ErrConfiguration},
					HandlerID: "foobar",
				},
			},
			err:      errorchain.New(&TestError{id: "foobar"}).CausedBy(heimdall.ErrConfiguration),
			matching: true,
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			matcher := ErrorMatcher(tc.em)

			// WHEN
			matched := matcher.Match(tc.err)

			// THEN
			assert.Equal(t, tc.matching, matched)
		})
	}
}

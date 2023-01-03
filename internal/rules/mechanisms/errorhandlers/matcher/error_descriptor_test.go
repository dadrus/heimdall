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

type testHandlerIdentifier struct {
	ID string
}

func (t *testHandlerIdentifier) HandlerID() string { return t.ID }

func TestErrorDescriptorMatches(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc            string
		errDescriptor ErrorDescriptor
		errToMatch    error
		matching      bool
	}{
		{
			uc: "with single error which does not match",
			errDescriptor: ErrorDescriptor{
				Errors: []error{heimdall.ErrInternal},
			},
			errToMatch: heimdall.ErrArgument,
			matching:   false,
		},
		{
			uc: "with multiple errors which do not match",
			errDescriptor: ErrorDescriptor{
				Errors: []error{heimdall.ErrInternal, heimdall.ErrArgument},
			},
			errToMatch: heimdall.ErrConfiguration,
			matching:   false,
		},
		{
			uc: "with single matching error",
			errDescriptor: ErrorDescriptor{
				Errors: []error{heimdall.ErrArgument},
			},
			errToMatch: heimdall.ErrArgument,
			matching:   true,
		},
		{
			uc: "with multiple errors, which one matching",
			errDescriptor: ErrorDescriptor{
				Errors: []error{heimdall.ErrInternal, heimdall.ErrArgument},
			},
			errToMatch: heimdall.ErrArgument,
			matching:   true,
		},
		{
			uc: "with matching error but not present but expected handler id",
			errDescriptor: ErrorDescriptor{
				Errors:    []error{heimdall.ErrArgument},
				HandlerID: "foo",
			},
			errToMatch: heimdall.ErrArgument,
			matching:   false,
		},
		{
			uc: "with matching error but not matching handler id",
			errDescriptor: ErrorDescriptor{
				Errors:    []error{heimdall.ErrArgument},
				HandlerID: "foo",
			},
			errToMatch: errorchain.New(heimdall.ErrArgument).WithErrorContext(&testHandlerIdentifier{ID: "bar"}),
			matching:   false,
		},
		{
			uc: "with matching error and matching handler id",
			errDescriptor: ErrorDescriptor{
				Errors:    []error{heimdall.ErrArgument},
				HandlerID: "foo",
			},
			errToMatch: errorchain.New(heimdall.ErrArgument).WithErrorContext(&testHandlerIdentifier{ID: "foo"}),
			matching:   true,
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// WHEN
			matched := tc.errDescriptor.Matches(tc.errToMatch)

			// THEN
			assert.Equal(t, tc.matching, matched)
		})
	}
}

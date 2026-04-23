// Copyright 2026 Dimitrij Drus <dadrus@gmx.de>
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

package pipeline

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func TestErrorContext(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		err             error
		expectedContext any
		expectedOK      bool
	}{
		"extracts context from errorchain": {
			err: errorchain.New(ErrAuthentication).
				WithErrorContext("test-mechanism"),
			expectedContext: "test-mechanism",
			expectedOK:      true,
		},
		"extracts context from wrapped errorchain": {
			err: errors.Join(
				ErrInternal,
				errorchain.New(ErrAuthentication).
					WithErrorContext(map[string]string{"foo": "bar"}),
			),
			expectedContext: map[string]string{"foo": "bar"},
			expectedOK:      true,
		},
		"returns false if no context carrier": {
			err: ErrInternal,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			context, ok := ErrorContext(tc.err)
			assert.Equal(t, tc.expectedOK, ok)
			assert.Equal(t, tc.expectedContext, context)
		})
	}
}

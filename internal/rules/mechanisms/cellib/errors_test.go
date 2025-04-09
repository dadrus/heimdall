// Copyright 2023 Dimitrij Drus <dadrus@gmx.de>
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

package cellib

import (
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type idProvider struct {
	id string
}

func (i idProvider) ID() string { return i.id }

func TestErrors(t *testing.T) {
	t.Parallel()

	env, err := cel.NewEnv(
		Errors(),
	)
	require.NoError(t, err)

	for _, tc := range []string{
		`type(Error) == authorization_error`,
		`authorization_error == type(Error)`,
		`authorization_error != Error`,
		`Error != authorization_error`,
		`type(Error) == authentication_error`,
		`type(Error) == internal_error`,
		`type(Error) in [internal_error, authorization_error, authentication_error]`,
		`type(Error) != precondition_error`,
		`precondition_error != type(Error)`,
		`type(Error) != communication_error`,
		`internal_error == internal_error`,
		`Error.Source == "test"`,
		`Error == Error`,
		`type(communication_error) != type(Error)`,
	} {
		t.Run(tc, func(t *testing.T) {
			ast, iss := env.Compile(tc)
			if iss != nil {
				require.NoError(t, iss.Err())
			}

			ast, iss = env.Check(ast)
			if iss != nil {
				require.NoError(t, iss.Err())
			}

			prg, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
			require.NoError(t, err)

			causeErr := errorchain.New(heimdall.ErrAuthorization).
				CausedBy(errorchain.New(heimdall.ErrAuthentication)).
				CausedBy(errorchain.New(heimdall.ErrConfiguration)).
				CausedBy(errorchain.New(heimdall.ErrInternal)).
				WithErrorContext(idProvider{id: "test"})

			out, _, err := prg.Eval(map[string]any{"Error": WrapError(causeErr)})
			require.NoError(t, err)
			require.Equal(t, true, out.Value()) //nolint:testifylint
		})
	}
}

func TestWrapError(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		err error
		id  string
	}{
		"no source":   {heimdall.ErrArgument, ""},
		"with source": {errorchain.New(heimdall.ErrAuthorization).WithErrorContext(idProvider{id: "test"}), "test"},
	} {
		t.Run(uc, func(t *testing.T) {
			// WHEN
			wrapped := WrapError(tc.err)

			// THEN
			require.Equal(t, tc.id, wrapped.Source)
			require.Equal(t, wrapped.errType.current, tc.err)
			require.Empty(t, wrapped.errType.types)
		})
	}
}

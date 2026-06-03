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

package secrets

import (
	"bytes"
	"context"
	"sync/atomic"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/secrets/metrics/mocks"
)

func TestLeasedBindingRun(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, logs *bytes.Buffer, calls *atomic.Int32) *leasedBinding[string]
		assert func(t *testing.T, entry *leasedBinding[string], logs *bytes.Buffer, calls *atomic.Int32)
	}{
		"resolves cached value": {
			setup: func(t *testing.T, _ *bytes.Buffer, calls *atomic.Int32) *leasedBinding[string] {
				t.Helper()

				bdg := newBinding(
					bindingKey{
						kind:      bindingKindSecret,
						source:    "source",
						selector:  "selector",
						namespace: "namespace",
						scope:     referenceScopeInternal,
					},
					zerolog.Nop(),
					mocks.NewSecretUsageMock(t),
					func(context.Context) (string, error) {
						calls.Add(1)

						return "resolved", nil
					},
				)

				return newLeasedBinding(bdg)
			},
			assert: func(t *testing.T, entry *leasedBinding[string], _ *bytes.Buffer, calls *atomic.Int32) {
				t.Helper()

				require.EqualValues(t, 1, calls.Load())

				value, ok := entry.binding.peek()
				require.True(t, ok)
				require.Equal(t, "resolved", value)
			},
		},
		"logs resolve error": {
			setup: func(t *testing.T, logs *bytes.Buffer, calls *atomic.Int32) *leasedBinding[string] {
				t.Helper()

				bdg := newBinding(
					bindingKey{
						kind:      bindingKindSecret,
						source:    "source",
						selector:  "selector",
						namespace: "namespace",
						scope:     referenceScopeInternal,
					},
					zerolog.Nop(),
					mocks.NewSecretUsageMock(t),
					func(context.Context) (string, error) {
						calls.Add(1)

						return "", assert.AnError
					},
				)

				bdg.logger = zerolog.New(logs)

				return newLeasedBinding(bdg)
			},
			assert: func(t *testing.T, entry *leasedBinding[string], logs *bytes.Buffer, calls *atomic.Int32) {
				t.Helper()

				require.EqualValues(t, 1, calls.Load())
				require.Contains(t, logs.String(), "Failed resolving secret binding")

				_, ok := entry.binding.peek()
				require.False(t, ok)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			var (
				logs  bytes.Buffer
				calls atomic.Int32
			)

			entry := tc.setup(t, &logs, &calls)

			entry.Run()

			tc.assert(t, entry, &logs, &calls)
		})
	}
}

func TestLeasedBindingUnschedule(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer

	bdg := newBinding[string](
		bindingKey{
			kind:      bindingKindSecret,
			source:    "source",
			selector:  "selector",
			namespace: "namespace",
			scope:     referenceScopeInternal,
		},
		zerolog.Nop(),
		mocks.NewSecretUsageMock(t),
		nil,
	)
	bdg.logger = zerolog.New(&logs)

	entry := newLeasedBinding(bdg)

	require.True(t, entry.Schedule())

	entry.Unschedule(assert.AnError)

	require.True(t, entry.Schedule())
	require.Contains(t, logs.String(), "Failed scheduling initial secret binding resolve task")
}

func TestLeasedBindingStop(t *testing.T) {
	t.Parallel()

	bdg := newBinding[string](
		bindingKey{
			kind:      bindingKindSecret,
			source:    "source",
			selector:  "selector",
			namespace: "namespace",
			scope:     referenceScopeInternal,
		},
		zerolog.Nop(),
		mocks.NewSecretUsageMock(t),
		nil,
	)
	bdg.subscribe(func(context.Context, string) error { return nil })

	entry := newLeasedBinding(bdg)

	require.True(t, entry.Schedule())
	require.True(t, entry.binding.Schedule())
	require.NotEmpty(t, entry.binding.callbacks)

	entry.stop()

	require.False(t, entry.Schedule())
	require.False(t, entry.binding.Schedule())
	require.Empty(t, entry.binding.callbacks)
}

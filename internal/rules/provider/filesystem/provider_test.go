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

package filesystem

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/rules/event"
	"github.com/dadrus/heimdall/internal/x"
)

// nolint: maintidx
func TestStartProvider(t *testing.T) {
	t.Parallel()

	var tearDownFuncs []func()

	defer func() {
		for _, f := range tearDownFuncs {
			f()
		}
	}()

	for _, tc := range []struct {
		uc             string
		createProvider func(t *testing.T, file *os.File, dir string) *provider
		writeContents  func(t *testing.T, file *os.File, dir string)
		assert         func(t *testing.T, err error, provider *provider)
	}{
		{
			uc: "start provider using not existing file",
			createProvider: func(t *testing.T, file *os.File, dir string) *provider {
				t.Helper()

				return &provider{
					src: "foo.bar",
					l:   log.Logger,
				}
			},
			assert: func(t *testing.T, err error, provider *provider) {
				t.Helper()

				require.Error(t, err)
				assert.Contains(t, err.Error(), "no such file")
			},
		},
		{
			uc: "start provider using file without read permissions",
			createProvider: func(t *testing.T, file *os.File, dir string) *provider {
				t.Helper()

				require.NoError(t, file.Chmod(0o200))

				return &provider{
					src: file.Name(),
					l:   log.Logger,
				}
			},
			assert: func(t *testing.T, err error, provider *provider) {
				t.Helper()

				require.Error(t, err)
				assert.Contains(t, err.Error(), "permission denied")
			},
		},
		{
			uc: "successfully start provider without watcher using empty file",
			createProvider: func(t *testing.T, file *os.File, dir string) *provider {
				t.Helper()

				return &provider{
					src: file.Name(),
					l:   log.Logger,
					q:   make(event.RuleSetChangedEventQueue, 10),
				}
			},
			assert: func(t *testing.T, err error, provider *provider) {
				t.Helper()

				require.NoError(t, err)

				assert.Len(t, provider.q, 0)
			},
		},
		{
			uc: "successfully start provider without watcher using not empty file",
			createProvider: func(t *testing.T, file *os.File, dir string) *provider {
				t.Helper()

				_, err := file.Write([]byte(`
version: 0.5.0-alpha
rules:
- id: foo
`))
				require.NoError(t, err)

				return &provider{
					src: file.Name(),
					l:   log.Logger,
					q:   make(event.RuleSetChangedEventQueue, 10),
				}
			},
			assert: func(t *testing.T, err error, provider *provider) {
				t.Helper()

				require.NoError(t, err)

				assert.Len(t, provider.q, 1)

				evt := <-provider.q

				assert.Contains(t, evt.Src, "file_system:")
				assert.Len(t, evt.RuleSet, 1)
				assert.Equal(t, "foo", evt.RuleSet[0].ID)
				assert.Equal(t, event.Create, evt.ChangeType)
			},
		},
		{
			uc: "successfully start provider without watcher using empty dir",
			createProvider: func(t *testing.T, file *os.File, dir string) *provider {
				t.Helper()

				return &provider{
					src: dir,
					l:   log.Logger,
					q:   make(event.RuleSetChangedEventQueue, 10),
				}
			},
			assert: func(t *testing.T, err error, provider *provider) {
				t.Helper()

				require.NoError(t, err)

				assert.Len(t, provider.q, 0)
			},
		},
		{
			uc: "successfully start provider without watcher using dir with not empty file",
			createProvider: func(t *testing.T, file *os.File, dir string) *provider {
				t.Helper()

				tmpFile, err := os.CreateTemp(dir, "test-rule-")
				require.NoError(t, err)

				_, err = tmpFile.Write([]byte(`
version: 0.5.0-alpha
rules:
- id: foo
`))
				require.NoError(t, err)

				return &provider{
					src: dir,
					l:   log.Logger,
					q:   make(event.RuleSetChangedEventQueue, 10),
				}
			},
			assert: func(t *testing.T, err error, provider *provider) {
				t.Helper()

				require.NoError(t, err)

				assert.Len(t, provider.q, 1)

				evt := <-provider.q

				assert.Contains(t, evt.Src, "file_system:")
				assert.Len(t, evt.RuleSet, 1)
				assert.Equal(t, "foo", evt.RuleSet[0].ID)
				assert.Equal(t, event.Create, evt.ChangeType)
			},
		},
		{
			uc: "successfully start provider without watcher using dir with other directory with rule file",
			createProvider: func(t *testing.T, file *os.File, dir string) *provider {
				t.Helper()

				tmpDir, err := os.MkdirTemp(dir, "test-dir-")
				require.NoError(t, err)

				tmpFile, err := os.CreateTemp(tmpDir, "test-rule-")
				require.NoError(t, err)

				_, err = tmpFile.Write([]byte(`- id: foo`))
				require.NoError(t, err)

				return &provider{
					src: dir,
					l:   log.Logger,
					q:   make(event.RuleSetChangedEventQueue, 10),
				}
			},
			assert: func(t *testing.T, err error, provider *provider) {
				t.Helper()

				require.NoError(t, err)

				assert.Len(t, provider.q, 0)
			},
		},
		{
			uc: "successfully start provider with watcher using initially empty dir and adding rule " +
				"file and deleting it then",
			createProvider: func(t *testing.T, file *os.File, dir string) *provider {
				t.Helper()

				provider, err := newProvider(
					map[string]any{"src": dir, "watch": true},
					make(event.RuleSetChangedEventQueue, 10),
					log.Logger)
				require.NoError(t, err)

				return provider
			},
			writeContents: func(t *testing.T, file *os.File, dir string) {
				t.Helper()

				tmpFile, err := os.CreateTemp(dir, "test-rule-")
				require.NoError(t, err)

				time.Sleep(200 * time.Millisecond)

				_, err = tmpFile.Write([]byte(`
version: 0.5.0-alpha
rules:
- id: foo
`))
				require.NoError(t, err)

				time.Sleep(200 * time.Millisecond)

				err = os.Remove(tmpFile.Name())
				require.NoError(t, err)

				time.Sleep(200 * time.Millisecond)
			},
			assert: func(t *testing.T, err error, provider *provider) {
				t.Helper()

				require.NoError(t, err)

				require.Len(t, provider.q, 3)

				evt := <-provider.q
				assert.Contains(t, evt.Src, "file_system:"+provider.src)
				assert.Empty(t, evt.RuleSet)
				assert.Equal(t, event.Remove, evt.ChangeType)

				evt = <-provider.q
				assert.Contains(t, evt.Src, "file_system:"+provider.src)
				assert.Len(t, evt.RuleSet, 1)
				assert.Equal(t, "foo", evt.RuleSet[0].ID)
				assert.Equal(t, event.Create, evt.ChangeType)

				evt = <-provider.q
				assert.Contains(t, evt.Src, "file_system:"+provider.src)
				assert.Empty(t, evt.RuleSet)
				assert.Equal(t, event.Remove, evt.ChangeType)
			},
		},
		{
			uc: "successfully start provider with watcher using initially empty file, " +
				"updating it afterwards and deleting it then",
			createProvider: func(t *testing.T, file *os.File, dir string) *provider {
				t.Helper()

				provider, err := newProvider(
					map[string]any{"src": file.Name(), "watch": true},
					make(event.RuleSetChangedEventQueue, 10),
					log.Logger)
				require.NoError(t, err)

				return provider
			},
			writeContents: func(t *testing.T, file *os.File, dir string) {
				t.Helper()

				_, err := file.Write([]byte(`
version: 0.5.0-alpha
rules:
- id: foo
`))
				require.NoError(t, err)

				time.Sleep(200 * time.Millisecond)

				err = os.Remove(file.Name())
				require.NoError(t, err)

				time.Sleep(200 * time.Millisecond)
			},
			assert: func(t *testing.T, err error, provider *provider) {
				t.Helper()

				require.NoError(t, err)

				require.Len(t, provider.q, 2)

				evt := <-provider.q
				assert.Contains(t, evt.Src, "file_system:"+provider.src)
				assert.Empty(t, evt.RuleSet)
				assert.Equal(t, event.Remove, evt.ChangeType)

				evt = <-provider.q
				assert.Contains(t, evt.Src, "file_system:"+provider.src)
				assert.Len(t, evt.RuleSet, 1)
				assert.Equal(t, "foo", evt.RuleSet[0].ID)
				assert.Equal(t, event.Create, evt.ChangeType)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			ctx := context.Background()
			tmpFile, err := os.CreateTemp(os.TempDir(), "test-dir-")
			require.NoError(t, err)

			tearDownFuncs = append(tearDownFuncs, func() { os.Remove(tmpFile.Name()) })

			tmpDir, err := os.MkdirTemp(os.TempDir(), "test-rule-")
			require.NoError(t, err)

			tearDownFuncs = append(tearDownFuncs, func() { os.Remove(tmpDir) })

			writeContents := x.IfThenElse(tc.writeContents != nil,
				tc.writeContents,
				func(t *testing.T, file *os.File, dir string) { t.Helper() },
			)

			// GIVEN
			provider := tc.createProvider(t, tmpFile, tmpDir)

			// WHEN
			err = provider.Start(ctx)
			writeContents(t, tmpFile, tmpDir)

			// nolint: errcheck
			tearDownFuncs = append(tearDownFuncs, func() { provider.Stop(ctx) })

			// THEN
			tc.assert(t, err, provider)
		})
	}
}

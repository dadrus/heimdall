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

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	config2 "github.com/dadrus/heimdall/internal/rules/config"
	"github.com/dadrus/heimdall/internal/rules/rule/mocks"
	"github.com/dadrus/heimdall/internal/x"
	mock2 "github.com/dadrus/heimdall/internal/x/testsupport/mock"
)

func TestNewProvider(t *testing.T) {
	t.Parallel()

	tmpFile, err := os.CreateTemp(os.TempDir(), "test-dir-")
	require.NoError(t, err)

	defer os.Remove(tmpFile.Name())

	for _, tc := range []struct {
		uc     string
		conf   map[string]any
		assert func(t *testing.T, err error, prov *Provider)
	}{
		{
			uc: "not configured provider",
			assert: func(t *testing.T, err error, prov *Provider) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, prov)
				assert.False(t, prov.configured)
			},
		},
		{
			uc:   "bad configuration",
			conf: map[string]any{"foo": "bar"},
			assert: func(t *testing.T, err error, prov *Provider) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to decode")
			},
		},
		{
			uc:   "no src configured",
			conf: map[string]any{"watch": true},
			assert: func(t *testing.T, err error, prov *Provider) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no src")
			},
		},
		{
			uc:   "configured src does not exist",
			conf: map[string]any{"src": "foo.bar"},
			assert: func(t *testing.T, err error, prov *Provider) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed to get info")
			},
		},
		{
			uc:   "successfully created provider without watcher",
			conf: map[string]any{"src": tmpFile.Name()},
			assert: func(t *testing.T, err error, prov *Provider) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, prov)
				assert.True(t, prov.configured)
				assert.Equal(t, tmpFile.Name(), prov.src)
				assert.Nil(t, prov.w)
				assert.False(t, prov.envVarsEnabled)
			},
		},
		{
			uc:   "successfully created provider with watcher",
			conf: map[string]any{"src": tmpFile.Name(), "watch": true},
			assert: func(t *testing.T, err error, prov *Provider) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, prov)
				assert.True(t, prov.configured)
				assert.Equal(t, tmpFile.Name(), prov.src)
				assert.NotNil(t, prov.w)
				assert.False(t, prov.envVarsEnabled)
			},
		},
		{
			uc:   "successfully created provider with env var support enabled",
			conf: map[string]any{"src": tmpFile.Name(), "env_vars_enabled": true},
			assert: func(t *testing.T, err error, prov *Provider) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, prov)
				assert.True(t, prov.configured)
				assert.Equal(t, tmpFile.Name(), prov.src)
				assert.Nil(t, prov.w)
				assert.True(t, prov.envVarsEnabled)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			conf := &config.Configuration{Providers: config.RuleProviders{FileSystem: tc.conf}}

			prov, err := NewProvider(conf, nil, log.Logger)

			tc.assert(t, err, prov)
		})
	}
}

func TestProviderLifecycle(t *testing.T) {
	for _, tc := range []struct {
		uc             string
		watch          bool
		setupContents  func(t *testing.T, file *os.File, dir string) string
		setupProcessor func(t *testing.T, processor *mocks.RuleSetProcessorMock)
		writeContents  func(t *testing.T, file *os.File, dir string)
		assert         func(t *testing.T, err error, provider *Provider, processor *mocks.RuleSetProcessorMock)
	}{
		{
			uc: "start provider using not existing file",
			setupContents: func(t *testing.T, file *os.File, dir string) string {
				t.Helper()

				return "foo.bar"
			},
			assert: func(t *testing.T, err error, provider *Provider, processor *mocks.RuleSetProcessorMock) {
				t.Helper()

				require.Error(t, err)
				assert.Contains(t, err.Error(), "no such file")
			},
		},
		{
			uc: "start provider using file without read permissions",
			setupContents: func(t *testing.T, file *os.File, dir string) string {
				t.Helper()

				require.NoError(t, file.Chmod(0o200))

				return file.Name()
			},
			assert: func(t *testing.T, err error, provider *Provider, processor *mocks.RuleSetProcessorMock) {
				t.Helper()

				require.Error(t, err)
				assert.Contains(t, err.Error(), "permission denied")
			},
		},
		{
			uc: "successfully start provider without watcher using empty file",
			assert: func(t *testing.T, err error, provider *Provider, processor *mocks.RuleSetProcessorMock) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc: "successfully start provider without watcher using not empty file",
			setupContents: func(t *testing.T, file *os.File, dir string) string {
				t.Helper()

				_, err := file.WriteString(`
version: "1"
rules:
- id: foo
`)
				require.NoError(t, err)

				return file.Name()
			},
			setupProcessor: func(t *testing.T, processor *mocks.RuleSetProcessorMock) {
				t.Helper()

				processor.EXPECT().OnCreated(mock.Anything).
					Run(mock2.NewArgumentCaptor[*config2.RuleSet](&processor.Mock, "captor1").Capture).
					Return(nil).Once()
			},
			assert: func(t *testing.T, err error, provider *Provider, processor *mocks.RuleSetProcessorMock) {
				t.Helper()

				require.NoError(t, err)

				ruleSet := mock2.ArgumentCaptorFrom[*config2.RuleSet](&processor.Mock, "captor1").Value()
				assert.Contains(t, ruleSet.Source, "file_system:")
				assert.Equal(t, "1", ruleSet.Version)
				assert.Len(t, ruleSet.Rules, 1)
				assert.Equal(t, "foo", ruleSet.Rules[0].ID)
			},
		},
		{
			uc: "successfully start provider without watcher using empty dir",
			setupContents: func(t *testing.T, file *os.File, dir string) string {
				t.Helper()

				return dir
			},
			assert: func(t *testing.T, err error, provider *Provider, processor *mocks.RuleSetProcessorMock) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc: "successfully start provider without watcher using dir with not empty file",
			setupContents: func(t *testing.T, file *os.File, dir string) string {
				t.Helper()

				tmpFile, err := os.CreateTemp(dir, "test-rule-")
				require.NoError(t, err)

				_, err = tmpFile.WriteString(`
version: "2"
rules:
- id: foo
`)
				require.NoError(t, err)

				return dir
			},
			setupProcessor: func(t *testing.T, processor *mocks.RuleSetProcessorMock) {
				t.Helper()

				processor.EXPECT().OnCreated(mock.Anything).
					Run(mock2.NewArgumentCaptor[*config2.RuleSet](&processor.Mock, "captor1").Capture).
					Return(nil).Once()
			},
			assert: func(t *testing.T, err error, provider *Provider, processor *mocks.RuleSetProcessorMock) {
				t.Helper()

				require.NoError(t, err)

				ruleSet := mock2.ArgumentCaptorFrom[*config2.RuleSet](&processor.Mock, "captor1").Value()
				assert.Contains(t, ruleSet.Source, "file_system:")
				assert.Equal(t, "2", ruleSet.Version)
				assert.Len(t, ruleSet.Rules, 1)
				assert.Equal(t, "foo", ruleSet.Rules[0].ID)
			},
		},
		{
			uc: "successfully start provider without watcher using dir with other directory with rule file",
			setupContents: func(t *testing.T, file *os.File, dir string) string {
				t.Helper()

				tmpDir, err := os.MkdirTemp(dir, "test-dir-")
				require.NoError(t, err)

				tmpFile, err := os.CreateTemp(tmpDir, "test-rule-")
				require.NoError(t, err)

				_, err = tmpFile.WriteString(`
version: "1"
rules:
- id: foo
`)
				require.NoError(t, err)

				return dir
			},
			assert: func(t *testing.T, err error, provider *Provider, processor *mocks.RuleSetProcessorMock) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc: "successfully start provider with watcher using initially empty dir and adding rule " +
				"file and deleting it then",
			watch: true,
			setupContents: func(t *testing.T, file *os.File, dir string) string {
				t.Helper()

				return dir
			},
			writeContents: func(t *testing.T, file *os.File, dir string) {
				t.Helper()

				tmpFile, err := os.CreateTemp(dir, "test-rule-")
				require.NoError(t, err)

				time.Sleep(200 * time.Millisecond)

				_, err = tmpFile.WriteString(`
version: "1"
rules:
- id: foo
`)
				require.NoError(t, err)

				time.Sleep(200 * time.Millisecond)

				err = os.Remove(tmpFile.Name())
				require.NoError(t, err)

				time.Sleep(200 * time.Millisecond)
			},
			setupProcessor: func(t *testing.T, processor *mocks.RuleSetProcessorMock) {
				t.Helper()

				call1 := processor.EXPECT().OnCreated(mock.Anything).
					Run(mock2.NewArgumentCaptor[*config2.RuleSet](&processor.Mock, "captor1").Capture).
					Return(nil).Once()

				processor.EXPECT().OnDeleted(mock.Anything).
					Run(mock2.NewArgumentCaptor[*config2.RuleSet](&processor.Mock, "captor2").Capture).
					Return(nil).Once().NotBefore(call1)
			},
			assert: func(t *testing.T, err error, provider *Provider, processor *mocks.RuleSetProcessorMock) {
				t.Helper()

				require.NoError(t, err)

				ruleSet := mock2.ArgumentCaptorFrom[*config2.RuleSet](&processor.Mock, "captor1").Value()
				assert.Contains(t, ruleSet.Source, "file_system:")
				assert.Equal(t, "1", ruleSet.Version)
				assert.Len(t, ruleSet.Rules, 1)
				assert.Equal(t, "foo", ruleSet.Rules[0].ID)

				ruleSet = mock2.ArgumentCaptorFrom[*config2.RuleSet](&processor.Mock, "captor2").Value()
				assert.Contains(t, ruleSet.Source, "file_system:")
			},
		},
		{
			uc: "successfully start provider with watcher using initially empty file, " +
				"updating it with same content, then with different content and deleting it then",
			watch: true,
			writeContents: func(t *testing.T, file *os.File, dir string) {
				t.Helper()

				_, err := file.WriteString(`
version: "1"
rules:
- id: foo
`)
				require.NoError(t, err)

				time.Sleep(200 * time.Millisecond)

				_, err = file.Seek(0, 0)
				require.NoError(t, err)

				_, err = file.WriteString(`
version: "1"
rules:
- id: foo
`)
				require.NoError(t, err)

				time.Sleep(200 * time.Millisecond)

				_, err = file.Seek(0, 0)
				require.NoError(t, err)

				_, err = file.WriteString(`
version: "2"
rules:
- id: bar
`)
				require.NoError(t, err)

				time.Sleep(200 * time.Millisecond)

				err = os.Remove(file.Name())
				require.NoError(t, err)

				time.Sleep(200 * time.Millisecond)
			},
			setupProcessor: func(t *testing.T, processor *mocks.RuleSetProcessorMock) {
				t.Helper()

				call1 := processor.EXPECT().OnCreated(mock.Anything).
					Run(mock2.NewArgumentCaptor[*config2.RuleSet](&processor.Mock, "captor1").Capture).
					Return(nil).Once()

				call2 := processor.EXPECT().OnUpdated(mock.Anything).
					Run(mock2.NewArgumentCaptor[*config2.RuleSet](&processor.Mock, "captor2").Capture).
					Return(nil).Once().NotBefore(call1)

				processor.EXPECT().OnDeleted(mock.Anything).
					Run(mock2.NewArgumentCaptor[*config2.RuleSet](&processor.Mock, "captor3").Capture).
					Return(nil).Once().NotBefore(call2)
			},
			assert: func(t *testing.T, err error, provider *Provider, processor *mocks.RuleSetProcessorMock) {
				t.Helper()

				require.NoError(t, err)

				ruleSet := mock2.ArgumentCaptorFrom[*config2.RuleSet](&processor.Mock, "captor1").Value()
				assert.Contains(t, ruleSet.Source, "file_system:")
				assert.Equal(t, "1", ruleSet.Version)
				assert.Len(t, ruleSet.Rules, 1)
				assert.Equal(t, "foo", ruleSet.Rules[0].ID)

				ruleSet = mock2.ArgumentCaptorFrom[*config2.RuleSet](&processor.Mock, "captor2").Value()
				assert.Contains(t, ruleSet.Source, "file_system:")
				assert.Equal(t, "2", ruleSet.Version)
				assert.Len(t, ruleSet.Rules, 1)
				assert.Equal(t, "bar", ruleSet.Rules[0].ID)

				ruleSet = mock2.ArgumentCaptorFrom[*config2.RuleSet](&processor.Mock, "captor3").Value()
				assert.Contains(t, ruleSet.Source, "file_system:")
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			ctx := context.Background()
			tmpFile, err := os.CreateTemp(os.TempDir(), "test-dir-")
			require.NoError(t, err)

			defer os.Remove(tmpFile.Name())

			tmpDir, err := os.MkdirTemp(os.TempDir(), "test-rule-")
			require.NoError(t, err)

			defer os.Remove(tmpDir)

			writeContents := x.IfThenElse(tc.writeContents != nil,
				tc.writeContents,
				func(t *testing.T, file *os.File, dir string) { t.Helper() },
			)

			setupContents := x.IfThenElse(tc.setupContents != nil,
				tc.setupContents,
				func(t *testing.T, file *os.File, dir string) string {
					t.Helper()

					return file.Name()
				},
			)

			setupProcessor := x.IfThenElse(tc.setupProcessor != nil,
				tc.setupProcessor,
				func(t *testing.T, processor *mocks.RuleSetProcessorMock) { t.Helper() })

			processor := mocks.NewRuleSetProcessorMock(t)
			setupProcessor(t, processor)

			var watcher *fsnotify.Watcher

			if tc.watch {
				watcher, err = fsnotify.NewWatcher()
				require.NoError(t, err)
			}

			// GIVEN
			prov := &Provider{
				src:        setupContents(t, tmpFile, tmpDir),
				p:          processor,
				l:          log.Logger,
				w:          watcher,
				configured: true,
			}

			// WHEN
			err = prov.Start(ctx)

			defer prov.Stop(ctx)

			writeContents(t, tmpFile, tmpDir)

			// THEN
			tc.assert(t, err, prov, processor)
		})
	}
}

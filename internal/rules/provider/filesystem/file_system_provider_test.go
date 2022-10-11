package filesystem

import (
	"os"
	"testing"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/event"
	"github.com/dadrus/heimdall/internal/x"
)

type mockLifecycle struct{ mock.Mock }

func (m *mockLifecycle) Append(hook fx.Hook) { m.Called(hook) }

func TestRegisterFileSystemProvider(t *testing.T) {
	t.Parallel()

	tmpFile, err := os.CreateTemp(os.TempDir(), "test-rule-")
	require.NoError(t, err)

	defer os.Remove(tmpFile.Name())

	for _, tc := range []struct {
		uc         string
		conf       config.Configuration
		setupMocks func(t *testing.T, mockLC *mockLifecycle)
		assert     func(t *testing.T, err error)
	}{
		{
			uc: "without it being configured",
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			uc: "without provided rules file/directory",
			conf: config.Configuration{
				Rules: config.RulesConfig{
					Providers: config.RuleProviders{
						FileSystem: &config.FileBasedRuleProviderConfig{},
					},
				},
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
			},
		},
		{
			uc: "with not existing referenced file",
			conf: config.Configuration{
				Rules: config.RulesConfig{
					Providers: config.RuleProviders{
						FileSystem: &config.FileBasedRuleProviderConfig{Src: "foo.bar"},
					},
				},
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				assert.Contains(t, err.Error(), "no such file")
			},
		},
		{
			uc: "with existing rules file",
			conf: config.Configuration{
				Rules: config.RulesConfig{
					Providers: config.RuleProviders{
						FileSystem: &config.FileBasedRuleProviderConfig{Src: tmpFile.Name()},
					},
				},
			},
			setupMocks: func(t *testing.T, mockLC *mockLifecycle) {
				t.Helper()

				mockLC.On("Append", mock.AnythingOfType("fx.Hook"))
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc: "with existing rules file and enabled watcher",
			conf: config.Configuration{
				Rules: config.RulesConfig{
					Providers: config.RuleProviders{
						FileSystem: &config.FileBasedRuleProviderConfig{Src: tmpFile.Name(), Watch: true},
					},
				},
			},
			setupMocks: func(t *testing.T, mockLC *mockLifecycle) {
				t.Helper()

				mockLC.On("Append", mock.AnythingOfType("fx.Hook"))
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			mlc := &mockLifecycle{}
			queue := make(event.RuleSetChangedEventQueue, 10)
			setupMocks := x.IfThenElse(tc.setupMocks != nil,
				tc.setupMocks,
				func(t *testing.T, mockLC *mockLifecycle) { t.Helper() })

			setupMocks(t, mlc)

			// WHEN
			err := registerProvider(registrationArguments{Lifecycle: mlc, Config: tc.conf, Queue: queue}, log.Logger)

			// THEN
			tc.assert(t, err)

			mlc.AssertExpectations(t)
		})
	}
}

// nolint: maintidx
func TestStartFileSystemProvider(t *testing.T) {
	t.Parallel()

	var tearDownFuncs []func()

	defer func() {
		for _, f := range tearDownFuncs {
			f()
		}
	}()

	for _, tc := range []struct {
		uc             string
		createProvider func(t *testing.T, file *os.File, dir string) *fileSystemProvider
		writeContents  func(t *testing.T, file *os.File, dir string)
		assert         func(t *testing.T, err error, provider *fileSystemProvider)
	}{
		{
			uc: "start provider using not existing file",
			createProvider: func(t *testing.T, file *os.File, dir string) *fileSystemProvider {
				t.Helper()

				return &fileSystemProvider{
					src:    "foo.bar",
					logger: log.Logger,
				}
			},
			assert: func(t *testing.T, err error, provider *fileSystemProvider) {
				t.Helper()

				require.Error(t, err)
				assert.Contains(t, err.Error(), "no such file")
			},
		},
		{
			uc: "start provider using file without read permissions",
			createProvider: func(t *testing.T, file *os.File, dir string) *fileSystemProvider {
				t.Helper()

				require.NoError(t, file.Chmod(0o200))

				return &fileSystemProvider{
					src:    file.Name(),
					logger: log.Logger,
				}
			},
			assert: func(t *testing.T, err error, provider *fileSystemProvider) {
				t.Helper()

				require.Error(t, err)
				assert.Contains(t, err.Error(), "permission denied")
			},
		},
		{
			uc: "successfully start provider without watcher using empty file",
			createProvider: func(t *testing.T, file *os.File, dir string) *fileSystemProvider {
				t.Helper()

				return &fileSystemProvider{
					src:    file.Name(),
					logger: log.Logger,
					queue:  make(event.RuleSetChangedEventQueue, 10),
				}
			},
			assert: func(t *testing.T, err error, provider *fileSystemProvider) {
				t.Helper()

				require.NoError(t, err)

				assert.Len(t, provider.queue, 0)
			},
		},
		{
			uc: "successfully start provider without watcher using not empty file",
			createProvider: func(t *testing.T, file *os.File, dir string) *fileSystemProvider {
				t.Helper()

				_, err := file.Write([]byte(`Hi Bar`))
				require.NoError(t, err)

				return &fileSystemProvider{
					src:    file.Name(),
					logger: log.Logger,
					queue:  make(event.RuleSetChangedEventQueue, 10),
				}
			},
			assert: func(t *testing.T, err error, provider *fileSystemProvider) {
				t.Helper()

				require.NoError(t, err)

				assert.Len(t, provider.queue, 1)

				evt := <-provider.queue

				assert.Contains(t, evt.Src, "file_system:")
				assert.Equal(t, []byte(`Hi Bar`), evt.Definition)
				assert.Equal(t, event.Create, evt.ChangeType)
			},
		},
		{
			uc: "successfully start provider without watcher using empty dir",
			createProvider: func(t *testing.T, file *os.File, dir string) *fileSystemProvider {
				t.Helper()

				return &fileSystemProvider{
					src:    dir,
					logger: log.Logger,
					queue:  make(event.RuleSetChangedEventQueue, 10),
				}
			},
			assert: func(t *testing.T, err error, provider *fileSystemProvider) {
				t.Helper()

				require.NoError(t, err)

				assert.Len(t, provider.queue, 0)
			},
		},
		{
			uc: "successfully start provider without watcher using dir with not empty file",
			createProvider: func(t *testing.T, file *os.File, dir string) *fileSystemProvider {
				t.Helper()

				tmpFile, err := os.CreateTemp(dir, "test-rule-")
				require.NoError(t, err)

				_, err = tmpFile.Write([]byte(`Hi Foo`))
				require.NoError(t, err)

				return &fileSystemProvider{
					src:    dir,
					logger: log.Logger,
					queue:  make(event.RuleSetChangedEventQueue, 10),
				}
			},
			assert: func(t *testing.T, err error, provider *fileSystemProvider) {
				t.Helper()

				require.NoError(t, err)

				assert.Len(t, provider.queue, 1)

				evt := <-provider.queue

				assert.Contains(t, evt.Src, "file_system:")
				assert.Equal(t, []byte(`Hi Foo`), evt.Definition)
				assert.Equal(t, event.Create, evt.ChangeType)
			},
		},
		{
			uc: "successfully start provider without watcher using dir with other directory with rule file",
			createProvider: func(t *testing.T, file *os.File, dir string) *fileSystemProvider {
				t.Helper()

				tmpDir, err := os.MkdirTemp(dir, "test-dir-")
				require.NoError(t, err)

				tmpFile, err := os.CreateTemp(tmpDir, "test-rule-")
				require.NoError(t, err)

				_, err = tmpFile.Write([]byte(`Hi Foo`))
				require.NoError(t, err)

				return &fileSystemProvider{
					src:    dir,
					logger: log.Logger,
					queue:  make(event.RuleSetChangedEventQueue, 10),
				}
			},
			assert: func(t *testing.T, err error, provider *fileSystemProvider) {
				t.Helper()

				require.NoError(t, err)

				assert.Len(t, provider.queue, 0)
			},
		},
		{
			uc: "successfully start provider with watcher using initially empty dir and adding rule " +
				"file and deleting it then",
			createProvider: func(t *testing.T, file *os.File, dir string) *fileSystemProvider {
				t.Helper()

				provider, err := newProvider(
					&config.FileBasedRuleProviderConfig{Src: dir, Watch: true},
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

				_, err = tmpFile.Write([]byte(`Hi Foo`))
				require.NoError(t, err)

				time.Sleep(200 * time.Millisecond)

				err = os.Remove(tmpFile.Name())
				require.NoError(t, err)

				time.Sleep(200 * time.Millisecond)
			},
			assert: func(t *testing.T, err error, provider *fileSystemProvider) {
				t.Helper()

				require.NoError(t, err)

				require.Len(t, provider.queue, 3)

				evt := <-provider.queue
				assert.Contains(t, evt.Src, "file_system:"+provider.src)
				assert.Equal(t, []byte(nil), evt.Definition)
				assert.Equal(t, event.Remove, evt.ChangeType)

				evt = <-provider.queue
				assert.Contains(t, evt.Src, "file_system:"+provider.src)
				assert.Equal(t, []byte(`Hi Foo`), evt.Definition)
				assert.Equal(t, event.Create, evt.ChangeType)

				evt = <-provider.queue
				assert.Contains(t, evt.Src, "file_system:"+provider.src)
				assert.Equal(t, []byte(nil), evt.Definition)
				assert.Equal(t, event.Remove, evt.ChangeType)
			},
		},
		{
			uc: "successfully start provider with watcher using initially empty file, " +
				"updating it afterwards and deleting it then",
			createProvider: func(t *testing.T, file *os.File, dir string) *fileSystemProvider {
				t.Helper()

				provider, err := newProvider(
					&config.FileBasedRuleProviderConfig{Src: file.Name(), Watch: true},
					make(event.RuleSetChangedEventQueue, 10),
					log.Logger)
				require.NoError(t, err)

				return provider
			},
			writeContents: func(t *testing.T, file *os.File, dir string) {
				t.Helper()

				_, err := file.Write([]byte(`Hi Foo`))
				require.NoError(t, err)

				time.Sleep(200 * time.Millisecond)

				err = os.Remove(file.Name())
				require.NoError(t, err)

				time.Sleep(200 * time.Millisecond)
			},
			assert: func(t *testing.T, err error, provider *fileSystemProvider) {
				t.Helper()

				require.NoError(t, err)

				require.Len(t, provider.queue, 2)

				evt := <-provider.queue
				assert.Contains(t, evt.Src, "file_system:"+provider.src)
				assert.Equal(t, []byte(nil), evt.Definition)
				assert.Equal(t, event.Remove, evt.ChangeType)

				evt = <-provider.queue
				assert.Contains(t, evt.Src, "file_system:"+provider.src)
				assert.Equal(t, []byte(`Hi Foo`), evt.Definition)
				assert.Equal(t, event.Create, evt.ChangeType)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
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
			err = provider.Start()
			writeContents(t, tmpFile, tmpDir)

			// nolint: errcheck
			tearDownFuncs = append(tearDownFuncs, func() { provider.Stop() })

			// THEN
			tc.assert(t, err, provider)
		})
	}
}

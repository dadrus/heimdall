package filesystem

import (
	"os"
	"testing"
	"time"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/rules/event"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
					src:    "foo.bar",
					logger: log.Logger,
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
					src:    file.Name(),
					logger: log.Logger,
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
					src:    file.Name(),
					logger: log.Logger,
					queue:  make(event.RuleSetChangedEventQueue, 10),
				}
			},
			assert: func(t *testing.T, err error, provider *provider) {
				t.Helper()

				require.NoError(t, err)

				assert.Len(t, provider.queue, 0)
			},
		},
		{
			uc: "successfully start provider without watcher using not empty file",
			createProvider: func(t *testing.T, file *os.File, dir string) *provider {
				t.Helper()

				_, err := file.Write([]byte(`Hi Bar`))
				require.NoError(t, err)

				return &provider{
					src:    file.Name(),
					logger: log.Logger,
					queue:  make(event.RuleSetChangedEventQueue, 10),
				}
			},
			assert: func(t *testing.T, err error, provider *provider) {
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
			createProvider: func(t *testing.T, file *os.File, dir string) *provider {
				t.Helper()

				return &provider{
					src:    dir,
					logger: log.Logger,
					queue:  make(event.RuleSetChangedEventQueue, 10),
				}
			},
			assert: func(t *testing.T, err error, provider *provider) {
				t.Helper()

				require.NoError(t, err)

				assert.Len(t, provider.queue, 0)
			},
		},
		{
			uc: "successfully start provider without watcher using dir with not empty file",
			createProvider: func(t *testing.T, file *os.File, dir string) *provider {
				t.Helper()

				tmpFile, err := os.CreateTemp(dir, "test-rule-")
				require.NoError(t, err)

				_, err = tmpFile.Write([]byte(`Hi Foo`))
				require.NoError(t, err)

				return &provider{
					src:    dir,
					logger: log.Logger,
					queue:  make(event.RuleSetChangedEventQueue, 10),
				}
			},
			assert: func(t *testing.T, err error, provider *provider) {
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
			createProvider: func(t *testing.T, file *os.File, dir string) *provider {
				t.Helper()

				tmpDir, err := os.MkdirTemp(dir, "test-dir-")
				require.NoError(t, err)

				tmpFile, err := os.CreateTemp(tmpDir, "test-rule-")
				require.NoError(t, err)

				_, err = tmpFile.Write([]byte(`Hi Foo`))
				require.NoError(t, err)

				return &provider{
					src:    dir,
					logger: log.Logger,
					queue:  make(event.RuleSetChangedEventQueue, 10),
				}
			},
			assert: func(t *testing.T, err error, provider *provider) {
				t.Helper()

				require.NoError(t, err)

				assert.Len(t, provider.queue, 0)
			},
		},
		{
			uc: "successfully start provider with watcher using initially empty dir and adding rule " +
				"file and deleting it then",
			createProvider: func(t *testing.T, file *os.File, dir string) *provider {
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
			assert: func(t *testing.T, err error, provider *provider) {
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
			createProvider: func(t *testing.T, file *os.File, dir string) *provider {
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
			assert: func(t *testing.T, err error, provider *provider) {
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

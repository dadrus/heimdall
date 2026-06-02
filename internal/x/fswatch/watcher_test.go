// Copyright 2026 Dimitrij Drus
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package fswatch

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		handler EventHandler
		assert  func(t *testing.T, watcher *Watcher, err error)
	}{
		"without handler": {
			assert: func(t *testing.T, watcher *Watcher, err error) {
				t.Helper()

				require.ErrorIs(t, err, errNoHandler)
				assert.Nil(t, watcher)
			},
		},
		"with handler": {
			handler: NewEventHandlerMock(t),
			assert: func(t *testing.T, watcher *Watcher, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, watcher)

				assert.False(t, watcher.started)
				assert.NotNil(t, watcher.dispatcher)
				assert.Empty(t, watcher.targets)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			watcher, err := New(tc.handler, WithLogger(zerolog.Nop()))

			tc.assert(t, watcher, err)
		})
	}
}

func TestWatcherAdd(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		startWatcher bool
		setup        func(t *testing.T, watcher *Watcher) string
		assert       func(t *testing.T, watcher *Watcher, path string, err error)
	}{
		"existing file before start": {
			setup: func(t *testing.T, _ *Watcher) string {
				t.Helper()

				path := filepath.Join(t.TempDir(), "key_and_cert.pem")

				require.NoError(t, os.WriteFile(path, []byte("content"), 0o600))

				return path
			},
			assert: func(t *testing.T, watcher *Watcher, path string, err error) {
				t.Helper()

				require.NoError(t, err)

				tgt, ok := watcher.targets[filepath.Clean(path)]
				require.True(t, ok)

				assert.Equal(t, filepath.Clean(path), tgt.path)
			},
		},
		"existing directory before start": {
			setup: func(t *testing.T, _ *Watcher) string {
				t.Helper()

				return t.TempDir()
			},
			assert: func(t *testing.T, watcher *Watcher, path string, err error) {
				t.Helper()

				require.NoError(t, err)

				tgt, ok := watcher.targets[filepath.Clean(path)]
				require.True(t, ok)

				assert.Equal(t, filepath.Clean(path), tgt.path)
			},
		},
		"existing file after start": {
			startWatcher: true,
			setup: func(t *testing.T, _ *Watcher) string {
				t.Helper()

				path := filepath.Join(t.TempDir(), "key_and_cert.pem")

				require.NoError(t, os.WriteFile(path, []byte("content"), 0o600))

				return path
			},
			assert: func(t *testing.T, watcher *Watcher, path string, err error) {
				t.Helper()

				require.NoError(t, err)

				tgt, ok := watcher.targets[filepath.Clean(path)]
				require.True(t, ok)

				assert.Equal(t, filepath.Clean(path), tgt.path)
			},
		},
		"missing path": {
			setup: func(t *testing.T, _ *Watcher) string {
				t.Helper()

				return filepath.Join(t.TempDir(), "missing.pem")
			},
			assert: func(t *testing.T, watcher *Watcher, _ string, err error) {
				t.Helper()

				require.Error(t, err)
				assert.Empty(t, watcher.targets)
			},
		},
		"already registered": {
			setup: func(t *testing.T, watcher *Watcher) string {
				t.Helper()

				path := filepath.Join(t.TempDir(), "key_and_cert.pem")

				require.NoError(t, os.WriteFile(path, []byte("content"), 0o600))
				require.NoError(t, watcher.Add(path))

				return path
			},
			assert: func(t *testing.T, watcher *Watcher, _ string, err error) {
				t.Helper()

				require.Error(t, err)
				assert.Len(t, watcher.targets, 1)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			watcher, err := New(NewEventHandlerMock(t), WithLogger(zerolog.Nop()))
			require.NoError(t, err)

			if tc.startWatcher {
				require.NoError(t, watcher.Start(t.Context()))

				t.Cleanup(func() {
					if watcher.started {
						require.NoError(t, watcher.Stop(context.Background()))
					}
				})
			}

			path := tc.setup(t, watcher)

			err = watcher.Add(path)

			tc.assert(t, watcher, path, err)
		})
	}
}

func TestWatcherRemove(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		startWatcher bool
		setup        func(t *testing.T, watcher *Watcher) string
		assert       func(t *testing.T, watcher *Watcher, path string, err error)
	}{
		"registered before start": {
			setup: func(t *testing.T, watcher *Watcher) string {
				t.Helper()

				path := filepath.Join(t.TempDir(), "key_and_cert.pem")

				require.NoError(t, os.WriteFile(path, []byte("content"), 0o600))
				require.NoError(t, watcher.Add(path))

				return path
			},
			assert: func(t *testing.T, watcher *Watcher, path string, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.NotContains(t, watcher.targets, filepath.Clean(path))
			},
		},
		"registered after start": {
			startWatcher: true,
			setup: func(t *testing.T, watcher *Watcher) string {
				t.Helper()

				path := filepath.Join(t.TempDir(), "key_and_cert.pem")

				require.NoError(t, os.WriteFile(path, []byte("content"), 0o600))
				require.NoError(t, watcher.Add(path))

				return path
			},
			assert: func(t *testing.T, watcher *Watcher, path string, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.NotContains(t, watcher.targets, filepath.Clean(path))
			},
		},
		"missing target before start": {
			setup: func(t *testing.T, _ *Watcher) string {
				t.Helper()

				return filepath.Join(t.TempDir(), "missing.pem")
			},
			assert: func(t *testing.T, watcher *Watcher, _ string, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Empty(t, watcher.targets)
			},
		},
		"missing target after start": {
			startWatcher: true,
			setup: func(t *testing.T, _ *Watcher) string {
				t.Helper()

				return filepath.Join(t.TempDir(), "missing.pem")
			},
			assert: func(t *testing.T, watcher *Watcher, _ string, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Empty(t, watcher.targets)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			watcher, err := New(NewEventHandlerMock(t), WithLogger(zerolog.Nop()))
			require.NoError(t, err)

			if tc.startWatcher {
				require.NoError(t, watcher.Start(t.Context()))

				t.Cleanup(func() {
					if watcher.started {
						require.NoError(t, watcher.Stop(context.Background()))
					}
				})
			}

			path := tc.setup(t, watcher)

			err = watcher.Remove(path)

			tc.assert(t, watcher, path, err)
		})
	}
}

func TestWatcherStart(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, watcher *Watcher)
		act    func(t *testing.T, watcher *Watcher) error
		assert func(t *testing.T, watcher *Watcher, err error)
	}{
		"starts without targets": {
			act: func(t *testing.T, watcher *Watcher) error {
				t.Helper()

				return watcher.Start(t.Context())
			},
			assert: func(t *testing.T, watcher *Watcher, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, watcher.started)
				assert.NotNil(t, watcher.cancel)
				assert.NotNil(t, watcher.watcher)
			},
		},
		"registers existing targets": {
			setup: func(t *testing.T, watcher *Watcher) {
				t.Helper()

				path := filepath.Join(t.TempDir(), "key_and_cert.pem")

				require.NoError(t, os.WriteFile(path, []byte("content"), 0o600))
				require.NoError(t, watcher.Add(path))
			},
			act: func(t *testing.T, watcher *Watcher) error {
				t.Helper()

				return watcher.Start(t.Context())
			},
			assert: func(t *testing.T, watcher *Watcher, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, watcher.started)
				assert.NotNil(t, watcher.watcher)
			},
		},
		"starting twice keeps existing fs watcher": {
			act: func(t *testing.T, watcher *Watcher) error {
				t.Helper()

				require.NoError(t, watcher.Start(t.Context()))

				fsWatcher := watcher.watcher

				err := watcher.Start(t.Context())

				assert.Same(t, fsWatcher, watcher.watcher)

				return err
			},
			assert: func(t *testing.T, watcher *Watcher, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, watcher.started)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			watcher, err := New(NewEventHandlerMock(t), WithLogger(zerolog.Nop()))
			require.NoError(t, err)

			if tc.setup != nil {
				tc.setup(t, watcher)
			}

			err = tc.act(t, watcher)

			t.Cleanup(func() {
				if watcher.started {
					require.NoError(t, watcher.Stop(context.Background()))
				}
			})

			tc.assert(t, watcher, err)
		})
	}
}

func TestWatcherStop(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, watcher *Watcher)
		assert func(t *testing.T, watcher *Watcher, err error)
	}{
		"without start": {
			assert: func(t *testing.T, watcher *Watcher, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.False(t, watcher.started)
				assert.Nil(t, watcher.cancel)
				assert.Nil(t, watcher.watcher)
			},
		},
		"after start": {
			setup: func(t *testing.T, watcher *Watcher) {
				t.Helper()

				require.NoError(t, watcher.Start(t.Context()))
			},
			assert: func(t *testing.T, watcher *Watcher, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.False(t, watcher.started)
				assert.Nil(t, watcher.cancel)
				assert.Nil(t, watcher.watcher)
			},
		},
		"after start with target": {
			setup: func(t *testing.T, watcher *Watcher) {
				t.Helper()

				path := filepath.Join(t.TempDir(), "key_and_cert.pem")

				require.NoError(t, os.WriteFile(path, []byte("content"), 0o600))
				require.NoError(t, watcher.Add(path))
				require.NoError(t, watcher.Start(t.Context()))
			},
			assert: func(t *testing.T, watcher *Watcher, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.False(t, watcher.started)
				assert.Nil(t, watcher.cancel)
				assert.Nil(t, watcher.watcher)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			watcher, err := New(NewEventHandlerMock(t), WithLogger(zerolog.Nop()))
			require.NoError(t, err)

			if tc.setup != nil {
				tc.setup(t, watcher)
			}

			err = watcher.Stop(t.Context())

			tc.assert(t, watcher, err)
		})
	}
}

func TestWatcherHandleEventDispatchesMatchingEvent(t *testing.T) {
	t.Parallel()

	handler := NewEventHandlerMock(t)
	handled := make(chan struct{}, 1)

	dir := t.TempDir()
	path := filepath.Join(dir, "key_and_cert.pem")

	require.NoError(t, os.WriteFile(path, []byte("content"), 0o600))

	expected := Event{
		Path: filepath.Clean(path),
		Op:   OpChanged,
	}

	handler.EXPECT().
		HandleEvent(expected).
		RunAndReturn(func(Event) error {
			handled <- struct{}{}

			return nil
		})

	watcher, err := New(handler, WithLogger(zerolog.Nop()))
	require.NoError(t, err)
	require.NoError(t, watcher.Add(path))
	require.NoError(t, watcher.dispatcher.Start())

	t.Cleanup(func() {
		require.NoError(t, watcher.dispatcher.Stop())
	})

	watcher.handleEvent(nil, fsnotify.Event{
		Name: path,
		Op:   fsnotify.Write,
	})

	require.Eventually(t, func() bool {
		select {
		case <-handled:
			return true
		default:
			return false
		}
	}, time.Second, 10*time.Millisecond)
}

func TestWatcherHandleEventIgnoresUnrelatedEvent(t *testing.T) {
	t.Parallel()

	handler := NewEventHandlerMock(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "key_and_cert.pem")
	otherPath := filepath.Join(dir, "other.pem")

	require.NoError(t, os.WriteFile(path, []byte("content"), 0o600))
	require.NoError(t, os.WriteFile(otherPath, []byte("content"), 0o600))

	watcher, err := New(handler, WithLogger(zerolog.Nop()))
	require.NoError(t, err)
	require.NoError(t, watcher.Add(path))
	require.NoError(t, watcher.dispatcher.Start())

	t.Cleanup(func() {
		require.NoError(t, watcher.dispatcher.Stop())
	})

	watcher.handleEvent(nil, fsnotify.Event{
		Name: otherPath,
		Op:   fsnotify.Write,
	})
}

func TestWatcherRunReturnsOnContextCancellation(t *testing.T) {
	t.Parallel()

	watcher, err := New(NewEventHandlerMock(t), WithLogger(zerolog.Nop()))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	fsWatcher := &fsnotify.Watcher{
		Events: make(chan fsnotify.Event),
		Errors: make(chan error),
	}

	done := make(chan struct{})

	go func() {
		watcher.run(ctx, fsWatcher)
		close(done)
	}()

	cancel()

	require.Eventually(t, func() bool {
		select {
		case <-done:
			return true
		default:
			return false
		}
	}, time.Second, 10*time.Millisecond)
}

func TestWatcherRunReturnsWhenEventsChannelIsClosed(t *testing.T) {
	t.Parallel()

	watcher, err := New(NewEventHandlerMock(t), WithLogger(zerolog.Nop()))
	require.NoError(t, err)

	fsWatcher := &fsnotify.Watcher{
		Events: make(chan fsnotify.Event),
		Errors: make(chan error),
	}

	done := make(chan struct{})

	go func() {
		watcher.run(t.Context(), fsWatcher)
		close(done)
	}()

	close(fsWatcher.Events)

	require.Eventually(t, func() bool {
		select {
		case <-done:
			return true
		default:
			return false
		}
	}, time.Second, 10*time.Millisecond)
}

func TestWatcherRunReturnsWhenErrorsChannelIsClosed(t *testing.T) {
	t.Parallel()

	watcher, err := New(NewEventHandlerMock(t), WithLogger(zerolog.Nop()))
	require.NoError(t, err)

	fsWatcher := &fsnotify.Watcher{
		Events: make(chan fsnotify.Event),
		Errors: make(chan error),
	}

	done := make(chan struct{})

	go func() {
		watcher.run(t.Context(), fsWatcher)
		close(done)
	}()

	close(fsWatcher.Errors)

	require.Eventually(t, func() bool {
		select {
		case <-done:
			return true
		default:
			return false
		}
	}, time.Second, 10*time.Millisecond)
}

func TestWatcherRunContinuesAfterWatcherError(t *testing.T) {
	t.Parallel()

	watcher, err := New(NewEventHandlerMock(t), WithLogger(zerolog.Nop()))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	fsWatcher := &fsnotify.Watcher{
		Events: make(chan fsnotify.Event),
		Errors: make(chan error),
	}

	done := make(chan struct{})

	go func() {
		watcher.run(ctx, fsWatcher)
		close(done)
	}()

	fsWatcher.Errors <- errors.New("watcher failed")

	require.Never(t, func() bool {
		select {
		case <-done:
			return true
		default:
			return false
		}
	}, 50*time.Millisecond, 10*time.Millisecond)

	cancel()

	require.Eventually(t, func() bool {
		select {
		case <-done:
			return true
		default:
			return false
		}
	}, time.Second, 10*time.Millisecond)
}

func TestWatcherRunHandlesWatcherEvent(t *testing.T) {
	t.Parallel()

	handler := NewEventHandlerMock(t)
	handled := make(chan struct{}, 1)

	dir := t.TempDir()
	path := filepath.Join(dir, "key_and_cert.pem")

	require.NoError(t, os.WriteFile(path, []byte("content"), 0o600))

	expected := Event{
		Path: filepath.Clean(path),
		Op:   OpChanged,
	}

	handler.EXPECT().
		HandleEvent(expected).
		RunAndReturn(func(Event) error {
			handled <- struct{}{}

			return nil
		})

	watcher, err := New(handler, WithLogger(zerolog.Nop()))
	require.NoError(t, err)
	require.NoError(t, watcher.Add(path))
	require.NoError(t, watcher.dispatcher.Start())

	t.Cleanup(func() {
		require.NoError(t, watcher.dispatcher.Stop())
	})

	ctx, cancel := context.WithCancel(t.Context())
	fsWatcher := &fsnotify.Watcher{
		Events: make(chan fsnotify.Event),
		Errors: make(chan error),
	}

	done := make(chan struct{})

	go func() {
		watcher.run(ctx, fsWatcher)
		close(done)
	}()

	fsWatcher.Events <- fsnotify.Event{
		Name: path,
		Op:   fsnotify.Write,
	}

	require.Eventually(t, func() bool {
		select {
		case <-handled:
			return true
		default:
			return false
		}
	}, time.Second, 10*time.Millisecond)

	cancel()

	require.Eventually(t, func() bool {
		select {
		case <-done:
			return true
		default:
			return false
		}
	}, time.Second, 10*time.Millisecond)
}

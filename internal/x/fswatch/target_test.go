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
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTarget(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T) string
		assert func(t *testing.T, tgt *target, path string, err error)
	}{
		"file": {
			setup: func(t *testing.T) string {
				t.Helper()

				path := filepath.Join(t.TempDir(), "key_and_cert.pem")

				require.NoError(t, os.WriteFile(path, []byte("content"), 0o600))

				return path
			},
			assert: func(t *testing.T, tgt *target, path string, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, tgt)

				assert.Equal(t, filepath.Clean(path), tgt.path)
				assert.Equal(t, filepath.Clean(path), tgt.resolvedPath)
				assert.False(t, tgt.isDir)
			},
		},
		"directory": {
			setup: func(t *testing.T) string {
				t.Helper()

				return t.TempDir()
			},
			assert: func(t *testing.T, tgt *target, path string, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, tgt)

				assert.Equal(t, filepath.Clean(path), tgt.path)
				assert.Equal(t, filepath.Clean(path), tgt.resolvedPath)
				assert.True(t, tgt.isDir)
			},
		},
		"missing path": {
			setup: func(t *testing.T) string {
				t.Helper()

				return filepath.Join(t.TempDir(), "missing.pem")
			},
			assert: func(t *testing.T, tgt *target, _ string, err error) {
				t.Helper()

				require.Error(t, err)
				assert.Nil(t, tgt)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			path := tc.setup(t)

			tgt, err := newTarget(path)

			tc.assert(t, tgt, path, err)
		})
	}
}

func TestTargetAddWatch(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	file := filepath.Join(dir, "key_and_cert.pem")

	require.NoError(t, os.WriteFile(file, []byte("content"), 0o600))

	tgt, err := newTarget(file)
	require.NoError(t, err)

	watcher, err := fsnotify.NewWatcher()
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, watcher.Close())
	})

	require.NoError(t, tgt.addWatch(watcher))
}

func TestTargetRemoveWatch(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	file := filepath.Join(dir, "key_and_cert.pem")

	require.NoError(t, os.WriteFile(file, []byte("content"), 0o600))

	tgt, err := newTarget(file)
	require.NoError(t, err)

	watcher, err := fsnotify.NewWatcher()
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, watcher.Close())
	})

	require.NoError(t, tgt.addWatch(watcher))

	tgt.removeWatch(watcher)
}

func TestTargetHandle(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup func(t *testing.T) (*target, *fsnotify.Watcher, fsnotify.Event, Event)
		ok    bool
	}{
		"file changed": {
			setup: func(t *testing.T) (*target, *fsnotify.Watcher, fsnotify.Event, Event) {
				t.Helper()

				dir := t.TempDir()
				file := filepath.Join(dir, "key_and_cert.pem")

				require.NoError(t, os.WriteFile(file, []byte("content"), 0o600))

				tgt, err := newTarget(file)
				require.NoError(t, err)

				return tgt,
					nil,
					fsnotify.Event{Name: file, Op: fsnotify.Write},
					Event{Path: filepath.Clean(file), Op: OpChanged}
			},
			ok: true,
		},
		"file deleted": {
			setup: func(t *testing.T) (*target, *fsnotify.Watcher, fsnotify.Event, Event) {
				t.Helper()

				dir := t.TempDir()
				file := filepath.Join(dir, "key_and_cert.pem")

				require.NoError(t, os.WriteFile(file, []byte("content"), 0o600))

				tgt, err := newTarget(file)
				require.NoError(t, err)

				watcher, err := fsnotify.NewWatcher()
				require.NoError(t, err)

				t.Cleanup(func() {
					require.NoError(t, watcher.Close())
				})

				require.NoError(t, tgt.addWatch(watcher))
				require.NoError(t, os.Remove(file))

				return tgt,
					watcher,
					fsnotify.Event{Name: file, Op: fsnotify.Remove},
					Event{Path: filepath.Clean(file), Op: OpDeleted}
			},
			ok: true,
		},
		"file renamed as deleted": {
			setup: func(t *testing.T) (*target, *fsnotify.Watcher, fsnotify.Event, Event) {
				t.Helper()

				dir := t.TempDir()
				file := filepath.Join(dir, "key_and_cert.pem")

				require.NoError(t, os.WriteFile(file, []byte("content"), 0o600))

				tgt, err := newTarget(file)
				require.NoError(t, err)

				return tgt,
					nil,
					fsnotify.Event{Name: file, Op: fsnotify.Rename},
					Event{Path: filepath.Clean(file), Op: OpDeleted}
			},
			ok: true,
		},
		"file replaced by rename as changed": {
			setup: func(t *testing.T) (*target, *fsnotify.Watcher, fsnotify.Event, Event) {
				t.Helper()

				dir := t.TempDir()
				file := filepath.Join(dir, "key_and_cert.pem")
				nextFile := filepath.Join(dir, "key_and_cert.pem.tmp")

				require.NoError(t, os.WriteFile(file, []byte("content"), 0o600))

				tgt, err := newTarget(file)
				require.NoError(t, err)

				require.NoError(t, os.WriteFile(nextFile, []byte("updated"), 0o600))
				require.NoError(t, os.Rename(nextFile, file))

				return tgt,
					nil,
					fsnotify.Event{Name: file, Op: fsnotify.Rename},
					Event{Path: filepath.Clean(file), Op: OpChanged}
			},
			ok: true,
		},
		"unrelated file event": {
			setup: func(t *testing.T) (*target, *fsnotify.Watcher, fsnotify.Event, Event) {
				t.Helper()

				dir := t.TempDir()
				file := filepath.Join(dir, "key_and_cert.pem")
				otherFile := filepath.Join(dir, "other.pem")

				require.NoError(t, os.WriteFile(file, []byte("content"), 0o600))
				require.NoError(t, os.WriteFile(otherFile, []byte("content"), 0o600))

				tgt, err := newTarget(file)
				require.NoError(t, err)

				return tgt, nil, fsnotify.Event{Name: otherFile, Op: fsnotify.Write}, Event{}
			},
			ok: false,
		},
		"directory child added": {
			setup: func(t *testing.T) (*target, *fsnotify.Watcher, fsnotify.Event, Event) {
				t.Helper()

				dir := t.TempDir()
				child := filepath.Join(dir, "rules.yaml")

				tgt, err := newTarget(dir)
				require.NoError(t, err)

				return tgt,
					nil,
					fsnotify.Event{Name: child, Op: fsnotify.Create},
					Event{Path: filepath.Clean(child), Op: OpAdded}
			},
			ok: true,
		},
		"directory child changed": {
			setup: func(t *testing.T) (*target, *fsnotify.Watcher, fsnotify.Event, Event) {
				t.Helper()

				dir := t.TempDir()
				child := filepath.Join(dir, "rules.yaml")

				tgt, err := newTarget(dir)
				require.NoError(t, err)

				return tgt,
					nil,
					fsnotify.Event{Name: child, Op: fsnotify.Write},
					Event{Path: filepath.Clean(child), Op: OpChanged}
			},
			ok: true,
		},
		"directory child chmod changed": {
			setup: func(t *testing.T) (*target, *fsnotify.Watcher, fsnotify.Event, Event) {
				t.Helper()

				dir := t.TempDir()
				child := filepath.Join(dir, "rules.yaml")

				tgt, err := newTarget(dir)
				require.NoError(t, err)

				return tgt,
					nil,
					fsnotify.Event{Name: child, Op: fsnotify.Chmod},
					Event{Path: filepath.Clean(child), Op: OpChanged}
			},
			ok: true,
		},
		"directory child removed": {
			setup: func(t *testing.T) (*target, *fsnotify.Watcher, fsnotify.Event, Event) {
				t.Helper()

				dir := t.TempDir()
				child := filepath.Join(dir, "rules.yaml")

				tgt, err := newTarget(dir)
				require.NoError(t, err)

				return tgt,
					nil,
					fsnotify.Event{Name: child, Op: fsnotify.Remove},
					Event{Path: filepath.Clean(child), Op: OpDeleted}
			},
			ok: true,
		},
		"directory child renamed as deleted": {
			setup: func(t *testing.T) (*target, *fsnotify.Watcher, fsnotify.Event, Event) {
				t.Helper()

				dir := t.TempDir()
				child := filepath.Join(dir, "rules.yaml")

				tgt, err := newTarget(dir)
				require.NoError(t, err)

				return tgt,
					nil,
					fsnotify.Event{Name: child, Op: fsnotify.Rename},
					Event{Path: filepath.Clean(child), Op: OpDeleted}
			},
			ok: true,
		},
		"nested directory child ignored": {
			setup: func(t *testing.T) (*target, *fsnotify.Watcher, fsnotify.Event, Event) {
				t.Helper()

				dir := t.TempDir()
				nestedChild := filepath.Join(dir, "nested", "rules.yaml")

				tgt, err := newTarget(dir)
				require.NoError(t, err)

				return tgt, nil, fsnotify.Event{Name: nestedChild, Op: fsnotify.Create}, Event{}
			},
			ok: false,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			tgt, watcher, raw, want := tc.setup(t)

			got, ok := tgt.handle(watcher, raw, zerolog.Nop())

			require.Equal(t, tc.ok, ok)

			if !tc.ok {
				assert.Empty(t, got)

				return
			}

			assert.Equal(t, want, got)
		})
	}
}

func TestTargetHandleFileSymlinkTargetChange(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("symlink based test")
	}

	dir := t.TempDir()

	firstDataDir := filepath.Join(dir, "1")
	secondDataDir := filepath.Join(dir, "2")
	dataLink := filepath.Join(dir, "data")
	nextDataLink := filepath.Join(dir, "data_tmp")
	path := filepath.Join(dir, "key_and_cert.pem")

	require.NoError(t, os.Mkdir(firstDataDir, 0o755))
	require.NoError(t, os.Mkdir(secondDataDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(firstDataDir, "key_and_cert.pem"), []byte("initial"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(secondDataDir, "key_and_cert.pem"), []byte("updated"), 0o600))
	require.NoError(t, os.Symlink(firstDataDir, dataLink))
	require.NoError(t, os.Symlink(filepath.Join("data", "key_and_cert.pem"), path))

	tgt, err := newTarget(path)
	require.NoError(t, err)
	require.Equal(t, filepath.Join(firstDataDir, "key_and_cert.pem"), tgt.resolvedPath)

	watcher, err := fsnotify.NewWatcher()
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, watcher.Close())
	})

	require.NoError(t, tgt.addWatch(watcher))

	require.NoError(t, os.Symlink(secondDataDir, nextDataLink))
	require.NoError(t, os.Rename(nextDataLink, dataLink))
	require.NoError(t, os.RemoveAll(firstDataDir))

	evt, ok := tgt.handle(watcher, fsnotify.Event{
		Name: path,
		Op:   fsnotify.Chmod,
	}, zerolog.Nop())

	require.True(t, ok)
	assert.Equal(t, Event{Path: filepath.Clean(path), Op: OpChanged}, evt)
	assert.Equal(t, filepath.Join(secondDataDir, "key_and_cert.pem"), tgt.resolvedPath)
	assert.False(t, tgt.isDir)
}

func TestTargetHandleDirectorySymlinkTargetChange(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("symlink based test")
	}

	dir := t.TempDir()

	firstDataDir := filepath.Join(dir, "1")
	secondDataDir := filepath.Join(dir, "2")
	dataLink := filepath.Join(dir, "data")
	nextDataLink := filepath.Join(dir, "data_tmp")
	path := filepath.Join(dir, "rules")

	require.NoError(t, os.MkdirAll(filepath.Join(firstDataDir, "rules"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(secondDataDir, "rules"), 0o755))
	require.NoError(t, os.Symlink(firstDataDir, dataLink))
	require.NoError(t, os.Symlink(filepath.Join("data", "rules"), path))

	tgt, err := newTarget(path)
	require.NoError(t, err)
	require.Equal(t, filepath.Join(firstDataDir, "rules"), tgt.resolvedPath)

	watcher, err := fsnotify.NewWatcher()
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, watcher.Close())
	})

	require.NoError(t, tgt.addWatch(watcher))

	require.NoError(t, os.Symlink(secondDataDir, nextDataLink))
	require.NoError(t, os.Rename(nextDataLink, dataLink))
	require.NoError(t, os.RemoveAll(firstDataDir))

	evt, ok := tgt.handle(watcher, fsnotify.Event{
		Name: filepath.Join(path, "any.yaml"),
		Op:   fsnotify.Chmod,
	}, zerolog.Nop())

	require.True(t, ok)
	assert.Equal(t, Event{Path: filepath.Clean(path), Op: OpChanged}, evt)
	assert.Equal(t, filepath.Join(secondDataDir, "rules"), tgt.resolvedPath)
	assert.True(t, tgt.isDir)
}

func TestIsDirectChild(t *testing.T) {
	t.Parallel()

	root := filepath.Clean("/tmp/rules")

	for uc, tc := range map[string]struct {
		path string
		want bool
	}{
		"same path": {
			path: root,
			want: false,
		},
		"direct child": {
			path: filepath.Join(root, "rules.yaml"),
			want: true,
		},
		"nested child": {
			path: filepath.Join(root, "nested", "rules.yaml"),
			want: false,
		},
		"sibling": {
			path: filepath.Clean("/tmp/other.yaml"),
			want: false,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, isDirectChild(root, tc.path))
		})
	}
}

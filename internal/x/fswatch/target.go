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
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog"
)

type targetState struct {
	exists  bool
	changed bool
}

type target struct {
	path         string
	resolvedPath string
	isDir        bool
	info         os.FileInfo

	watchMu sync.Mutex
}

func newTarget(path string) (*target, error) {
	path = filepath.Clean(path)

	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	resolvedPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}

	return &target{
		path:         path,
		resolvedPath: filepath.Clean(resolvedPath),
		isDir:        info.IsDir(),
		info:         info,
	}, nil
}

func (t *target) addWatch(watcher *fsnotify.Watcher) error {
	t.watchMu.Lock()
	defer t.watchMu.Unlock()

	return watcher.Add(t.path)
}

func (t *target) removeWatch(watcher *fsnotify.Watcher) {
	t.watchMu.Lock()
	defer t.watchMu.Unlock()

	_ = watcher.Remove(t.path)
}

func (t *target) handle(
	watcher *fsnotify.Watcher,
	raw fsnotify.Event,
	logger zerolog.Logger,
) (Event, bool) {
	t.watchMu.Lock()
	defer t.watchMu.Unlock()

	eventPath := filepath.Clean(raw.Name)
	if !t.concernsLocked(eventPath) {
		return Event{}, false
	}

	state, err := t.refreshLocked(watcher)
	if err != nil {
		logger.Error().
			Err(err).
			Str("_file", t.path).
			Msg("Failed refreshing watched file system target")
	}

	if state.changed {
		return Event{
			Path: t.path,
			Op:   OpChanged,
		}, true
	}

	if t.isDir {
		return t.directoryEventLocked(eventPath, raw.Op)
	}

	return t.fileEventLocked(raw.Op, state.exists)
}

func (t *target) refreshLocked(watcher *fsnotify.Watcher) (targetState, error) {
	info, err := os.Stat(t.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if watcher != nil {
				_ = watcher.Remove(t.path)
			}

			return targetState{}, nil
		}

		return targetState{}, err
	}

	resolvedPath, err := filepath.EvalSymlinks(t.path)
	if err != nil {
		return targetState{}, err
	}

	resolvedPath = filepath.Clean(resolvedPath)
	isDir := info.IsDir()

	if t.resolvedPath == resolvedPath && t.isDir == isDir && os.SameFile(t.info, info) {
		return targetState{exists: true}, nil
	}

	if watcher != nil {
		_ = watcher.Remove(t.path)
	}

	t.resolvedPath = resolvedPath
	t.isDir = isDir
	t.info = info

	if watcher != nil {
		if err = watcher.Add(t.path); err != nil {
			return targetState{}, err
		}
	}

	return targetState{exists: true, changed: true}, nil
}

func (t *target) concernsLocked(path string) bool {
	if t.isDir {
		// Keep root events so refreshLocked can detect directory target rebinds.
		return path == t.path || isDirectChild(t.path, path)
	}

	return path == t.path
}

func (t *target) fileEventLocked(op fsnotify.Op, exists bool) (Event, bool) {
	if !exists {
		return Event{Path: t.path, Op: OpDeleted}, true
	}

	if op.Has(fsnotify.Remove) || op.Has(fsnotify.Rename) {
		return Event{Path: t.path, Op: OpDeleted}, true
	}

	if op.Has(fsnotify.Create) || op.Has(fsnotify.Write) || op.Has(fsnotify.Chmod) {
		return Event{Path: t.path, Op: OpChanged}, true
	}

	return Event{}, false
}

func (t *target) directoryEventLocked(path string, op fsnotify.Op) (Event, bool) {
	if op.Has(fsnotify.Create) {
		return Event{Path: path, Op: OpAdded}, true
	}

	if op.Has(fsnotify.Remove) || op.Has(fsnotify.Rename) {
		return Event{Path: path, Op: OpDeleted}, true
	}

	if op.Has(fsnotify.Write) || op.Has(fsnotify.Chmod) {
		return Event{Path: path, Op: OpChanged}, true
	}

	return Event{}, false
}

func isDirectChild(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." {
		return false
	}

	return rel != ".." && filepath.Dir(rel) == "."
}

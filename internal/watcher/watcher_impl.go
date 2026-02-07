// Copyright 2024 Dimitrij Drus <dadrus@gmx.de>
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

package watcher

import (
	"context"
	"os"
	"path/filepath"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type listenerEntry struct {
	listener     []ChangeListener
	resolvedPath string
}

type watcher struct {
	w *fsnotify.Watcher
	m map[string]*listenerEntry
	l zerolog.Logger

	mut sync.Mutex
}

func newWatcher(logger zerolog.Logger) (*watcher, error) {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to instantiating new file watcher").
			CausedBy(err)
	}

	return &watcher{w: fsw, m: make(map[string]*listenerEntry), l: logger}, err
}

func (w *watcher) Add(path string, cl ChangeListener) error {
	w.mut.Lock()
	defer w.mut.Unlock()

	entry := w.m[path]
	if entry == nil {
		if err := w.w.Add(path); err != nil {
			return errorchain.NewWithMessagef(heimdall.ErrInternal,
				"listener registration for file %s failed", path).CausedBy(err)
		}

		resolvedPath, err := filepath.EvalSymlinks(path)
		if err != nil {
			return errorchain.NewWithMessagef(heimdall.ErrInternal,
				"listener registration for file %s failed", path).CausedBy(err)
		}

		w.m[path] = &listenerEntry{
			listener:     []ChangeListener{cl},
			resolvedPath: resolvedPath,
		}
	} else {
		entry.listener = append(entry.listener, cl)
	}

	return nil
}

func (w *watcher) startWatching() {
	for {
		select {
		case evt, ok := <-w.w.Events:
			if !ok {
				w.l.Debug().Msg("Config watcher closed")

				return
			}

			var (
				changed bool
				err     error
			)

			if evt.Has(fsnotify.Chmod) {
				changed, err = w.chackForUpdate(evt.Name)
				if err != nil {
					w.l.Warn().Err(err).Msgf("Handling modification for %s failed", evt.Name)
				}
			}

			if evt.Has(fsnotify.Write) || changed {
				w.fireOnChange(evt)
			}
		case err, ok := <-w.w.Errors:
			if !ok {
				w.l.Debug().Msg("Config watcher error channel closed")

				return
			}

			w.l.Warn().Err(err).Msg("Config watcher error received")
		}
	}
}

func (w *watcher) chackForUpdate(path string) (bool, error) {
	_, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			_ = w.w.Remove(path)

			return false, nil
		}

		return false, err
	}

	resolvedPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false, err
	}

	w.mut.Lock()
	defer w.mut.Unlock()

	entry := w.m[path]
	if entry.resolvedPath != resolvedPath {
		_ = w.w.Remove(path)
		entry.resolvedPath = resolvedPath
		_ = w.w.Add(path)

		return true, nil
	}

	return false, nil
}

func (w *watcher) start(_ context.Context) {
	w.l.Debug().Msg("Starting watching config files for changes")

	go w.startWatching()
}

func (w *watcher) stop(_ context.Context) error {
	w.l.Debug().Msg("Stopping watching config files for changes")

	return w.w.Close()
}

func (w *watcher) fireOnChange(evt fsnotify.Event) {
	w.mut.Lock()
	listeners := w.m[evt.Name].listener
	w.mut.Unlock()

	for _, listener := range listeners {
		go listener.OnChanged(w.l.Level(zerolog.InfoLevel))
	}
}

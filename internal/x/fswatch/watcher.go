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
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var (
	errNoHandler = errors.New("no handler configured")
	errAddTarget = errors.New("failed adding target")
)

// Watcher observes logical filesystem paths and emits normalized events.
type Watcher struct {
	logger zerolog.Logger

	started bool
	cancel  context.CancelFunc
	watcher *fsnotify.Watcher

	dispatcher *eventDispatcher

	targetsMu sync.RWMutex
	targets   map[string]*target

	wg sync.WaitGroup
}

// New creates a new Watcher.
//
// Targets can be registered before or after Start by using Add.
// Registering a target does not emit initial events.
func New(handler EventHandler, opts ...Option) (*Watcher, error) {
	if handler == nil {
		return nil, errNoHandler
	}

	cfg := applyOptions(opts)

	return &Watcher{
		logger:     cfg.logger,
		dispatcher: newEventDispatcher(handler, cfg.logger),
		targets:    make(map[string]*target),
	}, nil
}

// Add adds a logical filesystem path to the watcher.
func (w *Watcher) Add(path string) error {
	path = filepath.Clean(path)

	tgt, err := newTarget(path)
	if err != nil {
		return errorchain.NewWithMessage(errAddTarget, path).CausedBy(err)
	}

	w.targetsMu.Lock()
	defer w.targetsMu.Unlock()

	if _, ok := w.targets[path]; ok {
		return errorchain.NewWithMessagef(errAddTarget, "%s already registered", path)
	}

	if w.started {
		if err = tgt.addWatch(w.watcher); err != nil {
			return errorchain.NewWithMessage(errAddTarget, path).CausedBy(err)
		}
	}

	w.targets[path] = tgt

	return nil
}

// Remove removes a logical filesystem path from the watcher.
func (w *Watcher) Remove(path string) error {
	path = filepath.Clean(path)

	w.targetsMu.Lock()

	tgt, ok := w.targets[path]
	if ok {
		delete(w.targets, path)
	}

	w.targetsMu.Unlock()

	if !ok || !w.started {
		return nil
	}

	tgt.removeWatch(w.watcher)

	return nil
}

// Start starts observing all registered targets.
func (w *Watcher) Start(ctx context.Context) error {
	if w.started {
		return nil
	}

	var (
		fsWatcher *fsnotify.Watcher
		err       error
	)

	ctx, cancel := context.WithCancel(ctx)

	defer func() {
		if err == nil {
			return
		}

		cancel()

		if fsWatcher != nil {
			_ = fsWatcher.Close()
		}

		_ = w.dispatcher.Stop()
	}()

	fsWatcher, err = fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	w.targetsMu.RLock()

	targets := slices.Collect(maps.Values(w.targets))

	w.targetsMu.RUnlock()

	for _, tgt := range targets {
		if err = tgt.addWatch(fsWatcher); err != nil {
			return fmt.Errorf("failed watching target %q: %w", tgt.path, err)
		}
	}

	if err = w.dispatcher.Start(); err != nil {
		return err
	}

	w.cancel = cancel
	w.watcher = fsWatcher
	w.started = true

	w.wg.Go(func() {
		w.run(ctx, fsWatcher)
	})

	return nil
}

// Stop stops observing paths and waits until currently running event handling
// has completed or until ctx is cancelled.
func (w *Watcher) Stop(ctx context.Context) error {
	if !w.started {
		return nil
	}

	cancel := w.cancel
	fsWatcher := w.watcher
	dispatcher := w.dispatcher

	w.cancel = nil
	w.watcher = nil
	w.started = false

	cancel()

	_ = fsWatcher.Close()

	done := make(chan struct{})

	go func() {
		w.wg.Wait()

		_ = dispatcher.Stop()

		close(done)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return nil
	}
}

func (w *Watcher) run(ctx context.Context, fsWatcher *fsnotify.Watcher) {
	for {
		select {
		case <-ctx.Done():
			return

		case err, ok := <-fsWatcher.Errors:
			if !ok {
				return
			}

			w.logger.Error().
				Err(err).
				Msg("Received file watcher error")

		case evt, ok := <-fsWatcher.Events:
			if !ok {
				return
			}

			w.handleEvent(fsWatcher, evt)
		}
	}
}

func (w *Watcher) handleEvent(fsWatcher *fsnotify.Watcher, evt fsnotify.Event) {
	w.logger.Debug().
		Str("_file", evt.Name).
		Str("_operation", evt.Op.String()).
		Msg("Received file event")

	w.targetsMu.RLock()

	targets := slices.Collect(maps.Values(w.targets))

	w.targetsMu.RUnlock()

	for _, tgt := range targets {
		normalized, ok := tgt.handle(fsWatcher, evt, w.logger)
		if !ok {
			continue
		}

		w.logger.Debug().
			Str("_file", normalized.Path).
			Str("_operation", normalized.Op.String()).
			Msg("Dispatching normalized file event")

		w.dispatcher.Enqueue(normalized)
	}
}

package watcher

import (
	"context"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type ChangeListener interface {
	OnChanged(path zerolog.Logger)
}

//go:generate mockery --name Watcher --structname WatcherMock

type Watcher interface {
	Add(path string, cl ChangeListener) error
}

func newWatcher(logger zerolog.Logger) (*watcher, error) {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to instantiating new file watcher").
			CausedBy(err)
	}

	return &watcher{w: fsw, m: make(map[string][]ChangeListener), l: logger}, err
}

type watcher struct {
	w *fsnotify.Watcher
	m map[string][]ChangeListener
	l zerolog.Logger

	mut sync.Mutex
}

func (w *watcher) startWatching() {
	for {
		select {
		case evt, ok := <-w.w.Events:
			if !ok {
				w.l.Debug().Msg("Config watcher closed")

				return
			}

			if evt.Has(fsnotify.Write) {
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

func (w *watcher) Start(_ context.Context) error {
	w.l.Debug().Msg("Starting watching config files for changes")

	go w.startWatching()

	return nil
}

func (w *watcher) Stop(_ context.Context) error {
	w.l.Debug().Msg("Stopping watching config files for changes")

	return w.w.Close()
}

func (w *watcher) Add(path string, cl ChangeListener) error {
	w.mut.Lock()
	defer w.mut.Unlock()

	list, ok := w.m[path]
	if !ok {
		if err := w.w.Add(path); err != nil {
			return err
		}

		w.m[path] = []ChangeListener{cl}
	} else {
		w.m[path] = append(list, cl)
	}

	return nil
}

func (w *watcher) fireOnChange(evt fsnotify.Event) {
	var (
		listeners []ChangeListener
		ok        bool
	)

	w.mut.Lock()
	listeners, ok = w.m[evt.Name]
	w.mut.Unlock()

	if !ok {
		return
	}

	for _, listener := range listeners {
		go listener.OnChanged(w.l)
	}
}
